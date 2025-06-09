#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/conf.h>

SSL *ssl = NULL; //Almaceno la representacion de la conexion TSL
char send_buffer[1024], recv_buffer[1024 + EVP_MAX_BLOCK_LENGTH];
int recv_len;
int conection_state = 1;
char *clave_privada;

typedef struct {
    char *clave_publica;
} Keys;

Keys claves;

EVP_PKEY *priv_key;
EVP_PKEY **pub_key;


unsigned char **encrypted_key;
int encrypted_key_len[1];
    unsigned char iv[EVP_MAX_IV_LENGTH];

unsigned char *dencrypted_key;
int dencrypted_key_len;

EVP_CIPHER_CTX *encrypt_ctx;

int desencriptar(unsigned char *ciphertext, int ciphertext_len){

    
    
    int len;
    
    EVP_CIPHER_CTX *decrypt_ctx;

  if(!(decrypt_ctx = EVP_CIPHER_CTX_new())){
      printf("No se pudo crear el contexto de encriptacion\n");
      return 0;
    }
    if(EVP_OpenInit(decrypt_ctx, EVP_aes_256_cbc(), dencrypted_key, dencrypted_key_len, iv, priv_key) != 1){
          
          return 0;
        }
    if(EVP_OpenUpdate(decrypt_ctx, recv_buffer, &len, ciphertext, ciphertext_len) != 1){
          printf("Error al descifrar\n");
          return 0;
        }
        
        recv_len = len;

        /*********************************************************************************************************************************************************************************/
        if(EVP_OpenFinal(decrypt_ctx, recv_buffer + len, &len) != 1){
          //printf("Me mori, no se porque\n");
          //ERR_print_errors_fp(stderr);
          //return 0;
        }
        recv_len += len;
        EVP_CIPHER_CTX_free(decrypt_ctx);
        return recv_len;
}



//Funcion para recibir mensajes y mostrarlos por pantalla
void *read_text(){
printf("LISTO PARA RECIBIR\n");
    int rval, len;
    size_t readed;
    unsigned char ciphertext[1024 + EVP_MAX_BLOCK_LENGTH];
printf("Creadno\n");
    
    FILE *fp = fopen(clave_privada, "r");
if (!fp) {
    perror("fopen");
    return NULL;
}
 priv_key = PEM_read_PrivateKey(fp, NULL , NULL, NULL);
fclose(fp);
if (!priv_key) {
    fprintf(stderr, "Error leyendo la clave privada\n");
    return NULL;
}
    do{
    printf("ready to recv\n");
        memset(recv_buffer,0,sizeof(recv_buffer));
        memset(ciphertext,0,sizeof(ciphertext));
        rval=SSL_read_ex(ssl,ciphertext,1024, &readed);
        len = desencriptar(ciphertext, readed);
        printf("%s",recv_buffer);
    }while(conection_state);
    
    
}


//Funcion para enviar un mensaje al chat
void *write_text(){

    int rval;
    
    unsigned char ciphertext[1024 + EVP_MAX_BLOCK_LENGTH];
    int ciphertext_len;
    int len;
    
    do{
      printf("ready to send\n");
        memset(send_buffer,0,sizeof(send_buffer));
        fgets(send_buffer, 1024, stdin);
        if(EVP_SealUpdate(encrypt_ctx, ciphertext, &ciphertext_len, send_buffer, 1024) != 1){
          printf("Error al cifrar\n");
          return NULL;
        }
        if(strcmp(send_buffer, "QUIT\n") == 0){//El cliente se hace cargo de mandar el QUIT
            conection_state = 0;
        }
        if(EVP_SealFinal(encrypt_ctx, ciphertext + len, &len) != 1){
          printf("Error al finalizar cifrado\n");
          return NULL;
        }
	ciphertext_len += len;
	printf("%s\n",ciphertext);
	printf("%d\n",ciphertext_len);
	SSL_write(ssl, ciphertext, ciphertext_len);
    }while(conection_state);
    EVP_CIPHER_CTX_free(encrypt_ctx);
}

static SSL_CTX *create_client_context(const char *ca_pem, const char *cert_pem, const char *key_pem){
    SSL_CTX *ctx;

    //Creamos el contexto TSL
    if (!(ctx = SSL_CTX_new(TLS_client_method()))) {
        printf("No se pudo crear el contexto SSL\n");
        return NULL;
    }

    //Cargamos la autenticacion de certificados del usuario
    if (SSL_CTX_load_verify_locations(ctx, ca_pem, NULL) != 1) {
        printf("No se pudo encontrar el verificador de certificados\n");
        SSL_CTX_free(ctx);
        return NULL;
    }

    //Cargamos el certificado del cliente
    if (SSL_CTX_use_certificate_file(ctx, cert_pem, SSL_FILETYPE_PEM) != 1) {
        printf("El certificado del cliente no es correcto\n");
        SSL_CTX_free(ctx);
        return NULL;
    }

    //Cargamos la clave del cliente
    if (SSL_CTX_use_PrivateKey_file(ctx, key_pem, SSL_FILETYPE_PEM) != 1) {
        printf("La clave del cliente no es valida\n");
        SSL_CTX_free(ctx);
        return NULL;
    }

    //verificamos que el certificado del cliente y la clave coincidan
    if (SSL_CTX_check_private_key(ctx) != 1) {
        printf("No hay coincidencia entre el certificado y la clave\n");
        SSL_CTX_free(ctx);
        return NULL;
    }

    SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_verify_depth(ctx, 1);

    return ctx;
}

int main(int argc, char *argv[])
{


    int portno, n;
    pthread_t r_thread, w_thread;

    SSL_CTX *ctx = NULL; //Almaceno los contextos
    BIO *bio = NULL; //BASIC IO para SSL

    if (argc < 6) {
        printf("Para %s ingrese <hostname> <ca.pem> <cert.pem> <private_key.pem> <public_key.pem>\n", argv[0]);
        exit(1);
    }
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
    portno = atoi(argv[2]);

    //Creo el contexto
    ctx = create_client_context(argv[2], argv[3], argv[4]);
    if (!ctx) {
        ERR_print_errors_fp(stderr);
        printf("Fallo al crear el contexto\n");
        exit(1);
    }

    //Creo el objeto BIO para las operaciones read/write
    if (!(bio = BIO_new_ssl_connect(ctx))) {
        printf("No se pudo obtener el objeto BIO del contexto\n");
        SSL_CTX_free(ctx);
		exit(1);
    }
    
    BIO_get_ssl(bio, &ssl);

    if(!ssl){
        printf("Fallo al obtener el SSL del BIO\n");
        exit(1);
    }
    //Conexion con el servidor
    if (BIO_set_conn_hostname(bio, argv[1]) != 1) {
        printf("No se pudo conectar con el server\n");
        BIO_free_all(bio);
		exit(1);
    }
    
    //Handshake con el server
    if ((n = SSL_do_handshake(ssl)) != 1) {
        printf("Fallo el Handshake SSL\n");
        BIO_free_all(bio);
        printf("ERROR: %i %i\n",SSL_get_error(ssl, n), n);
		exit(1);
    }
    
    //Verificar que el handshake fue correcto
    if (SSL_get_verify_result(ssl) != X509_V_OK) {
        fprintf(stderr, "Verification of handshake failed\n");
        BIO_free_all(bio);
		exit(1);
    }
    printf("Conexion establecida\n");
    //Envio HELLO al servidor para confirmar la conexion
    bzero((char *) &send_buffer, sizeof(send_buffer));
    char hello[] = "HELLO";
    SSL_write(ssl, hello, 5);
    SSL_read(ssl, recv_buffer, 1);
    
    bzero((char *) &send_buffer, sizeof(send_buffer));
    bzero((char *) &recv_buffer, sizeof(recv_buffer));

    clave_privada = argv[4];
    claves.clave_publica = argv[5];
    

/*******************************************************************************/

        pub_key = (EVP_PKEY **)malloc(1 * sizeof(EVP_PKEY *));
        for(int i = 0; i < 1; i++){
          pub_key[i] = (EVP_PKEY *)malloc(sizeof(EVP_PKEY *));
        }
        
        printf("Creadno\n");
    FILE *fp = fopen(claves.clave_publica, "r");
if (!fp) {
    perror("fopen");
    exit(1);
}

pub_key[0] = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
fclose(fp);

if (!pub_key[0]) {
    fprintf(stderr, "Error leyendo la clave pública\n");
    ERR_print_errors_fp(stderr);
    exit(1);
}

    if(!(encrypt_ctx = EVP_CIPHER_CTX_new())){
      printf("No se pudo crear el contexto de encriptacion\n");
       exit(1);
    }

    encrypted_key = (unsigned char **)malloc(1 * sizeof(unsigned char *));
    for(int i = 0; i < 1; i++){
      encrypted_key[i] = (unsigned char *)malloc(sizeof(unsigned char));
    }
    
    if(EVP_SealInit(encrypt_ctx, EVP_aes_256_cbc(), encrypted_key, encrypted_key_len, iv, pub_key, 1) != 1){
          printf("Error al setup cifrado\n");
          ERR_print_errors_fp(stderr);
           return 1;
        }
    dencrypted_key = encrypted_key[0];
    dencrypted_key_len = encrypted_key_len[0];
/*******************************************************************************/
    //Creo 2 hilos uno para la recibir los mensajes, otro para enviar mensajes
    pthread_create(&r_thread, NULL,*read_text, NULL);
    
    pthread_create(&w_thread, NULL,*write_text, NULL);
    pthread_join(w_thread, NULL);
    pthread_join(r_thread, NULL);
    return 0;
}
