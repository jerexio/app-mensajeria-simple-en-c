#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include "time.h"
#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/conf.h>
#include "encriptador.h"
#include "desencriptador.h"
#include "clave_publica_send_recv.h"

#define MAX_TO_SEND 96
#define SIZE_MSG 480
#define SIZE_SEND_RECV SIZE_MSG+EVP_MAX_BLOCK_LENGTH

SSL *ssl = NULL; // Almaceno la representacion de la conexion TSL
unsigned char send_buffer[SIZE_SEND_RECV], recv_buffer[SIZE_SEND_RECV];

int conection_state = 1;
int user_nro;

char *clave_privada;

typedef struct
{
    char *clave_publica;
} Keys;

Keys claves;

EVP_PKEY *priv_key;
EVP_PKEY **pub_key;


unsigned char *dencrypted_key;
int dencrypted_key_len;


//Funcion para recibir mensajes y mostrarlos por pantalla
void *read_text(void *args){
    int rval, 
        ciphertext_len,
        encrypted_key_len = 32,
        len_recv_buffer;
    unsigned char *encrypted_key = (unsigned char *)malloc(32);
    unsigned char *ciphertext = (unsigned char *)malloc(SIZE_SEND_RECV);
    unsigned char iv[EVP_MAX_IV_LENGTH];
    do{
        printf("Ready to recv\n");
        memset(&ciphertext_len, 0, sizeof(int));
        memset(encrypted_key, 0, 32);
        memset(ciphertext, 0, SIZE_SEND_RECV);
        memset(iv, 0, EVP_MAX_IV_LENGTH);

        rval = SSL_read(ssl, &ciphertext_len, sizeof(int));

        if(rval > 0){
            rval = SSL_read(ssl, iv, EVP_MAX_IV_LENGTH);

            if(rval > 0){
                SSL_read(ssl, encrypted_key, encrypted_key_len);
                rval = SSL_read(ssl, ciphertext, ciphertext_len);
                if(rval > 0){
                    len_recv_buffer = desencriptar(ciphertext, ciphertext_len, encrypted_key, iv, recv_buffer);
                    printf("%s",recv_buffer);
                }
                free(ciphertext);
            }
        }
    }while(conection_state);
}

//Funcion para enviar un mensaje al chat
void *write_text(void *args){
    int rval,
        ciphertext_len,
        encrypted_key_len = 32;
    unsigned char **encrypted_key;
    unsigned char *ciphertext;
    unsigned char iv[EVP_MAX_IV_LENGTH];

    encrypted_key = (unsigned char **)malloc(2 * sizeof(unsigned char *));
    for (int i = 0; i < 2; i++)
    {
        encrypted_key[i] = (unsigned char *)malloc(32);
    }
    ciphertext = (unsigned char *)malloc(SIZE_SEND_RECV);

    do{
        printf("Ready to send\n");
        memset(send_buffer,0, SIZE_SEND_RECV);
        memset(ciphertext, 0, SIZE_SEND_RECV);
        fgets(send_buffer, SIZE_SEND_RECV, stdin);
        ciphertext_len = encriptar(send_buffer, strlen(send_buffer),
              encrypted_key[(user_nro+1)%2], iv,
              ciphertext);

        SSL_write(ssl, &ciphertext_len, sizeof(int));
        SSL_write(ssl, iv, EVP_MAX_IV_LENGTH);
        SSL_write(ssl, encrypted_key[(user_nro+1)%2], encrypted_key_len); //El (user_nro+1)%2 solo se puede usar porque son 2 usuarios
        SSL_write(ssl, ciphertext, ciphertext_len);

        if(strcmp(send_buffer, "QUIT\n") == 0){//El cliente se hace cargo de mandar el QUIT
            conection_state = 0;
        }
    }while(conection_state);
}


static SSL_CTX *create_client_context(const char *ca_pem, const char *cert_pem, const char *key_pem)
{
    SSL_CTX *ctx;

    // Creamos el contexto TSL
    if (!(ctx = SSL_CTX_new(TLS_client_method())))
    {
        printf("No se pudo crear el contexto SSL\n");
        return NULL;
    }

    // Cargamos la autenticacion de certificados del usuario
    if (SSL_CTX_load_verify_locations(ctx, ca_pem, NULL) != 1)
    {
        printf("No se pudo encontrar el verificador de certificados\n");
        SSL_CTX_free(ctx);
        return NULL;
    }

    // Cargamos el certificado del cliente
    if (SSL_CTX_use_certificate_file(ctx, cert_pem, SSL_FILETYPE_PEM) != 1)
    {
        printf("El certificado del cliente no es correcto\n");
        SSL_CTX_free(ctx);
        return NULL;
    }

    // Cargamos la clave del cliente
    if (SSL_CTX_use_PrivateKey_file(ctx, key_pem, SSL_FILETYPE_PEM) != 1)
    {
        printf("La clave del cliente no es valida\n");
        SSL_CTX_free(ctx);
        return NULL;
    }

    // verificamos que el certificado del cliente y la clave coincidan
    if (SSL_CTX_check_private_key(ctx) != 1)
    {
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

    SSL_CTX *ctx = NULL; // Almaceno los contextos
    BIO *bio = NULL;     // BASIC IO para SSL

    if (argc < 6)
    {
        printf("Para %s ingrese <hostname> <ca.pem> <cert.pem> <private_key.pem> <public_key.pem>\n", argv[0]);
        exit(1);
    }
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
    portno = atoi(argv[2]);

    // Creo el contexto
    ctx = create_client_context(argv[2], argv[3], argv[4]);
    if (!ctx)
    {
        ERR_print_errors_fp(stderr);
        printf("Fallo al crear el contexto\n");
        exit(1);
    }

    // Creo el objeto BIO para las operaciones read/write
    if (!(bio = BIO_new_ssl_connect(ctx)))
    {
        printf("No se pudo obtener el objeto BIO del contexto\n");
        SSL_CTX_free(ctx);
        exit(1);
    }

    BIO_get_ssl(bio, &ssl);

    if (!ssl)
    {
        printf("Fallo al obtener el SSL del BIO\n");
        exit(1);
    }
    // Conexion con el servidor
    if (BIO_set_conn_hostname(bio, argv[1]) != 1)
    {
        printf("No se pudo conectar con el server\n");
        BIO_free_all(bio);
        exit(1);
    }

    // Handshake con el server
    if ((n = SSL_do_handshake(ssl)) != 1)
    {
        printf("Fallo el Handshake SSL\n");
        BIO_free_all(bio);
        printf("ERROR: %i %i\n", SSL_get_error(ssl, n), n);
        exit(1);
    }

    // Verificar que el handshake fue correcto
    if (SSL_get_verify_result(ssl) != X509_V_OK)
    {
        fprintf(stderr, "Verification of handshake failed\n");
        BIO_free_all(bio);
        exit(1);
    }
    printf("Conexion establecida\n");
    // Envio HELLO al servidor para confirmar la conexion
    bzero((char *)&send_buffer, sizeof(send_buffer));
    char hello[] = "HELLO";
    SSL_write(ssl, hello, 5);
    SSL_read(ssl, recv_buffer, 1);
    user_nro = recv_buffer[0];
    bzero((char *)&send_buffer, sizeof(send_buffer));
    bzero((char *)&recv_buffer, sizeof(recv_buffer));

    clave_privada = argv[4];
    claves.clave_publica = argv[5];

    /*******************************************************************************/

    pub_key = (EVP_PKEY **)malloc(2 * sizeof(EVP_PKEY *));
    for (int i = 0; i < 2; i++)
    {
        pub_key[i] = (EVP_PKEY *)malloc(sizeof(EVP_PKEY *));
    }

    printf("Creadno\n");
    FILE *fp = fopen(claves.clave_publica, "r");
    if (!fp)
    {
        perror("fopen");
        exit(1);
    }

    pub_key[user_nro] = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);

    if (!pub_key[user_nro])
    {
        fprintf(stderr, "Error leyendo la clave pública\n");
        ERR_print_errors_fp(stderr);
        exit(1);
    }

    printf("Creadno\n");

    fp = fopen(clave_privada, "r");
    if (!fp)
    {
        perror("fopen");
        exit(1);
    }
    priv_key = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    if (!priv_key)
    {
        fprintf(stderr, "Error leyendo la clave privada\n");
        exit(1);
    }
    /*******************************************************************************/
    
    fp = fopen("./external_pub_key/other_pub_key.pem", "r");
    if (!fp)
    {
        perror("fopen");
        exit(1);
    }

    pub_key[(user_nro+1)%2] = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);

    printf("CLAVES CARGADAS\n");
    if (!pub_key[(user_nro+1)%2]) {
        printf("La clave pública no es RSA\n");
        ERR_print_errors_fp(stderr);
        exit(1);
    }
    // Creo 2 hilos uno para l*/
    pthread_create(&r_thread, NULL, *read_text, NULL);
    pthread_create(&w_thread, NULL, *write_text, NULL);
    pthread_join(w_thread, NULL);
    pthread_join(r_thread, NULL);
    return 0;
}
