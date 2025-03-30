#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>

SSL *ssl = NULL; //Almaceno la representacion de la conexion TSL
char send_buffer[1024], recv_buffer[1024];
int conection_state = 1;

//Funcion para recibir mensajes y mostrarlos por pantalla
void *read_text(){
    int rval;
    do{
        memset(recv_buffer,0,sizeof(recv_buffer));
        rval=SSL_read(ssl,recv_buffer,1024);
        if(rval > 0){
            printf("%s",recv_buffer);
        }
    }while(conection_state);
}

//Funcion para enviar un mensaje al chat
void *write_text(){
    int rval;
    do{
        memset(send_buffer,0,sizeof(send_buffer));
        fgets(send_buffer, 1024, stdin);
        //Envio el mensaje
        SSL_write(ssl, send_buffer, strlen(send_buffer));
        if(strcmp(send_buffer, "QUIT\n") == 0){//El cliente se hace cargo de mandar el QUIT
            conection_state = 0;
        }
    }while(conection_state);
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

    if (argc < 5) {
        printf("Para %s ingrese <hostname> <ca.pem> <cert.pem> <key.pem>\n", argv[0]);
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

    //Creo 2 hilos uno para la recibir los mensajes, otro para enviar mensajes
    pthread_create(&r_thread, NULL,*read_text, NULL);
    pthread_create(&w_thread, NULL,*write_text, NULL);
    pthread_join(w_thread, NULL);
    pthread_join(r_thread, NULL);
    return 0;
}
