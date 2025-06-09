/* A simple server in the internet domain using TCP
   The port number is passed as an argument 
   This version runs forever, forking off a separate 
   process for each connection
*/
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h> 
#include <sys/socket.h>
#include <netinet/in.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>

#include <openssl/err.h>
#include <openssl/ssl.h>

#define N_CLIENTES 10

/*
Estructura Cliente
    send_buffer: Buffer de lo que envió el cliente
    recv_buffer: Buffer de lo que le debo enviar al cliente
*/
typedef struct {
    struct sockaddr_in cli_addr;
    socklen_t clilen;
    int cli_sockfd;
    char send_buffer[1024];
    char recv_buffer[1024];
    pthread_t cli_thread;
    char username[4];
    SSL *cli_ssl; //El socket de este cliente para la conexion ssl
    int state;
} Client;
Client client[N_CLIENTES];

void *job(void *index){
    printf("Hilo ccreado\n");
    int rval, conection_state=1;
    int i = (int)index;
    memset(client[i].send_buffer,0,sizeof(client[i].send_buffer));
    memset(client[i].recv_buffer,0,sizeof(client[i].recv_buffer));
    do{
            memset(client[i].send_buffer,0,sizeof(client[i].send_buffer));
            rval=SSL_read(client[i].cli_ssl,client[i].send_buffer,1024);
            if (rval<0){
                SSL_write(client[i].cli_ssl,"Mensaje no recibido",19);
            }
            else{
                if(strcmp(client[i].send_buffer, "QUIT\n") == 0){//El cliente se hace cargo de mandar el QUIT
                    conection_state = 0;
                }else{
                    printf("Mensaje recibido \n");
                    //printf("%s",client[i].send_buffer);
                    //printf("\n");
                    for(int j=0; j < N_CLIENTES; j++){
                        if(j != i ){
                            SSL_write(client[j].cli_ssl,client[i].send_buffer,strlen(client[i].send_buffer));
                        }
                    }
                }
            }
            }while(conection_state);
    printf("\nCerrando\n");
    SSL_shutdown(client[i].cli_ssl);
    SSL_free(client[i].cli_ssl);
}

static SSL_CTX *create_server_context(const char *ca_pem, const char *cert_pem, const char *key_pem){
    SSL_CTX *ctx;

    //Defino el contexto
    if (!(ctx = SSL_CTX_new(TLS_server_method()))) {
        printf("Creacion del contexto SSL fallo\n");
        return NULL;
    }

    //Defino el autenticador de certificados
    if (SSL_CTX_load_verify_locations(ctx, ca_pem, NULL) != 1) {
        printf("No se pudo encontrar el verificador de certificados\n");
        SSL_CTX_free(ctx);
		return NULL;
    }

    //Cargo el CA del cliente
    SSL_CTX_set_client_CA_list(ctx, SSL_load_client_CA_file(ca_pem));

    //Defino el certificado del server firmado por CA
    if (SSL_CTX_use_certificate_file(ctx, cert_pem, SSL_FILETYPE_PEM) != 1) {
        printf("El certificado del server no es correcto\n");
        SSL_CTX_free(ctx);
		return NULL;
    }

    //Defino la clave del servidor para el certificado previo
    if (SSL_CTX_use_PrivateKey_file(ctx, key_pem, SSL_FILETYPE_PEM) != 1) {
        printf("La clave del servidor no es valida\n");
        SSL_CTX_free(ctx);
		return NULL;
    }

    //Verifico si el certificado coincide con la clave
    if (SSL_CTX_check_private_key(ctx) != 1) {
        printf("No hay coincidencia entre el certificado y la clave\n");
        SSL_CTX_free(ctx);
		return NULL;
    }

    SSL_CTX_set_mode(ctx, SSL_MODE_AUTO_RETRY);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    SSL_CTX_set_verify_depth(ctx, 1);
    return ctx;
}

/**
 * Funcion para la creacion de un socket basico
 */
static int create_socket(int portno){
    struct sockaddr_in serv_addr;
    int sockfd, val;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);

    //Pisa el socket en uso actual para evitar error por socket ocupado
    setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));

    bzero((char *) &serv_addr, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET; // Asignacion del tipo de drirecciones (Familia)
    serv_addr.sin_addr.s_addr = INADDR_ANY; // INADDR para que el sistema operativo asigne al servidor el ip local
    serv_addr.sin_port = htons(portno);

    if (bind(sockfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr)) < 0) //El servidor llama a bind() para darle un nombre al socket, para luego poder recibir 											conexiones, es decir establece por cual número de puerto escuchará.
        printf("ERROR on binding\n"); // En caso de error el proceso abortara

    listen(sockfd, N_CLIENTES);

    return sockfd;

}

/**
 * Compilar con -lssl y -lcrypto
 * Llamar con port, ca.pem, cert.pem, key.pem
 */
int main(int argc, char *argv[])
{
    int sockfd, portno, rval; //El servidor escuchara a traves sockfd y las transferencias de datos se hacen por medio de newsockfd
    struct sockaddr_in serv_addr; // serv_addr contendra la direccion de IP y el numero de puerto local, cli_addr contendra el numero de IP el puerto del cliente

    SSL_CTX *ctx = NULL; //Almaceno los contextos
    if (argc < 5) {
        printf("Para %s ingrese <port> <ca.pem> <cert.pem> <key.pem>\n", argv[0]);
        exit(1);
    }
    //Iniciamos SSL
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();

    portno = atoi(argv[1]);

    //Creo el contexto ("Fabrica" de conexiones ssl)
    ctx = create_server_context(argv[2], argv[3], argv[4]);
    if (!ctx) {
        printf("Fallo al crear el contexto\n");
        exit(1);
    }
    
    //Creo un socket comun para establecer la primera instancia de conexion
    if((sockfd = create_socket(portno)) < 0){
        SSL_CTX_free(ctx);
        return 0;
    }
    
    for(int i = 0; i < N_CLIENTES; i++){
        printf("Esperando clientes...\n");
        client[i].clilen = sizeof(client[i].cli_addr);
        
        //Espero a que UN cliente quiera hacer handshake
        client[i].cli_sockfd = accept(sockfd, (struct sockaddr *) &client[i].cli_addr, &client[i].clilen);
        
        //Para el cliente creo una nueva conexion ssl
        if (!(client[i].cli_ssl = SSL_new(ctx))) {
            printf("No se pudo crear la estructura SLL con el contexto\n");
            close(client[i].cli_sockfd);
            continue; //Salteo la iteracion
        }

        //Establece el fd de la conexion, cli_sockfd,
        //como la herramienta para entrada/salida para el lado TLS/SSL, cli_ssl.
        SSL_set_fd(client[i].cli_ssl, client[i].cli_sockfd);
        //Espero a que EL cliente quiera hacer handshake de SSL
        if ((client[i].state = SSL_accept(client[i].cli_ssl)) != 1) {
            printf("No se pudo realizar el handshake de SSL\n");
            if (client[i].state != 0) {
                SSL_shutdown(client[i].cli_ssl);
            }
            SSL_free(client[i].cli_ssl);
            continue; //Salteo la iteracion
        }
        
        printf("Conexion segura completada\n");

        memset(client[i].send_buffer,0,sizeof(client[i].send_buffer));
        //Recibo bytes del cliente usando el SSL
        rval = SSL_read(client[i].cli_ssl, client[i].recv_buffer, sizeof(client[i].recv_buffer));
        /* ACA INTERCAMBIAR CLAVES PUBLICAS USER-SERVER (Archivos) */
        if(strcmp(client[i].send_buffer, "HELLO")){
            //Recibo bytes del cliente que conforman la palabra HELLO
            client[i].recv_buffer[0] = i;
            //Respondo al cliente con su numero de id
            SSL_write(client[i].cli_ssl, client[i].recv_buffer, 1);
            pthread_create(&client[i].cli_thread, NULL,*job, (void*)i);
        }
    }

    for(int i=0; i < N_CLIENTES; i++){
        pthread_join(client[i].cli_thread, NULL);
    }

    return 0;
}
