#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define BUFFER_SIZE 1024

// Función para enviar archivo completo
void enviar_archivo(SSL *ssl, const char *filename) {
    FILE *file = fopen(filename, "rb");
    if (!file) {
        perror("Error abriendo archivo para lectura");
        exit(EXIT_FAILURE);
    }

    printf("NOSE \n");
    // Obtener tamaño del archivo
    fseek(file, 0, SEEK_END);
    long filesize = ftell(file);
    rewind(file);

    // Leer todo el archivo al buffer
    char *buffer = malloc(filesize);
    if (!buffer) {
        perror("Error asignando memoria");
        fclose(file);
        exit(EXIT_FAILURE);
    }

    if (fread(buffer, 1, filesize, file) != filesize) {
        perror("Error leyendo archivo completo");
        free(buffer);
        fclose(file);
        exit(EXIT_FAILURE);
    }

    fclose(file);
    printf("%s\n", buffer);
    // Enviar todo el buffer
    long total_sent = 0;
    while (total_sent < filesize) {
        int sent = SSL_write(ssl, buffer + total_sent, filesize - total_sent);
        if (sent <= 0) {
            ERR_print_errors_fp(stderr);
            free(buffer);
            exit(EXIT_FAILURE);
        }
        total_sent += sent;
    }

    free(buffer);
}

// Función para recibir archivo y luego imprimirlo como texto
void recibir_archivo(SSL *ssl, const char *filename) {
    FILE *file = fopen(filename, "wb");
    if (!file) {
        perror("Error abriendo archivo para escritura");
        exit(EXIT_FAILURE);
    }

    char buffer[BUFFER_SIZE];
    int bytes_received;
    printf("Recibiendo datos...\n");

    // Recibir y guardar en archivo
    if ((bytes_received = SSL_read(ssl, buffer, BUFFER_SIZE)) > 0) {
        fwrite(buffer, 1, bytes_received, file);
    }

    fclose(file);

    // Mostrar contenido del archivo como texto
    file = fopen(filename, "rb");
    if (!file) {
        perror("Error reabriendo archivo para lectura");
        exit(EXIT_FAILURE);
    }

    fclose(file);
    printf("\nFin del contenido.\n");
}

void *leer_archivo_a_buffer(const char *ruta, size_t *tam) {
    FILE *f = fopen(ruta, "rb");
    if (!f) return NULL;

    fseek(f, 0, SEEK_END);
    *tam = ftell(f);
    fseek(f, 0, SEEK_SET);

    void *buffer = malloc(*tam);
    if (!buffer) {
        fclose(f);
        return NULL;
    }

    fread(buffer, 1, *tam, f);
    fclose(f);
    return buffer;
}

int escribir_a_archivo(const char *ruta, const void *buffer, size_t tam) {
    FILE *f = fopen(ruta, "wb");
    if (!f) return -1;

    size_t escritos = fwrite(buffer, 1, tam, f);
    fclose(f);

    return (escritos == tam) ? 0 : -1;
}
