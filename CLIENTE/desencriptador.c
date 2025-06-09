#include <openssl/evp.h>
#include <openssl/err.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


void print_bytes(const unsigned char *buf) {
    for (int i = 0; i < strlen(buf); i++) {
        printf("%02X", buf[i]);
    }
    printf("\n");
}

int desencriptar(unsigned char *ciphertext, int ciphertext_len,
                 unsigned char *key, unsigned char *iv,
                 unsigned char *plaintext)
{
    EVP_CIPHER_CTX *ctx;
    EVP_CIPHER *cipher = NULL;
    int len, plaintext_len;
    
    // Obtener cipher
    cipher = EVP_CIPHER_fetch(NULL, "AES-256-CBC", NULL);
    if (!cipher) {
        fprintf(stderr, "No se pudo obtener el cipher AES-256-CBC\n");
        return -1;
    }

    // Crear contexto
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "Error al crear contexto de descifrado\n");
        return -1;
    }

    // Inicializar descifrado
    if (EVP_DecryptInit_ex(ctx, cipher, NULL, key, iv) <= 0) {
        ERR_print_errors_fp(stderr);
        return -1;
    }

    // Descifrar datos
    if (EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len) <= 0) {
        ERR_print_errors_fp(stderr);
        return -1;
    }
    plaintext_len = len;

    // Finalizar descifrado
    if (EVP_DecryptFinal_ex(ctx, plaintext + len, &len) <= 0) {
        ERR_print_errors_fp(stderr);
        return -1;
    }
    plaintext_len += len;

    // Limpieza
    EVP_CIPHER_CTX_free(ctx);
    EVP_CIPHER_free(cipher);

    return plaintext_len;
}
