#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/conf.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

int encriptar(unsigned char *plaintext, int plaintext_len,
              unsigned char *key, unsigned char *iv,
              unsigned char *ciphertext)
{
    EVP_CIPHER_CTX *encrypt_ctx;
    EVP_CIPHER *cipher = NULL;
    int len, ciphertext_len;

    cipher = EVP_CIPHER_fetch(NULL, "AES-256-CBC", NULL);
    if (!cipher) {
        fprintf(stderr, "No se pudo obtener el cipher AES-256-CBC\n");
        return -1;
    }

    //Genero una clave aleatoria de 32 bytes y el vector
    if (!RAND_bytes(key, 32)) {
        fprintf(stderr, "Error generando clave AES aleatoria\n");
        return -1;
    }
    if (!RAND_bytes(iv, EVP_CIPHER_get_iv_length(cipher))) {
        fprintf(stderr, "Error generando IV aleatorio\n");
        return -1;
    }

    encrypt_ctx = EVP_CIPHER_CTX_new();
    if (!encrypt_ctx) {
        fprintf(stderr, "Error al crear el contexto de cifrado\n");
        return -1;
    }

    //Encripto usando la clave e IV
    if (EVP_EncryptInit_ex(encrypt_ctx, cipher, NULL, key, iv) <= 0) {
        ERR_print_errors_fp(stderr);
        return -1;
    }
    if (EVP_EncryptUpdate(encrypt_ctx, ciphertext, &len, plaintext, plaintext_len) <= 0) {
        ERR_print_errors_fp(stderr);
        return -1;
    }
    ciphertext_len = len;
    if (EVP_EncryptFinal_ex(encrypt_ctx, ciphertext + len, &len) <= 0) {
        ERR_print_errors_fp(stderr);
        return -1;
    }
    ciphertext_len += len;

    //Libero la memoria utilizada
    EVP_CIPHER_CTX_free(encrypt_ctx);
    EVP_CIPHER_free(cipher);

    return ciphertext_len;
}
