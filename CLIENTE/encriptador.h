#ifndef _ENCRIPTADOR_H
#define _ENCRIPTADOR_H

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/conf.h>

int encriptar(unsigned char *plaintext, int plaintext_len,
              unsigned char *key, unsigned char *iv,
              unsigned char *ciphertext);

#endif	/* _ENCRIPTADOR_H */