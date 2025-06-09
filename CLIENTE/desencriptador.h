#ifndef _DESENCRIPTADOR_H
#define _DESENCRIPTADOR_H

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/conf.h>

int desencriptar(unsigned char *ciphertext, int ciphertext_len,
                 unsigned char *key, unsigned char *iv,
                 unsigned char *plaintext);

#endif	/* _DESENCRIPTADOR_H */