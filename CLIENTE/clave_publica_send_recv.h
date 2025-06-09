#ifndef _CLAVE_PUBLICA_SEND_RECV_H
#define _CLAVE_PUBLICA_SEND_RECV_H

#include <openssl/bio.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/conf.h>

void enviar_archivo(SSL *ssl, const char *filename);
void recibir_archivo(SSL *ssl, const char *filename);
void *leer_archivo_a_buffer(const char *ruta, size_t *tam);
int escribir_a_archivo(const char *ruta, const void *buffer, size_t tam);

#endif	/* _CLAVE_PUBLICA_SEND_RECV_H */