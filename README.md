# app-mensajeria-simple-en-c
Una app simple de mensajería con interfaz en la terminal en c. Para aprender sobre conexión básica TSL/SSL.

## Verificación previa: Necesitas las siguientes librerias/programas
1. libssl
2. libcrypto
3. openssl

## Generacion basica de certificados y claves
| **ESTO NO PRETENDE SER UN CERTIFICADO 100% PROFESIONAL, SINO FUNCIONAL PARA EL TEST DE LA APLICACION** |
| ------------- |

### Generacion de CA
```
mkdir ca ca/private

openssl req -x509 -nodes -days 365 -newkey rsa:4096 -keyout ./ca/private/ca_key.pem -out ./ca/ca_cert.pem -subj "/C=US/ST=TXT State/L=TXT City/O=TXT Inc./CN=example.com"
```

### Generacion para server
```
mkdir server server/private

openssl genrsa -out ./server/private/sv_key.pem 4096

openssl req -new -key ./server/private/sv_key.pem -out ./server/sv_cert.csr -subj "/C=US/ST=TXT State/L=TXT City/O=TXT Inc./CN=server.example.com"

openssl x509 -req -days 365 -in ./server/sv_cert.csr -extfile <(printf "subjectAltName=IP:127.0.0.1") -CA ./ca/ca_cert.pem -CAkey ./ca/private/ca_key.pem -CAcreateserial -out ./server/sv_cert.pem

```

### Generacion para cliente
```
mkdir cliente cliente/private

openssl genrsa -out ./cliente/private/cl_key.pem 4096

openssl req -new -key ./cliente/private/cl_key.pem -out ./cliente/cl_cert.csr -subj "/C=US/ST=TXT State/L=TXT City/O=TXT Inc./CN=server.example.com"

openssl x509 -req -days 365 -in ./cliente/cl_cert.csr -extfile <(printf "subjectAltName=IP:127.0.0.1") -CA ./ca/ca_cert.pem -CAkey ./ca/private/ca_key.pem -CAcreateserial -out ./cliente/cl_cert.pem

```

## ¿Como compilar?
### Cliente
```
gcc -o clienteTLS clienteTLS.c -lssl -lcrypto -lpthread
```
### Servidor
```
gcc -o servidorTSL servidorTSL.c -lssl -lcrypto -lpthread
```

## ¿Como ejecutar?
### Cliente
```
./clienteTLS localhost:<port> <ca_cert.pem> <client_cert.pem> <client_key.pem>
```
### Servidor
```
./servidorTSL <port> <ca_cert.pem> <server_cert.pem> <server_key.pem>
```
