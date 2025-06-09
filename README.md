# app-mensajeria-simple-en-c
Una app simple de mensajería con interfaz en la terminal en c. Para aprender sobre conexión básica TSL/SSL.

## Verificación previa: Necesitas las siguientes librerias/programas
1. libssl
2. libcrypto
3. openssl

## Generacion basica de certificados y claves
| **ESTO NO PRETENDE SER UN CERTIFICADO 100% PROFESIONAL, SINO FUNCIONAL PARA EL TEST DE LA APLICACION** |
| ------------- |

### PASO 1
```
Crear una carpeta "certs" en las carpetas SERVIDOR y CLIENTE
```

### PASO 2: Generacion de CA
```
mkdir ca ca/private

openssl req -x509 -nodes -days 365 -newkey rsa:4096 -keyout ./ca/private/ca_key.pem -out ./ca/ca_cert.pem -subj "/C=US/ST=TXT State/L=TXT City/O=TXT Inc./CN=example.com"

Copie la carpeta ca en las carpetas "certs" creadas previamente
```

### PASO 3: Generacion para server
```
Dentro de la carpeta "SERVIDOR/certs/", ejecute los siguientes comandos:

mkdir server server/private

openssl genrsa -out ./server/private/sv_key.pem 4096

openssl req -new -key ./server/private/sv_key.pem -out ./server/sv_cert.csr -subj "/C=US/ST=TXT State/L=TXT City/O=TXT Inc./CN=server.example.com"

openssl x509 -req -days 365 -in ./server/sv_cert.csr -extfile <(printf "subjectAltName=IP:127.0.0.1") -CA ./ca/ca_cert.pem -CAkey ./ca/private/ca_key.pem -CAcreateserial -out ./server/sv_cert.pem

```

### PASO 4: Generacion para cliente
```
Dentro de la carpeta "CLIENTE/certs/", ejecute los siguientes comandos:

mkdir cliente cliente/private cliente/public

openssl genrsa -out ./cliente/private/cl_key.pem 4096

openssl req -new -key ./cliente/private/cl_key.pem -out ./cliente/cl_cert.csr -subj "/C=US/ST=TXT State/L=TXT City/O=TXT Inc./CN=server.example.com"

openssl x509 -req -days 365 -in ./cliente/cl_cert.csr -extfile <(printf "subjectAltName=IP:127.0.0.1") -CA ./ca/ca_cert.pem -CAkey ./ca/private/ca_key.pem -CAcreateserial -out ./cliente/cl_cert.pem

openssl rsa -in private/client_key.pem -pubout -out public/client_pub_key.pem
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

Ejemplo: Estando en la carpeta CLIENTE
./clienteTLS localhost:12345 ./certs/ca/ca_cert.pem ./certs/client/client_cert.pem ./certs/client/private/client_key.pem ./certs/client/public/client_pub_key.pem
```
### Servidor
```
./servidorTSL <port> <ca_cert.pem> <server_cert.pem> <server_key.pem>

Ejemplo: Estando en la carpeta SERVIDOR
./servidorTSL 12345 ./certs/ca/ca_cert.pem ./certs/server/server_cert.pem ./certs/server/private/server_key.pem
```
