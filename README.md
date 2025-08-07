# app-mensajeria-simple-en-c
Una app simple de mensajería con interfaz en la terminal en c. Para aprender sobre conexión básica TSL/SSL.

## Verificación previa: Necesitas las siguientes librerias/programas
1. libssl
2. libcrypto
3. openssl

### Distros basadas en Debian
libssl-dev y openssl

## Generacion basica de certificados y claves
| **ESTO NO PRETENDE SER UN CERTIFICADO 100% PROFESIONAL, SINO FUNCIONAL PARA EL TEST DE LA APLICACION** |
| ------------- |
```
En la carpeta generar_certs, ejecutar:
bash Principal.sh

Para generar certificados en un cliente externos
bash Cli-externo.sh
```
Asegurese de compartir las claves publicas de los clientes y almacenarlas en la carpeta external_pub_key

## ¿Como compilar y ejecutar?
### Cliente
```
En la carpeta CLIENTE (Luego de crear los certificados)
bash run.sh
```
### Servidor
```
En la carpeta SERVIDOR (Luego de crear los certificados)
bash run.sh
```
