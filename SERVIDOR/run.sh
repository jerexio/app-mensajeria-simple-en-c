#!/bin/bash
read -p "Ingrese el numero de PUERTO: " PORT
make
./servidorTSL "$PORT" ./certs/ca/ca_cert.pem ./certs/server/sv_cert.pem ./certs/server/private/sv_key.pem
