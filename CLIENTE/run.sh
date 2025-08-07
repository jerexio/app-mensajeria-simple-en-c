#!/bin/bash
read -p "Ingrese el HOST:PUERTO (ejemplo, 127.0.0.1:9999): " HOSTPUERTO
make
./clienteTLS "$HOSTPUERTO" ./certs/ca/ca_cert.pem ./certs/cliente/cl_cert.pem ./certs/cliente/private/cl_key.pem ./certs/cliente/public/cl_pub_key.pem ./external_pub_key/cl_pub_key.pem 
