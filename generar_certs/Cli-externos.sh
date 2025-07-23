cd ..

mkdir CLIENTE/certs CLIENTE/certs/cliente CLIENTE/certs/cliente/private CLIENTE/certs/cliente/public CLIENTE/external_pub_key

cp -r ca CLIENTE/certs

cd CLIENTE/certs

openssl genrsa -out ./cliente/private/cl_key.pem 4096

openssl req -new -key ./cliente/private/cl_key.pem -out ./cliente/cl_cert.csr -subj "/C=US/ST=TXT State/L=TXT City/O=TXT Inc./CN=server.example.com"

openssl x509 -req -days 365 -in ./cliente/cl_cert.csr -extfile <(printf "subjectAltName=IP:127.0.0.1") -CA ./ca/ca_cert.pem -CAkey ./ca/private/ca_key.pem -CAcreateserial -out ./cliente/cl_cert.pem

openssl rsa -in ./cliente/private/cl_key.pem -pubout -out ./cliente/public/cl_pub_key.pem
