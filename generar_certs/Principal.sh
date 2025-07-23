cd ..

mkdir CLIENTE/certs CLIENTE/certs/cliente CLIENTE/certs/cliente/private CLIENTE/certs/cliente/public CLIENTE/external_pub_key

mkdir SERVIDOR/certs SERVIDOR/certs/server SERVIDOR/certs/server/private

mkdir ca ca/private

openssl req -x509 -nodes -days 365 -newkey rsa:4096 -keyout ./ca/private/ca_key.pem -out ./ca/ca_cert.pem -subj "/C=US/ST=TXT State/L=TXT City/O=TXT Inc./CN=example.com"

cp -r ca SERVIDOR/certs
cp -r ca CLIENTE/certs

cd CLIENTE/certs

openssl genrsa -out ./cliente/private/cl_key.pem 4096

openssl req -new -key ./cliente/private/cl_key.pem -out ./cliente/cl_cert.csr -subj "/C=US/ST=TXT State/L=TXT City/O=TXT Inc./CN=server.example.com"

openssl x509 -req -days 365 -in ./cliente/cl_cert.csr -extfile <(printf "subjectAltName=IP:127.0.0.1") -CA ./ca/ca_cert.pem -CAkey ./ca/private/ca_key.pem -CAcreateserial -out ./cliente/cl_cert.pem

openssl rsa -in ./cliente/private/cl_key.pem -pubout -out ./cliente/public/cl_pub_key.pem

cd ../..
cd SERVIDOR/certs

openssl genrsa -out ./server/private/sv_key.pem 4096

openssl req -new -key ./server/private/sv_key.pem -out ./server/sv_cert.csr -subj "/C=US/ST=TXT State/L=TXT City/O=TXT Inc./CN=server.example.com"

openssl x509 -req -days 365 -in ./server/sv_cert.csr -extfile <(printf "subjectAltName=IP:127.0.0.1") -CA ./ca/ca_cert.pem -CAkey ./ca/private/ca_key.pem -CAcreateserial -out ./server/sv_cert.pem