#!/usr/bin/env bash
set -euo pipefail

mkdir -p certs
cd certs

echo "==> Cleaning old certs..."
rm -f *.crt *.key *.csr *.srl *.pem server.cnf 2>/dev/null || true
rm -f rogue_* 2>/dev/null || true

echo "==> Generating trusted CA..."
openssl genrsa -out ca.key 4096
openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650 \
  -subj "/C=US/ST=CA/L=MountainView/O=EB1A-Research/OU=CA/CN=EB1A-Research-RootCA" \
  -out ca.crt

echo "==> Generating server cert (SAN=localhost,127.0.0.1)..."
openssl genrsa -out server.key 4096

cat > server.cnf << 'EOF'
[req]
default_bits = 4096
prompt = no
default_md = sha256
distinguished_name = dn
req_extensions = req_ext

[dn]
C=US
ST=CA
L=MountainView
O=EB1A-Research
OU=Server
CN=localhost

[req_ext]
subjectAltName = @alt_names

[alt_names]
DNS.1 = localhost
IP.1 = 127.0.0.1
EOF

openssl req -new -key server.key -out server.csr -config server.cnf
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out server.crt -days 825 -sha256 -extensions req_ext -extfile server.cnf

echo "==> Generating GOOD client cert (signed by trusted CA)..."
openssl genrsa -out client_good.key 4096
openssl req -new -key client_good.key -out client_good.csr \
  -subj "/C=US/ST=CA/L=MountainView/O=EB1A-Research/OU=Client/CN=service-a"

openssl x509 -req -in client_good.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out client_good.crt -days 825 -sha256

echo "==> Generating ROGUE CA + BAD client cert (attacker)..."
openssl genrsa -out rogue_ca.key 4096
openssl req -x509 -new -nodes -key rogue_ca.key -sha256 -days 3650 \
  -subj "/C=US/ST=CA/L=MountainView/O=AttackerLab/OU=CA/CN=Rogue-RootCA" \
  -out rogue_ca.crt

openssl genrsa -out client_bad.key 4096
openssl req -new -key client_bad.key -out client_bad.csr \
  -subj "/C=US/ST=CA/L=MountainView/O=AttackerLab/OU=Client/CN=attacker-x"

openssl x509 -req -in client_bad.csr -CA rogue_ca.crt -CAkey rogue_ca.key -CAcreateserial \
  -out client_bad.crt -days 825 -sha256

echo "==> Done. Generated in ./certs"
echo "Trusted CA:        certs/ca.crt"
echo "Server cert/key:   certs/server.crt , certs/server.key"
echo "Good client cert:  certs/client_good.crt , certs/client_good.key"
echo "Bad client cert:   certs/client_bad.crt , certs/client_bad.key (signed by rogue CA)"
