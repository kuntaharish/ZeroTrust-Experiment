#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CERT_DIR="${ROOT_DIR}/certs"
mkdir -p "${CERT_DIR}"

cd "${CERT_DIR}"

echo "🔐 Generating trusted CA..."
openssl genrsa -out ca.key 2048 >/dev/null 2>&1
openssl req -x509 -new -nodes -key ca.key -sha256 -days 3650 \
  -subj "/CN=ZT-Trusted-CA" \
  -out ca.crt >/dev/null 2>&1

echo "🔐 Generating server cert for localhost (SAN=localhost)..."
openssl genrsa -out server.key 2048 >/dev/null 2>&1

cat > server_openssl.cnf <<'EOF'
[ req ]
default_bits       = 2048
prompt             = no
default_md         = sha256
distinguished_name = dn
req_extensions     = req_ext

[ dn ]
CN = localhost

[ req_ext ]
subjectAltName = @alt_names

[ alt_names ]
DNS.1 = localhost
IP.1  = 127.0.0.1
EOF

openssl req -new -key server.key -out server.csr -config server_openssl.cnf >/dev/null 2>&1
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -CAcreateserial \
  -out server.crt -days 825 -sha256 -extensions req_ext -extfile server_openssl.cnf >/dev/null 2>&1

gen_client () {
  local name="$1"
  echo "🔐 Generating client cert for ${name}..."
  openssl genrsa -out "${name}.key" 2048 >/dev/null 2>&1
  openssl req -new -key "${name}.key" -out "${name}.csr" -subj "/CN=${name}" >/dev/null 2>&1
  openssl x509 -req -in "${name}.csr" -CA ca.crt -CAkey ca.key -CAcreateserial \
    -out "${name}.crt" -days 825 -sha256 >/dev/null 2>&1
}

gen_client "service-a"
gen_client "service-b"
gen_client "service-c"
gen_client "service-d"

echo "🧪 Generating rogue CA + rogue client cert..."
openssl genrsa -out rogue_ca.key 2048 >/dev/null 2>&1
openssl req -x509 -new -nodes -key rogue_ca.key -sha256 -days 3650 \
  -subj "/CN=Rogue-CA" \
  -out rogue_ca.crt >/dev/null 2>&1

openssl genrsa -out rogue_client.key 2048 >/dev/null 2>&1
openssl req -new -key rogue_client.key -out rogue_client.csr -subj "/CN=evil-worm" >/dev/null 2>&1
openssl x509 -req -in rogue_client.csr -CA rogue_ca.crt -CAkey rogue_ca.key -CAcreateserial \
  -out rogue_client.crt -days 825 -sha256 >/dev/null 2>&1

chmod 600 *.key || true

echo "✅ Done. Generated certs in ${CERT_DIR}"
echo "   Trusted CA: ca.crt"
echo "   Server: server.crt/server.key"
echo "   Clients: service-a.crt..service-d.crt"
echo "   Rogue: rogue_client.crt signed by rogue_ca.crt"
