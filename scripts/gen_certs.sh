#!/usr/bin/env bash
set -euo pipefail

CERT_DIR="certs"
mkdir -p "${CERT_DIR}"

# Services: a..l (12 services)
SERVICES=(service-a service-b service-c service-d service-e service-f service-g service-h service-i service-j service-k service-l)

# Key type: rsa (default) or ecdsa
KEY_TYPE="${KEY_TYPE:-rsa}"

echo "[*] Generating certs into ./${CERT_DIR} (KEY_TYPE=${KEY_TYPE})"

# --- Helpers ---
gen_key() {
  local out="$1"
  if [[ "${KEY_TYPE}" == "ecdsa" ]]; then
    openssl ecparam -name prime256v1 -genkey -noout -out "${out}"
  else
    openssl genrsa -out "${out}" 2048
  fi
}

# --- CA ---
if [[ ! -f "${CERT_DIR}/ca.key" || ! -f "${CERT_DIR}/ca.crt" ]]; then
  echo "[*] Creating CA"
  gen_key "${CERT_DIR}/ca.key"
  openssl req -x509 -new -nodes -key "${CERT_DIR}/ca.key" \
    -sha256 -days 3650 \
    -subj "/CN=ZeroTrust-Experiment-CA" \
    -out "${CERT_DIR}/ca.crt"
else
  echo "[*] CA already exists. Reusing ${CERT_DIR}/ca.crt"
fi

# --- Server cert (localhost) ---
echo "[*] Creating server cert (localhost)"
gen_key "${CERT_DIR}/server.key"

cat > "${CERT_DIR}/server.cnf" <<'EOF'
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

openssl req -new -key "${CERT_DIR}/server.key" -out "${CERT_DIR}/server.csr" -config "${CERT_DIR}/server.cnf"

openssl x509 -req -in "${CERT_DIR}/server.csr" \
  -CA "${CERT_DIR}/ca.crt" -CAkey "${CERT_DIR}/ca.key" -CAcreateserial \
  -out "${CERT_DIR}/server.crt" -days 3650 -sha256 \
  -extensions req_ext -extfile "${CERT_DIR}/server.cnf"

rm -f "${CERT_DIR}/server.csr" "${CERT_DIR}/server.cnf"

# --- Client certs per service ---
echo "[*] Creating client certs for: ${SERVICES[*]}"
for svc in "${SERVICES[@]}"; do
  gen_key "${CERT_DIR}/${svc}.key"
  openssl req -new -key "${CERT_DIR}/${svc}.key" \
    -subj "/CN=${svc}" \
    -out "${CERT_DIR}/${svc}.csr"
  openssl x509 -req -in "${CERT_DIR}/${svc}.csr" \
    -CA "${CERT_DIR}/ca.crt" -CAkey "${CERT_DIR}/ca.key" -CAcreateserial \
    -out "${CERT_DIR}/${svc}.crt" -days 3650 -sha256
  rm -f "${CERT_DIR}/${svc}.csr"
done

# --- Rogue CA + rogue client (for attacker cert tests) ---
echo "[*] Creating rogue CA + rogue client cert"
gen_key "${CERT_DIR}/rogue_ca.key"
openssl req -x509 -new -nodes -key "${CERT_DIR}/rogue_ca.key" \
  -sha256 -days 3650 \
  -subj "/CN=Rogue-CA" \
  -out "${CERT_DIR}/rogue_ca.crt"

gen_key "${CERT_DIR}/rogue_client.key"
openssl req -new -key "${CERT_DIR}/rogue_client.key" \
  -subj "/CN=rogue-client" \
  -out "${CERT_DIR}/rogue_client.csr"
openssl x509 -req -in "${CERT_DIR}/rogue_client.csr" \
  -CA "${CERT_DIR}/rogue_ca.crt" -CAkey "${CERT_DIR}/rogue_ca.key" -CAcreateserial \
  -out "${CERT_DIR}/rogue_client.crt" -days 3650 -sha256
rm -f "${CERT_DIR}/rogue_client.csr"

# --- Metadata for reproducibility ---
cat > "${CERT_DIR}/cert_metadata.json" <<EOF
{
  "generated_at_utc": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "key_type": "${KEY_TYPE}",
  "services": $(python - <<PY
import json
svcs = ${SERVICES[@]+"${SERVICES[@]}"}
print(json.dumps(svcs))
PY
)
}
EOF

echo "[+] Done. Generated:"
ls -1 "${CERT_DIR}" | sed 's/^/  - /'
