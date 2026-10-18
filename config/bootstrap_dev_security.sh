#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TLS_DIR="${ROOT_DIR}/config/tls"
ENV_FILE="${ROOT_DIR}/.env"

command -v openssl >/dev/null 2>&1 || {
  echo "OpenSSL is required. Run this script in Ubuntu under WSL." >&2
  exit 1
}

if [[ -f "${ENV_FILE}" \
  && -f "${TLS_DIR}/ca.crt" \
  && -f "${TLS_DIR}/central-server.crt" \
  && -f "${TLS_DIR}/central-server.key" \
  && -f "${TLS_DIR}/cloud-client.crt" \
  && -f "${TLS_DIR}/cloud-client.key" ]]; then
  if grep -Eq '^CENTRAL_SERVICE_JWT_SECRET=.{32,}$' "${ENV_FILE}"; then
    echo "Existing local mTLS credentials and JWT signing secret are ready."
    exit 0
  fi
  CENTRAL_SERVICE_JWT_SECRET="$(openssl rand -base64 48 | tr -d '\r\n')"
  sed -i '/^CENTRAL_SERVICE_JWT_SECRET=/d' "${ENV_FILE}"
  printf '\nCENTRAL_SERVICE_JWT_SECRET=%s\n' \
    "${CENTRAL_SERVICE_JWT_SECRET}" >> "${ENV_FILE}"
  if ! chmod 600 "${ENV_FILE}"; then
    echo "WARNING: this filesystem does not support POSIX chmod; restrict .env with host OS permissions." >&2
  fi
  echo "Added a random cloud-central JWT signing secret to the existing local .env without replacing certificates or other secrets."
  exit 0
fi

if [[ -e "${ENV_FILE}" || -e "${TLS_DIR}" ]]; then
  echo "Refusing to overwrite existing local secrets or certificates." >&2
  echo "Existing credentials are incomplete. Back them up and repair the missing files manually before regenerating." >&2
  exit 1
fi

umask 077
mkdir -p "${TLS_DIR}"

openssl rand -base64 48 > "${ROOT_DIR}/.vehicle_socket_secret"
VEHICLE_SOCKET_SECRET="$(tr -d '\r\n' < "${ROOT_DIR}/.vehicle_socket_secret")"
rm "${ROOT_DIR}/.vehicle_socket_secret"
SCAN_HISTORY_ENCRYPTION_KEY="$(openssl rand -base64 32 | tr '+/' '-_' | tr -d '\r\n')"
CENTRAL_SERVICE_JWT_SECRET="$(openssl rand -base64 48 | tr -d '\r\n')"

openssl genrsa -out "${TLS_DIR}/dev-ca.key" 3072
openssl req -x509 -new -sha256 \
  -key "${TLS_DIR}/dev-ca.key" \
  -days 3650 \
  -subj "/CN=Automotive Scanner Development CA" \
  -addext "basicConstraints=critical,CA:TRUE" \
  -addext "keyUsage=critical,keyCertSign,cRLSign" \
  -out "${TLS_DIR}/ca.crt"

openssl req -new -newkey rsa:3072 -nodes \
  -keyout "${TLS_DIR}/central-server.key" \
  -out "${TLS_DIR}/central-server.csr" \
  -subj "/CN=vehicle-central-compute"
cat > "${TLS_DIR}/central-server.ext" <<'EOF'
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:vehicle-central-compute,DNS:localhost,IP:127.0.0.1
EOF
openssl x509 -req -sha256 \
  -in "${TLS_DIR}/central-server.csr" \
  -CA "${TLS_DIR}/ca.crt" \
  -CAkey "${TLS_DIR}/dev-ca.key" \
  -CAcreateserial \
  -days 365 \
  -extfile "${TLS_DIR}/central-server.ext" \
  -out "${TLS_DIR}/central-server.crt"

openssl req -new -newkey rsa:3072 -nodes \
  -keyout "${TLS_DIR}/cloud-client.key" \
  -out "${TLS_DIR}/cloud-client.csr" \
  -subj "/CN=cloud-app"
cat > "${TLS_DIR}/cloud-client.ext" <<'EOF'
basicConstraints=CA:FALSE
keyUsage=digitalSignature,keyEncipherment
extendedKeyUsage=clientAuth
EOF
openssl x509 -req -sha256 \
  -in "${TLS_DIR}/cloud-client.csr" \
  -CA "${TLS_DIR}/ca.crt" \
  -CAkey "${TLS_DIR}/dev-ca.key" \
  -CAcreateserial \
  -days 365 \
  -extfile "${TLS_DIR}/cloud-client.ext" \
  -out "${TLS_DIR}/cloud-client.crt"

cat > "${ENV_FILE}" <<EOF
VEHICLE_SOCKET_SECRET=${VEHICLE_SOCKET_SECRET}
SCAN_HISTORY_ENCRYPTION_KEY=${SCAN_HISTORY_ENCRYPTION_KEY}
CENTRAL_SERVICE_JWT_SECRET=${CENTRAL_SERVICE_JWT_SECRET}
SCAN_RETENTION_DAYS=30
CLOUD_REGION=unspecified
EOF

if ! chmod 600 "${ENV_FILE}" \
  "${TLS_DIR}/dev-ca.key" \
  "${TLS_DIR}/central-server.key" \
  "${TLS_DIR}/cloud-client.key"; then
  echo "WARNING: this filesystem does not support POSIX chmod; restrict the generated secret files with host OS permissions." >&2
fi

echo "Development mTLS certificates and local encryption keys created."
echo "Private keys and .env are Git-ignored. Do not use these development credentials in production."
echo "Set CLOUD_REGION in .env to the actual approved cloud deployment region before deployment."
