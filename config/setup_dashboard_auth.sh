#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="${ROOT_DIR}/.env"

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run this setup with sudo: sudo bash config/setup_dashboard_auth.sh" >&2
  exit 1
fi

if [[ ! -f "${ENV_FILE}" ]]; then
  echo "Missing ${ENV_FILE}; first run config/bootstrap_dev_security.sh." >&2
  exit 1
fi

command -v docker >/dev/null 2>&1 || {
  echo "Docker Engine is required on this VM." >&2
  exit 1
}

if ! command -v htpasswd >/dev/null 2>&1; then
  apt-get update
  apt-get install -y apache2-utils
fi

read -r -p "Dashboard hostname (for example aegisdrive-automotive.duckdns.org): " domain
if [[ ! "${domain}" =~ ^[A-Za-z0-9.-]+$ || "${domain}" != *.* ]]; then
  echo "Enter a valid DNS hostname without a scheme or path." >&2
  exit 1
fi

read -r -p "Dashboard username: " username
if [[ ! "${username}" =~ ^[A-Za-z0-9._-]{1,64}$ ]]; then
  echo "Use 1-64 letters, digits, dots, underscores, or hyphens for the username." >&2
  exit 1
fi

echo "Enter a unique dashboard password when prompted by htpasswd."
echo "Do not reuse your Google account password."
auth_entry="$(htpasswd -nB "${username}")"
password_hash="${auth_entry#*:}"
if [[ "${password_hash}" == "${auth_entry}" || "${password_hash}" != '$2'* ]]; then
  echo "Failed to generate a bcrypt password hash." >&2
  exit 1
fi

temporary_env="$(mktemp)"
trap 'rm -f "${temporary_env}"' EXIT
awk '!/^DASHBOARD_(DOMAIN|USER|PASSWORD_HASH)=/' "${ENV_FILE}" > "${temporary_env}"
{
  cat "${temporary_env}"
  printf 'DASHBOARD_DOMAIN=%s\n' "${domain}"
  printf 'DASHBOARD_USER=%s\n' "${username}"
  printf "DASHBOARD_PASSWORD_HASH='%s'\n" "${password_hash}"
} > "${ENV_FILE}"
chmod 600 "${ENV_FILE}"

cd "${ROOT_DIR}"
docker compose --profile public-dashboard config --quiet
docker compose --profile public-dashboard run --rm --no-deps caddy \
  caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile
docker compose --profile public-dashboard up -d --build

printf '\nDashboard deployment started for https://%s\n' "${domain}"
printf 'Caddy will obtain and renew a publicly trusted HTTPS certificate after DNS and ports 80/443 are reachable.\n'
printf 'Check startup with: cd %q && docker compose --profile public-dashboard ps\n' "${ROOT_DIR}"
