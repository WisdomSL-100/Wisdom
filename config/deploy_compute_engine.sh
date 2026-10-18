#!/usr/bin/env bash
# Deploy the complete simulator stack to one Compute Engine VM.
# Run from Google Cloud Shell or a Linux shell authenticated to the target project.
set -euo pipefail

PROJECT_ID=${1:?Usage: $0 PROJECT_ID [ZONE] [INSTANCE]}
ZONE=${2:-us-central1-a}
INSTANCE=${3:-sdv-cyber-scanner}
MACHINE_TYPE=${MACHINE_TYPE:-e2-standard-4}
IMAGE_FAMILY=${IMAGE_FAMILY:-ubuntu-2404-lts-amd64}
IMAGE_PROJECT=${IMAGE_PROJECT:-ubuntu-os-cloud}
ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
ARCHIVE=$(mktemp /tmp/aegisdrive-source.XXXXXX.tar.gz)
REMOTE_ARCHIVE=/tmp/aegisdrive-source.tar.gz

cleanup() { rm -f "$ARCHIVE"; }
trap cleanup EXIT

command -v gcloud >/dev/null || { echo 'Install Google Cloud CLI first.' >&2; exit 1; }
gcloud config set project "$PROJECT_ID"
gcloud services enable compute.googleapis.com iap.googleapis.com

if gcloud compute firewall-rules describe aegisdrive-frontend >/dev/null 2>&1; then
  gcloud compute firewall-rules update aegisdrive-frontend \
    --network=default --direction=INGRESS --action=ALLOW \
    --rules=tcp:80,tcp:443,udp:443 --source-ranges=0.0.0.0/0 \
    --target-tags=aegisdrive-frontend \
    --description='Public HTTPS dashboard through Caddy authentication; HTTP only for certificate issuance and HTTPS redirect'
else
  gcloud compute firewall-rules create aegisdrive-frontend \
    --network=default --direction=INGRESS --action=ALLOW \
    --rules=tcp:80,tcp:443,udp:443 --source-ranges=0.0.0.0/0 \
    --target-tags=aegisdrive-frontend \
    --description='Public HTTPS dashboard through Caddy authentication; HTTP only for certificate issuance and HTTPS redirect'
fi

if gcloud compute firewall-rules describe aegisdrive-iap-ssh >/dev/null 2>&1; then
  gcloud compute firewall-rules update aegisdrive-iap-ssh \
    --network=default --direction=INGRESS --action=ALLOW --rules=tcp:22 \
    --source-ranges=35.235.240.0/20 --target-tags=aegisdrive-ssh \
    --description='SSH access through Identity-Aware Proxy only'
else
  gcloud compute firewall-rules create aegisdrive-iap-ssh \
    --network=default --direction=INGRESS --action=ALLOW --rules=tcp:22 \
    --source-ranges=35.235.240.0/20 --target-tags=aegisdrive-ssh \
    --description='SSH access through Identity-Aware Proxy only'
fi

if gcloud compute instances describe "$INSTANCE" --zone="$ZONE" >/dev/null 2>&1; then
  gcloud compute instances add-tags "$INSTANCE" --zone="$ZONE" \
    --tags=aegisdrive-frontend,aegisdrive-ssh
else
  gcloud compute instances create "$INSTANCE" \
    --zone="$ZONE" --machine-type="$MACHINE_TYPE" \
    --image-family="$IMAGE_FAMILY" --image-project="$IMAGE_PROJECT" \
    --boot-disk-size=40GB --tags=aegisdrive-frontend,aegisdrive-ssh \
    --metadata=enable-oslogin=TRUE
fi

tar --create --gzip --file="$ARCHIVE" \
  --exclude=.git --exclude=.venv --exclude=__pycache__ --exclude='*/__pycache__' \
  --exclude='.env' --exclude='config/tls' --exclude='cloud-app/data' \
  -C "$(dirname "$ROOT_DIR")" "$(basename "$ROOT_DIR")"

gcloud compute ssh "$INSTANCE" --zone="$ZONE" --tunnel-through-iap \
  --command='sudo apt-get update && sudo apt-get install -y docker.io docker-compose-v2 openssl apache2-utils && sudo systemctl enable --now docker'
gcloud compute scp "$ARCHIVE" "$INSTANCE:$REMOTE_ARCHIVE" --zone="$ZONE" \
  --tunnel-through-iap
gcloud compute ssh "$INSTANCE" --zone="$ZONE" --tunnel-through-iap \
  --command="set -e; mkdir -p ~/aegisdrive; tar -xzf $REMOTE_ARCHIVE -C ~/aegisdrive --strip-components=1; cd ~/aegisdrive; sed -i 's/^PROJECT_ID=.*/PROJECT_ID=$PROJECT_ID/' config/gcp.env; sudo bash config/bootstrap_dev_security.sh"

EXTERNAL_IP=$(gcloud compute instances describe "$INSTANCE" --zone="$ZONE" --format='get(networkInterfaces[0].accessConfigs[0].natIP)')
printf '\nSource uploaded and local-only credentials initialized on the VM.\n'
printf 'Point your DNS hostname to the VM external IP: %s\n' "$EXTERNAL_IP"
printf 'After DNS resolves, configure HTTPS/password and start services with:\n'
printf '  gcloud compute ssh %s --zone=%s --tunnel-through-iap\n' "$INSTANCE" "$ZONE"
printf 'Then in the VM shell run: cd ~/aegisdrive && sudo bash config/setup_dashboard_auth.sh\n'
