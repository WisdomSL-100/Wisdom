#!/usr/bin/env bash
# Deploy the complete simulator stack to one Compute Engine VM.
# Run locally after `gcloud auth login` and `gcloud auth application-default login`.
set -euo pipefail

PROJECT_ID=${1:?Usage: $0 PROJECT_ID [ZONE] [INSTANCE] [ALLOWED_CIDR]}
ZONE=${2:-us-central1-a}
INSTANCE=${3:-aegisdrive-demo}
ALLOWED_CIDR=${4:-0.0.0.0/0}
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
gcloud services enable compute.googleapis.com

if gcloud compute firewall-rules describe aegisdrive-frontend >/dev/null 2>&1; then
  :
else
  gcloud compute firewall-rules create aegisdrive-frontend \
    --network=default --direction=INGRESS --action=ALLOW --rules=tcp:3000 \
    --source-ranges="$ALLOWED_CIDR" --target-tags=aegisdrive-frontend
fi

if gcloud compute instances describe "$INSTANCE" --zone="$ZONE" >/dev/null 2>&1; then
  :
else
  gcloud compute instances create "$INSTANCE" \
    --zone="$ZONE" --machine-type="$MACHINE_TYPE" \
    --image-family="$IMAGE_FAMILY" --image-project="$IMAGE_PROJECT" \
    --boot-disk-size=40GB --tags=aegisdrive-frontend \
    --metadata=enable-oslogin=TRUE
fi

tar --create --gzip --file="$ARCHIVE" \
  --exclude=.git --exclude=.venv --exclude=__pycache__ --exclude='*/__pycache__' \
  --exclude='.env' --exclude='config/tls' --exclude='cloud-app/data' \
  -C "$(dirname "$ROOT_DIR")" "$(basename "$ROOT_DIR")"

gcloud compute ssh "$INSTANCE" --zone="$ZONE" --command='sudo apt-get update && sudo apt-get install -y docker.io docker-compose-v2 openssl && sudo systemctl enable --now docker && sudo usermod -aG docker $USER'
gcloud compute scp "$ARCHIVE" "$INSTANCE:$REMOTE_ARCHIVE" --zone="$ZONE"
gcloud compute ssh "$INSTANCE" --zone="$ZONE" --command="set -e; rm -rf ~/aegisdrive; mkdir -p ~/aegisdrive; tar -xzf $REMOTE_ARCHIVE -C ~/aegisdrive --strip-components=1; cd ~/aegisdrive; sed -i 's/^PROJECT_ID=.*/PROJECT_ID=$PROJECT_ID/' config/gcp.env; bash config/bootstrap_dev_security.sh; sudo docker compose up -d --build"

EXTERNAL_IP=$(gcloud compute instances describe "$INSTANCE" --zone="$ZONE" --format='get(networkInterfaces[0].accessConfigs[0].natIP)')
printf '\nDeployment started. Dashboard: http://%s:3000\n' "$EXTERNAL_IP"
printf 'Wait for health checks, then use: gcloud compute ssh %s --zone=%s --command="cd ~/aegisdrive && sudo docker compose ps"\n' "$INSTANCE" "$ZONE"
