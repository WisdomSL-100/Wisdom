# GCP deployment

This simulator is deployed as a single Compute Engine VM because the vehicle-node containers use private TCP sockets and Compose health dependencies. Cloud Run is not an appropriate replacement for this multi-container simulator topology.

## One-time Google Cloud setup

1. Create or select a GCP project and enable billing.
2. Install the [Google Cloud CLI](https://cloud.google.com/sdk/docs/install).
3. Authenticate locally:

   ```bash
   gcloud auth login
   gcloud auth application-default login
   ```

4. Run the deployment script from WSL or another Linux shell:

   ```bash
   cd /mnt/c/work/workspace/automotive-cybersecurity-scanner
   chmod +x config/deploy_compute_engine.sh
   ./config/deploy_compute_engine.sh YOUR_PROJECT_ID us-central1-a aegisdrive-demo YOUR_PUBLIC_IP/32
   ```

Use your public IP with `/32` instead of `0.0.0.0/0` to limit dashboard access. The script enables Compute Engine, creates a firewall rule for dashboard port 3000, creates an `e2-standard-4` Ubuntu VM, installs Docker Compose, creates simulator-only TLS/secrets on the VM, uploads this source tree, and starts the complete stack.

## Operations

```bash
# Check services
 gcloud compute ssh aegisdrive-demo --zone us-central1-a \
  --command='cd ~/aegisdrive && sudo docker compose ps'

# Read logs
 gcloud compute ssh aegisdrive-demo --zone us-central1-a \
  --command='cd ~/aegisdrive && sudo docker compose logs --tail=100 cloud-app'

# Stop charges while preserving the VM disk
 gcloud compute instances stop aegisdrive-demo --zone us-central1-a

# Remove all deployed resources
 gcloud compute instances delete aegisdrive-demo --zone us-central1-a
 gcloud compute firewall-rules delete aegisdrive-frontend
```

## Security and scope

This deployment hosts a simulator only. The dashboard is exposed on port 3000; the simulator sockets and internal cloud services remain on the Compose private network. The script generates development mTLS certificates and secrets on the VM. Replace those development credentials with Secret Manager-backed production secrets before any non-demo deployment.
