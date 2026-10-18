# Configuration

This folder stores deployment configuration and model settings used by the containers.

## Files

- gcp.env: shared GCP environment variables for local Docker-based deployment and testing
- model-config.yaml: model configuration for Isolation Forest
- bootstrap_dev_security.sh: creates local development mTLS certificates, the cloud-central JWT secret, and ignored runtime secrets for Docker Compose
- deploy_compute_engine.sh: deploys the complete simulator stack to one Google Compute Engine VM
- GCP_DEPLOYMENT.md: Google Cloud account setup, deployment, operations, and teardown instructions

Do not commit generated `.env` values or `tls/` private keys. Development credentials are not suitable for production. If WSL reports that the project filesystem cannot apply POSIX permissions, restrict `.env` and private keys with host OS ACLs. Set an approved cloud region and retention period for the deployment before use.

## Notes

Keep sensitive values like project IDs and service account paths outside source control in a secured environment when deploying to real infrastructure.
