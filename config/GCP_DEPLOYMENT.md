# GCP demo deployment

This runbook deploys the simulator stack to one Compute Engine VM. The
multi-container vehicle topology uses private TCP sockets and Compose health
dependencies, so this stack is not a direct Cloud Run deployment.

The shared dashboard is published by Caddy with automatic HTTPS and
username/password authentication. The frontend and internal APIs bind only to
the VM loopback address; simulator sockets stay on the private Compose
network. This is a protected prototype demo, not a production vehicle service.

## Before you start

You need:

- A GCP project with billing enabled and permission to enable APIs, create
  Compute Engine firewall rules/VMs, and use IAP SSH.
- A running Ubuntu 24.04 LTS x86/64 VM. Suggested demo size: `e2-standard-4`
  and a 40 GB balanced persistent boot disk. The deployment script can create
  the VM if it does not exist.
- A static external IPv4 address assigned to the VM. Reserve it in **VPC
  network → IP addresses**, then edit the VM network interface to use that
  reserved address. Static addresses can incur charges; review current GCP
  pricing.
- A public DNS hostname you control. This example uses
  `aegisdrive-automotive.duckdns.org`.
- Google Cloud Shell, opened in the Console with the correct project selected.
  No local or WSL Google Cloud CLI installation is required.

Set a billing budget and alerts. A budget is a notification, not a hard
spending cap. Stopping the VM stops compute charges, but the boot disk and
reserved IP may continue to incur charges.

## 1. Point DNS to the VM

In your DuckDNS account, set the IPv4 address for
`aegisdrive-automotive.duckdns.org` to the VM's **static external IP**. Keep
your DuckDNS token private; do not put it in the repository or share it here.

Wait for DNS to update, then in Cloud Shell check:

```bash
getent ahostsv4 aegisdrive-automotive.duckdns.org
```

The returned address must match the VM's static external IP before starting
Caddy. Caddy needs the hostname to resolve publicly and inbound TCP ports 80
and 443 to be reachable to request a trusted TLS certificate.

## 2. Select the GCP project and get the source

In Cloud Shell, select your project (use its **Project ID**, not display name)
and verify the VM:

```bash
gcloud config set project YOUR_PROJECT_ID
gcloud compute instances list
```

Clone the public project and enter its root directory:

```bash
git clone https://github.com/WisdomSL-100/Wisdom.git
cd Wisdom
```

If the folder already exists in Cloud Shell, update it before deploying:

```bash
cd ~/Wisdom
git pull --ff-only
```

## 3. Upload the project and prepare the VM

Use the VM's actual name and zone. The suggested values here are
`sdv-cyber-scanner` and `us-central1-a`:

```bash
bash config/deploy_compute_engine.sh \
  YOUR_PROJECT_ID \
  us-central1-a \
  sdv-cyber-scanner
```

The script enables Compute Engine and IAP APIs, configures a public firewall
rule only for Caddy's TCP 80/443 and UDP 443 listeners, configures SSH through
IAP, adds the required network tags to the VM, uploads the source, installs
Docker Compose, and creates simulator-only credentials on the VM. The web
firewall is public because teammates need to reach the HTTPS site; dashboard
requests still require the Basic Auth credentials configured in the next
step. Port 3000 and internal API ports are not opened on the public interface.

If the VM is on a custom VPC instead of the default VPC, stop before running
the script: the current script creates its firewall rules on the `default`
network and needs adapting to your network.

## 4. Configure the hostname and password privately

First make sure the DuckDNS A record resolves to the VM's static IP. Then
connect from Cloud Shell using IAP:

```bash
gcloud compute ssh sdv-cyber-scanner \
  --zone=us-central1-a \
  --tunnel-through-iap
```

In the VM shell, run:

```bash
cd ~/aegisdrive
sudo bash config/setup_dashboard_auth.sh
```

The script prompts for the hostname, username, and password. Enter the
hostname exactly as configured in DuckDNS. The password is entered into a
hidden prompt; the script stores only its bcrypt hash in the VM's
mode-600, Git-ignored `.env` file. Choose a unique password and share it with
Cup teammates through a separate private channel. Do not send it to this chat,
put it in Cloud Shell command arguments, or commit it.

The script validates the Compose and Caddy configuration, then builds and
starts the stack with the `public-dashboard` profile. Caddy obtains and renews
the HTTPS certificate automatically. Allow a short time for certificate
issuance.

## 5. Verify the deployment

On the VM:

```bash
cd ~/aegisdrive
sudo docker compose --profile public-dashboard ps
sudo docker compose --profile public-dashboard logs --tail=100 caddy
```

Open `https://aegisdrive-automotive.duckdns.org` in a private/incognito
browser window. Confirm that:

1. The browser shows a valid HTTPS certificate.
2. The dashboard requests the configured username and password.
3. A wrong password is rejected.
4. The dashboard loads after successful authentication.

Do not share an HTTP URL, VM IP, DuckDNS token, or password in a public Cup
submission. The team can use the HTTPS hostname and credentials without
installing the project locally.

## Operations

Run from Cloud Shell:

```bash
# Connect to the VM through IAP
gcloud compute ssh sdv-cyber-scanner \
  --zone=us-central1-a \
  --tunnel-through-iap
```

Then on the VM:

```bash
cd ~/aegisdrive
sudo docker compose --profile public-dashboard ps
sudo docker compose --profile public-dashboard logs --tail=100
sudo docker compose --profile public-dashboard down
sudo docker compose --profile public-dashboard up -d
```

Stop the VM when not being demoed to reduce compute charges:

```bash
gcloud compute instances stop sdv-cyber-scanner --zone=us-central1-a
```

The HTTPS link will be unavailable while the VM is stopped. Its boot disk and
reserved static IP may still incur charges.

To delete the VM and firewall rules after the demo (destructive; review before
running):

```bash
gcloud compute instances delete sdv-cyber-scanner --zone=us-central1-a
gcloud compute firewall-rules delete aegisdrive-frontend aegisdrive-iap-ssh
```

Also release the reserved static IP if it is no longer needed.

## Security and scope

- This is a simulator-only demonstration; it does not assess a physical
  vehicle.
- Caddy provides HTTPS and shared Basic Auth protection. Shared credentials
  are convenient for a prototype but do not provide per-user identity or
  revocation; rotate the password after the event.
- Use IAP SSH. The `aegisdrive-iap-ssh` rule only permits TCP 22 from Google's
  IAP TCP-forwarding range. Do not add a public `0.0.0.0/0` SSH rule.
- The app's HTTP/API listeners bind to VM loopback; the vehicle sockets remain
  Compose-private. Only ports 80/443 are intended for public dashboard access.
- Simulator HMAC authenticates socket messages but does not encrypt them.
- Local development certificates and secrets are generated on the VM and are
  not production secrets. The deployment is not hardened for real vehicle
  data, production workloads, regulatory compliance, or security
  certification.
