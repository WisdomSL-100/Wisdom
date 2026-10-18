# Cloud Application

This container orchestrates authorized simulator scans, retrieves aggregate evidence from Central Compute, encrypts privacy-filtered scan history at rest, and serves read-only scan/evidence APIs to the dashboard.

## Responsibilities
- Check the vehicle's service state before dispatching a scan; Central Compute independently enforces the same gate.
- Call Central Compute REST endpoints over HTTPS using the configured CA and cloud client certificate.
- Sign a short-lived HS256 JWT for each cloud-to-central request. Configure the same `CENTRAL_SERVICE_JWT_SECRET` (at least 32 bytes) in both services.
- Persist only allowlisted aggregate scan evidence, encrypted using `SCAN_HISTORY_ENCRYPTION_KEY`.
- Serve `/api/evidence/latest` and `/api/evidence/<scan_id>` for safe dashboard rendering; raw frames and per-node diagnostic payloads are excluded.
- Maintain a local CVE catalog at `/api/cves`, with operator JSON import at
  `/api/cves/import`, bounded NVD synchronization at `/api/cves/sync`, and
  SBOM component matching at `/api/cves/match`.
- Expose audience-specific reports through `/api/report/latest` and
  `/api/report/<scan_id>` using `owner`, `technician`, or `oem` audiences.
- Generate deterministic explanations from a bundled reference corpus, with
  optional Gemini text generation when `GEMINI_API_KEY` is configured.
- Preserve scan-local new-event aggregates in history and report evidence so
  repeated attacks remain visible when rolling event-window counts saturate.

Bounded simulator flooding is allowed in every assessment mode and for every
registered node. Service-center safe still caps severity at medium and blocks
the separate `dos` scenario. The cloud and Central Compute independently apply
the mode policy and in-service gate.

The CVE catalog is intentionally local and bounded for the simulator. NVD
synchronization requires outbound internet access and should be scheduled and
rate-limited by the production deployment rather than triggered continuously
from a browser.

Development mTLS certificates and service secrets are generated with `config/bootstrap_dev_security.sh`. These credentials are for local simulation only, not production use.
