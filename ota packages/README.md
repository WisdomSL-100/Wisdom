# Simulator OTA package sets

These package files are for the simulated ECUs, ZCUs, and HPCs in
`vehicle-network_Simulator/ecus/`. They contain small synthetic firmware image
bytes, node-specific manifests, and signatures in the simulator's development
format. They are **not** deployable firmware and must never be used with a
physical vehicle or production ECU.

## Package sets

- `BaselineSecure Packages/` contains one package per node. Its OTA software
  profile enables every supported security control. Its package name starts
  with `BASELINE`.
- `Attack Prone Packages/<control>/` contains one package per node for each
  supported security control. Only the named control is disabled in each
  profile; all other supported controls remain enabled. Apply these only in
  the isolated simulator, then run a simulator attack or diagnostic to observe
  the resulting node behavior and security events. Package names start with
  the related weakness ID (`W1`–`W10`) followed by a concise weakness
  description and target node, making them recognizable in the dashboard.

The 13 profile controls are `security_access_required`,
`message_authentication`, `replay_protection`, `freshness_protection`,
`rate_limiting`, `timing_validation`, `range_validation`,
`message_id_validation`, `diagnostic_access_control`, `zonal_segmentation`,
`firmware_signature_required`, `anti_downgrade`, and `ids_logging`.

Each package is a JSON object accepted by the simulator's OTA `package` field.
It includes the node's target ID, an allowed HPC source, the ZCU route where
required, a synthetic `image_hex`, and a manifest containing the exact
software profile and a node-specific simulator signature.

## Generate and verify

Run from PowerShell with the project's Python interpreter:

```powershell
& 'C:\work\workspace\.venv\Scripts\python.exe' `
  '.\ota packages\generate_packages.py'
```

To verify existing packages without rewriting them:

```powershell
& 'C:\work\workspace\.venv\Scripts\python.exe' `
  '.\ota packages\generate_packages.py' --check
```

The deterministic signatures use keys derived from public simulator source
code (`firmware-signature:<node-id>`). This is deliberately a development
mechanism, not cryptographic key management or a production trust anchor.

## Dashboard assurance workflow

The frontend exposes all JSON packages through its generated OTA package
catalog. Select either a secure baseline package or an attack-prone package,
flash it in the simulator, and review the OTA assurance result before running
an attack scan. Assurance checks include:

- package hash and simulator signature verification;
- a signed simulator OEM baseline containing required security controls;
- firmware version and downgrade direction;
- security-profile drift and explainable findings; and
- optional SBOM/CVE summary metadata when included in a package.

The package catalog and all flashes remain simulator-only. `service_center_safe`
scan mode allows bounded flooding, blocks the separate DoS scenario, and limits severity to medium;
`oem_validation` and `lab_penetration_test` are separate bounded simulator
policies. These results are not evidence of production hardware security.
