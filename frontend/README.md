# Frontend Container

This container exposes the user interface and orchestration layer for attack configuration and live monitoring.

## Responsibilities

- launch attack scenarios
- show live vehicle status
- display alerts and security events
- visualize network telemetry
- summarize incident reports

## Typical stack

- Python + FastAPI
- optional React frontend in the future
- real-time dashboard support through WebSockets or polling

Each completed scan replaces the outcome cards, charts, and report. The
post-attack chart includes both installed OTA weakness target counts and new
observed security-event counts, so unchanged OTA posture does not hide a later
attack's events. These are observation counts, not a pass/fail percentage.
New event aggregates use simulator event identities rather than subtracting
rolling-window sizes; older saved scans retain the count-delta fallback.

Bounded simulator flooding is selectable for all ECU, ZCU, and HPC targets in
every assessment mode. Service-center safe still caps severity at medium and
blocks the separate `dos` scenario. Tests require the simulator to be in service,
last 1-60 seconds, and retain the Stop control.

Run dashboard JavaScript regression checks with
`node --test tests/test_dashboard_runtime.js` from the repository root.
