# Prototype Performance and Benchmarking

## Slide-ready summary

> **End-to-end automotive cybersecurity assessment prototype validated in simulation:** 210 OTA packages, 15 modeled targets, and 2,100 package/attack scan combinations exercised with no failures recorded by the matrix run.

### Main pointers

| Area | Headline |
| --- | --- |
| End-to-end workflow | OTA package → simulated attack → analysis → report |
| Test scale | 210 packages · 15 modeled targets · 10 attack scenarios |
| Matrix volume | 2,100 package/attack scans · 225 flash/restore attempts |
| Matrix outcome | 0 failures recorded by this simulator matrix run |
| Performance benchmark | Initial local timings measured for one scan workflow and XLSX export; small simulator-only sample |
| Validation scope | Local simulation only; no real vehicle, hardware, or certification claim |

| Prototype measure | Result | What it demonstrates |
| --- | ---: | --- |
| Generated OTA packages exercised | 210 | Package handling across the generated secure-baseline and attack-prone package set |
| Modeled ECU, ZCU, and HPC targets | 15 | Coverage across the configured simulator target fleet |
| Package/attack scan combinations | 2,100 | All 210 packages exercised with the 10 supported attack scenarios |
| OTA flash attempts | 225 | Package flashes plus secure-baseline restoration attempts in the isolated test workers |
| Matrix-recorded failures | 0 | No flash, scan, or matrix assertion failures were recorded in this run |
| OTA weakness families represented | W1-W10 | Weakness evidence is associated with relevant checks; “covered” means a relevant test was run, not that an exploit succeeded |
| Execution environment | Local Docker-compatible Compose via Podman/WSL | Repeatable, local simulator-based validation |

## Benchmark status

| Claim area | Current evidence | Safe wording for the deck |
| --- | --- | --- |
| End-to-end orchestration | Implemented across the local prototype services and exercised by simulated scan workflows | “The prototype orchestrates OTA package handling, simulated attack execution, post-attack analysis, and report generation end to end.” |
| Functional scale test | The automated OTA matrix exercised 210 packages across 15 targets and 10 attack scenarios | “A 2,100-combination simulation matrix completed with zero recorded matrix failures.” |
| Performance benchmark | Three sequential completed scan runs and three XLSX exports measured locally; broader attack/baseline cases hit simulator socket/UDS failures | “Initial local prototype timings were measured for representative workflows; these are not production-grade latency or throughput claims.” |
| Production or hardware validation | Not established by the simulator matrix | “Results are from modeled simulator targets, not physical ECUs or an in-vehicle network.” |
| Certification or compliance | Not established by this prototype test | “This is prototype validation evidence, not certification, formal compliance evidence, or an OEM security case.” |

## Suggested slide content

### Prototype validation: broad simulated coverage, not production benchmarking

- **2,100** package/attack scan combinations exercised
- **210** generated OTA packages across **15** modeled ECU, ZCU, and HPC targets
- **10** supported attack scenarios; weaknesses represented across **W1-W10**
- **0** failures recorded by the automated OTA matrix
- Local, Docker-compatible Compose workflow using Podman in WSL
- End-to-end flow: OTA package → simulated attack → behavior/security analysis → findings and report

**Scope note:** These are functional test-volume results from the project’s simulator integration matrix. They are not runtime, latency, throughput, capacity, reliability-at-scale, or real-vehicle benchmark results. No real hardware was tested. “Zero failures” refers only to failures recorded by that matrix run and does not imply absence of vulnerabilities.

## Definitions and interpretation

- **Package/attack scan combination:** one generated OTA package exercised against one supported attack scenario for its modeled target.
- **OTA flash attempt:** an attempted package flash or secure-baseline restore performed by the isolated matrix worker. This is a test-operation count, not a flash-throughput measurement.
- **Weakness coverage:** the matrix checks that a relevant scenario was exercised for a weakness. It does not mean the attack succeeded, the weakness was exploited, or the weakness is absent when a test does not match.
- **Matrix-recorded failure:** a failure reported by the automated runner for a flash, scan, or matrix assertion. This is not a general availability or defect-rate metric.

## Benchmarking still needed

For a future performance benchmark, measure and publish results with a recorded machine/runtime configuration and repeatable workload:

1. Scan end-to-end latency, plus baseline, attack, post-attack analysis, and report-generation durations.
2. OTA flash duration by package size and target class.
3. Sustained scans per minute and concurrent-scan behavior.
4. CPU, memory, and network utilization under representative and peak workloads.
5. Repeated-run success rate, timeout rate, and latency percentiles (p50/p95/p99).

Until those measurements are collected under a documented protocol, do not describe the figures above as certified, production-grade, or hardware benchmark results.

## Initial local performance test

Three sequential samples were collected on the local stack on 2026-10-18. The browser measured request-to-response wall time with `performance.now()`. Scan samples were counted only when the returned scan record reported `scan_status=completed` and `test_execution_result=passed`. Percentiles use nearest rank; with only three samples, p95 is the maximum and is not a stable tail-latency estimate.

| Workflow | Workload and repetitions | Successful samples | Median (p50) | p95 (nearest rank) | Observed range |
| --- | --- | ---: | ---: | ---: | ---: |
| Simulated attack scan | `replay_attack`, low severity, 1-second duration, `lab_penetration_test`, baseline checks off; 3 sequential runs | 3/3 | 13.281 s end-to-end | 13.849 s end-to-end | 9.641–13.849 s |
| Attack execution window | Same three completed replay scans; internal `attack_summary.elapsed_seconds` | 3/3 | 1.000 s | 1.030 s | 1.000–1.030 s |
| XLSX report export | Five report rows; 3 sequential requests; all responses were HTTP 200 and valid XLSX/ZIP files (1,904 bytes each) | 3/3 | 0.0432 s | 0.1035 s | 0.0295–0.1035 s |

**Interpretation:** The measured scan wall time includes the local frontend-to-cloud-to-central-compute path, simulated execution, analysis, and response serialization; it is not just attack runtime. The scan summary reported analysis across 15 simulated nodes. XLSX timing measures the five-row export endpoint and response transfer, not spreadsheet opening or user download time.

**Environment:** Windows host with Ubuntu/WSL, Docker-compatible Compose backed by Podman; WSL reported 16 CPUs and 3.7 GiB total memory (1.8 GiB available in the pre-test snapshot). No controlled CPU, memory, or throughput profiling was performed during these runs.

**Unsuccessful comparison attempts:** The attempted `unauthorized_diagnostics` baseline-on/off runs and `invalid_firmware` baseline-on runs did not complete successfully and are excluded from the timing percentiles. Container logs recorded unavailable modeled node sockets (including `ecu-body-front`, `zcu-rear-left`, and `hpc-cockpit`) and a UDS probe that did not receive a valid response from `hpc-vehicle`. One additional replay scan with baseline checks enabled also failed on a UDS probe. These are simulator reliability findings to resolve before publishing baseline-on or broader attack-scenario performance comparisons; they are not evidence of slow completed scans.

The service state was `in_service` before and after testing. The stack was reachable at the end, although some background network-activity requests intermittently returned HTTP 503.

**Deck-safe wording:** “In a local simulator run, a 1-second replay scenario completed in 9.6–13.8 seconds end to end across three successful runs; the modeled attack window was about 1 second. A five-row XLSX report exported in 0.03–0.10 seconds across three runs. These early results are simulator-only, small-sample measurements; some other scan configurations were blocked by simulator socket/UDS failures.”

## Provenance

Counts above are taken from the project’s saved full OTA matrix result (`ota-matrix-full.json`) and its runner (`tests/run_ota_matrix.py`). The matrix uses isolated simulator test workers and restores a secure baseline after testing each target.
