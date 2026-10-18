# Automotive Cybersecurity Scanner Handoff

Workspace: `C:\work\workspace\automotive-cybersecurity-scanner` (Windows). Existing Python environment: `C:\work\workspace\.venv\Scripts\python.exe`.

## Architecture

- `docker-compose.yml` defines eight ECU, four ZCU, and three HPC node services. Each `vehicle-node-{node_id}` container runs only the node selected by `VEHICLE_NODE_ID` and owns that node's state, protocol/service dispatch, and authenticated TCP socket on container port `6001`.
- ZCU and HPC containers also listen on port `6003` for authenticated CAN/CAN-FD frame envelopes. Non-safety local ECUs use their ZCU; safety-critical ECUs connect directly to their HPC. Frame events expose CAN ID, DLC, byte payload, and, for UDS, ISO-TP-style frame sequence and total message length.
- ZCU-HPC traffic uses a dedicated authenticated TCP listener on port `6004` at both controller ends; Cloud/central-compute requests to HPC use a separate authenticated HPC listener on port `6005`. The dashboard has four logical socket views: ZCU CAN, HPC CAN, HPC-ZCU TCP, and Cloud-HPC TCP.
- The separate `vehicle-network` container provides the aggregate snapshot socket on port `6001`. In deployed routing mode it does not accept node-specific UDS, OTA, SOME/IP, or SOVD service actions.
- Central compute routes target-specific UDS, OTA, SOME/IP, and SOVD requests directly to the responsible node socket. It uses the aggregate socket for full-network snapshots and aggregated data.
- ECU, ZCU, and HPC protocol behavior is implemented on the node side; `vehicle-network_Simulator/ecus/hpc_vehicle_node.py` includes shared node-side mixin behavior. Do not add another common protocol-service module.
- `vehicle-central-compute/scanner/hpc_vehicle_model.py` is a standalone companion model, not the live vehicle HPC instance.
- All network and OTA behavior is simulated. Do not describe this as physical CAN communication or hardware flashing. SOVD support is a simulated subset, not full ISO 17978 conformance.

## Central-compute behavior and data handling

- The dashboard selects bounded scan duration (1-60 seconds); scans require vehicle service state `in_service`.
- Scans collect before/after diagnostics and behavior analysis and report aggregate analytics. Raw node, signal, event, and network snapshots must not be forwarded or exposed in cloud scan history.
- `POST /signals/read` accepts `target_node_id`, `signal_name`, and an optional `requester_node_id`; the request is routed to the target node for SOME/IP signal handling.
- `POST /sovd/v1/diagnostics` sends supported diagnostic operations as target-specific node requests.
- Simulated OTA can produce UDS `0x10`, `0x27`, `0x34`, `0x36`, and `0x37` messages. These frames represent simulated activity only.
- `GET /architecture` on central compute provides the module and socket map.
- `vehicle-network/` is a legacy copy; deployment and integration tests use `vehicle-network_Simulator/`.

## Verification

Run from the project root:

```powershell
C:\work\workspace\.venv\Scripts\python.exe -m unittest discover -s tests -p "test_vehicle_network_*.py"
```

Socket tests cover direct and zonal routing, node-owned UDS/OTA/SOME/IP/SOVD handling, IDS behavior, and scan-state gating in the local simulator configuration.

## Known validation limits / next work

- Docker is unavailable in the current environment; Compose startup and real container-to-container communication have not been verified here.
- Re-run the complete vehicle-network test suite after changes to per-node routing.
- The dashboard's Network sockets view now shows controller CAN/TCP endpoints and live frame/probe activity, including scan phase, CAN ID, DLC, payload bytes, and rejection reasons.
- The bounded CAN protocol probes use controller-owned CAN sockets in deployed routing mode. The timed authorized attack scenario is still explicitly marker-only and does not send an attack payload; do not present it as a CAN/TCP injection.
- Confirm aggregate snapshots include all live node diagnostics, messages, security events, and OTA state.
- Docker is unavailable in the current environment, so the new multi-container listeners and Compose health checks remain unverified in real containers.
