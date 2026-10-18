# Vehicle Network Simulator

The active simulator deployment uses the SDV zonal topology in `docker-compose.yml`. Each of the 15 ECU, ZCU, and HPC nodes runs in its own container and owns its live node state, protocol handling, security decisions, and authenticated TCP socket. The node implementations are under `ecus/`; `ecus/hpc_vehicle_node.py` contains shared node-side behavior used by the relevant HPC/ZCU classes.

## Socket responsibilities

- Each `vehicle-node-{node_id}` container listens on authenticated newline-framed JSON TCP port `6001` inside its isolated container. Its node instance handles requests addressed to it and routes applicable UDS/SOVD requests to child node sockets.
- ZCU and HPC containers listen on port `6003` for authenticated CAN/CAN-FD frame envelopes. Non-safety local ECUs use their owning ZCU; safety-critical ECUs use their directly connected HPC. Frames include CAN ID, DLC, and data bytes; routed UDS traffic is represented as ISO-TP-style CAN frames with request/response IDs and length.
- ZCU-HPC traffic uses a dedicated authenticated TCP link on port `6004` at both controller ends, carrying SOME/IP relays and HPC-to-ZCU diagnostic requests. HPC containers also expose a separate Cloud-HPC service socket on port `6005`.
- `vehicle-network` listens on port `6001` as the separate aggregate socket. It supplies full-network snapshots and aggregate read/diagnostic data; in deployed routing mode it rejects target-specific service actions rather than processing them against shadow nodes.
- Central compute routes target-specific UDS, OTA, SOME/IP, and SOVD requests directly to the owning node socket. It uses the aggregate socket for network snapshots and aggregated data.
- The node and aggregate containers use the same configured `VEHICLE_SOCKET_SECRET` for HMAC-SHA256 envelope authentication. The secret must be configured outside source control and be at least 32 characters. HMAC provides integrity/authentication, not encryption.

The node set consists of eight ECUs, four ZCUs, and three HPCs. Compose exposes ports `6001`, `6003`, and `6004` for controller containers, plus port `6005` for HPC containers; health checks verify each applicable listener before central compute starts. The dashboard shows four logical socket groups: ZCU CAN, HPC CAN, HPC-ZCU TCP, and Cloud-HPC TCP.

## Monitoring

The dashboard's **Network sockets** cards show the four monitored paths: ZCU CAN, HPC CAN, HPC-ZCU TCP, and Cloud-HPC TCP. The live activity log shows accepted/dropped frames, CAN ID, DLC, payload hex, UDS segmentation and total message length, SOME/IP service/method and packet length, scan phase, and rejection reason. Socket events are tagged with attack/diagnostic phase and can be filtered by any of these four links.

The bounded protocol probes submit malformed/replayed/out-of-range CAN messages through the controller CAN sockets, where node-side validation records whether they were accepted or dropped. Timed authorized tests send bounded protocol-shaped frames or diagnostic/firmware probes through the selected simulator handlers and record accepted/dropped outcomes. These are simulator TCP sockets, not physical CAN interfaces; no traffic is sent to a real vehicle.

## Simulation and testing

Networking, diagnostics, and firmware updates are simulated. The simulator does not communicate with physical ECUs or vehicle buses, and OTA is not hardware flashing. The simulated UDS download sequence can include `0x10`, `0x27`, `0x34`, `0x36`, and `0x37`; it represents protocol activity, not a real firmware transfer.

The vehicle service state starts as `out_of_service` (or can be set with `VEHICLE_SERVICE_STATE`). Authorized security tests require `in_service`. Probe suites exercise simulated protocol handlers and return aggregate scan results; the general `inject_frames` action remains disabled.

The bounded flooding scenario supports every registered ECU, ZCU, and HPC.
Explicit target IDs limit execution to those nodes; the default flooding
scenario covers all nodes. All assessment modes permit flooding, with
Service-center safe retaining its medium-severity ceiling and separate DoS
restriction. Node-side protections remain enabled: drops and security events
are valid resilience-test effects, not a reason to bypass those protections.
