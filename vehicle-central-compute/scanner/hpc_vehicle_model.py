"""Standalone central-compute companion model for simulated vehicle-HPC behavior.

The active in-vehicle hpc-vehicle node is registered from
vehicle-network_Simulator/ecus/hpc_vehicle_node.py. This copy is not a second
node in the simulator topology.
"""

import copy
import hashlib
import hmac
import json
import secrets


class VehicleHPC:
    def __init__(self):
        self._message_next_due = {}
        self._message_sequence = 0
        self._message_history = []
        self._uds_state = {}
        self._zcu_message_history = []
        self._direct_can_message_history = []
        self._hpc_peer_message_history = []

    def receive_zcu_messages(self, zcu_id, messages):
        if zcu_id not in self.ZCU_MESSAGE_SOURCES:
            raise ValueError("unregistered ZCU source")
        if not isinstance(messages, list) or not messages:
            raise ValueError("ZCU message batch must not be empty")
        for message in messages:
            if not isinstance(message, dict):
                raise ValueError("ZCU message batch contains an invalid message")
            received = copy.deepcopy(message)
            received["relayed_by_zcu_id"] = zcu_id
            received["received_by_hpc_id"] = self.NODE_ID
            self._zcu_message_history.append(received)
        self._zcu_message_history = self._zcu_message_history[-2000:]
        return len(messages)

    def aggregated_zcu_messages(self, limit=500):
        messages = self._zcu_message_history + self._direct_can_message_history + self._hpc_peer_message_history
        messages.sort(key=lambda message: message.get("sampled_at_monotonic_ms", 0))
        return copy.deepcopy(messages[-limit:])

    def receive_direct_can_messages(self, messages):
        self._direct_can_message_history.extend(copy.deepcopy(messages))
        self._direct_can_message_history = self._direct_can_message_history[-2000:]
        return len(messages)

    def receive_hpc_peer_messages(self, hpc_id, messages):
        if hpc_id not in {"hpc-adas", "hpc-cockpit"}:
            raise ValueError("unregistered HPC backbone source")
        received = copy.deepcopy(messages)
        for message in received:
            message["relayed_by_hpc_id"] = hpc_id
            message["received_by_hpc_id"] = self.NODE_ID
        self._hpc_peer_message_history.extend(received)
        self._hpc_peer_message_history = self._hpc_peer_message_history[-2000:]
        return len(received)

    def handle_sovd_request(self, request, nodes, transport):
        operation = str(request.get("operation", "readDataByIdentifier")).lower().replace("-", "_")
        if operation in {"read_did", "read_data_by_identifier", "read_diagnostic_data", "readdatabyidentifier", "readdiagnosticdata"}:
            raw_did = request.get("data_id", request.get("did"))
            try:
                did = int(raw_did, 16) if isinstance(raw_did, str) and not raw_did.lower().startswith("0x") else int(raw_did, 0) if isinstance(raw_did, str) else raw_did
            except (TypeError, ValueError) as exc:
                raise ValueError("data_id must be a 16-bit DID") from exc
            if type(did) is not int or not 0 <= did <= 0xFFFF:
                raise ValueError("data_id must be a 16-bit DID")
            uds_request = [0x22, did >> 8, did & 0xFF]
            operation_result = {"operation": "read_data_by_identifier", "data_id": f"0x{did:04X}"}
        elif operation in {"read_dtcs", "read_dtc_information", "readdtcinformation"}:
            uds_request = [0x19, 0x01]
            operation_result = {"operation": "read_dtc_information"}
        elif operation in {"tester_present", "keep_alive"}:
            uds_request = [0x3E, 0x00]
            operation_result = {"operation": "tester_present"}
        else:
            raise ValueError("unsupported VehicleHPC SOVD operation")

        component_id = request.get("component_id")
        target = nodes.get(component_id)
        if target is None:
            raise ValueError("component_id is not registered")
        route = [self.NODE_ID]
        transports = []
        doip_packets = None
        if target.NODE_ID == self.NODE_ID:
            uds_result = self.handle_uds_request(uds_request, request.get("context"))
            transports.append("local UDS")
        elif getattr(target, "ROLE", "") == "hpc":
            peer_result = transport["peer_sovd"](self.NODE_ID, target.NODE_ID, request)
            peer_result["routing"]["path"].insert(0, self.NODE_ID)
            peer_result["routing"]["transports"].insert(0, "SOME/IP over Automotive Ethernet")
            return peer_result
        elif getattr(target, "ROLE", "") == "zone_controller":
            doip_result = transport["doip"](self.NODE_ID, target.NODE_ID, target.NODE_ID, uds_request, request.get("context"))
            uds_result = doip_result["uds_result"]
            doip_packets = {"request": doip_result["doip_request_packet_hex"], "response": doip_result["doip_response_packet_hex"]}
            route.append(target.NODE_ID)
            transports.append("DoIP over Automotive Ethernet")
        elif getattr(target, "ROLE", "ecu") == "ecu":
            parent_id = target.CONNECTED_TO
            if target.SAFETY_CRITICAL and parent_id == self.NODE_ID:
                uds_result = transport["can_uds"](self.NODE_ID, target.NODE_ID, uds_request, request.get("context"))["uds_result"]
                route.append(target.NODE_ID)
                transports.append(target.PROTOCOL)
            elif target.SAFETY_CRITICAL:
                peer_result = transport["peer_sovd"](self.NODE_ID, parent_id, request)
                peer_result["routing"]["path"].insert(0, self.NODE_ID)
                peer_result["routing"]["transports"].insert(0, "SOME/IP over Automotive Ethernet")
                return peer_result
            else:
                zcu_id = self.ZCU_ROUTES.get(target.NODE_ID)
                if zcu_id is None:
                    raise ValueError("VehicleHPC has no configured ZCU route for this ECU")
                doip_result = transport["doip"](self.NODE_ID, zcu_id, target.NODE_ID, uds_request, request.get("context"))
                uds_result = doip_result["uds_result"]
                doip_packets = {"request": doip_result["doip_request_packet_hex"], "response": doip_result["doip_response_packet_hex"]}
                route.extend([zcu_id, target.NODE_ID])
                transports.extend(["DoIP over Automotive Ethernet", target.PROTOCOL])
        else:
            raise ValueError("VehicleHPC does not serve this SOVD component")
        return {"status": "completed" if uds_result.get("positive_response") else "rejected", "vehicle_id": request.get("vehicle_id", "simulated-vehicle"), "component_id": target.NODE_ID, **operation_result, "result": uds_result, "routing": {"path": route, "transports": transports}, "doip_packets": doip_packets, "simulated": True}

    def emit_due_messages(self, now_ms, secret):
        emitted = []
        recipients = self.CONNECTED_TO if isinstance(self.CONNECTED_TO, list) else ([self.CONNECTED_TO] if self.CONNECTED_TO else [])
        recipients = sorted(set(recipients + list(getattr(self, "BACKBONE_PEERS", []))))
        for index, (message_name, cycle_time_ms) in enumerate(self.MESSAGE_DEFINITIONS):
            if now_ms < self._message_next_due.get(index, 0):
                continue
            self._message_sequence += 1
            message = {"source_node_id": self.NODE_ID, "recipient_node_ids": recipients, "zone": getattr(self, "ZONE", "central"), "role": self.ROLE, "functional_domain": self.FUNCTIONAL_DOMAIN, "protocol": self.PROTOCOL, "network_segment": self.NETWORK_SEGMENT, "message_id": f"0x{int(self.MESSAGE_ID, 16) + index:03X}", "message_name": message_name, "cycle_time_ms": cycle_time_ms, "sequence": self._message_sequence, "sampled_at_monotonic_ms": round(now_ms, 3), "signals": copy.deepcopy(self.SIGNALS), "simulated": True}
            key = hmac.new(secret, b"node-message:" + self.NODE_ID.encode(), hashlib.sha256).digest()
            message["auth_tag"] = hmac.new(key, json.dumps(message, sort_keys=True, separators=(",", ":")).encode(), hashlib.sha256).hexdigest()
            self._message_next_due[index] = now_ms + cycle_time_ms
            emitted.append(message)
        self._message_history.extend(emitted)
        self._message_history = self._message_history[-200:]
        return emitted


        return {"node_id": self.NODE_ID, "functional_domain": self.FUNCTIONAL_DOMAIN, "protocol": self.PROTOCOL, "messages_sent": self._message_sequence, "recent_messages": copy.deepcopy(self._message_history[-10:]), "uds_session": self._uds_state.get("session", 0x01), "security_unlocked": self._uds_state.get("unlocked", False), "active_dtcs": list(self._uds_state.get("dtcs", {}).values()), "firmware": self._uds_state.get("firmware", {"version": "SIM-1.0", "simulated": True})}


    def diagnostics(self):
        return {
            "node_id": self.NODE_ID,
            "functional_domain": getattr(self, "FUNCTIONAL_DOMAIN", "vehicle_control"),
            "protocol": getattr(self, "PROTOCOL", "Automotive Ethernet"),
            "messages_sent": self._message_sequence,
            "recent_messages": list(self._message_history[-10:]),
            "uds_session": self._uds_state.get("session", 0x01),
            "security_unlocked": self._uds_state.get("unlocked", False),
            "active_dtcs": list(self._uds_state.get("dtcs", {}).values()),
            "firmware": self._uds_state.get("firmware", {"version": "SIM-1.0", "simulated": True}),
        }

    def handle_signal_request(self, signal_name, aggregated_messages=None):
        normalize = lambda value: "".join(character for character in str(value).lower() if character.isalnum())
        expected = normalize(signal_name)
        messages = list(getattr(self, "_received_message_history", [])) + list(aggregated_messages or [])
        messages.extend(self.aggregated_zcu_messages())
        messages.sort(key=lambda message: message.get("sampled_at_monotonic_ms", 0))
        for message in reversed(messages):
            layout = message.get("signal_layout", {})
            if expected in {normalize(layout.get("source_signal", "")), normalize(layout.get("name", "")), normalize(message.get("message_name", ""))}:
                return {"signal_name": layout["source_signal"], "value": layout["value"], "minimum": layout["minimum"], "maximum": layout["maximum"], "unit": layout.get("unit", "raw"), "cycle_time_ms": message["cycle_time_ms"], "source_node_id": message["source_node_id"], "message_name": message["message_name"], "message_id": message["message_id"], "sampled_at_monotonic_ms": message.get("sampled_at_monotonic_ms")}
        for name, value in self.SIGNALS.items():
            if normalize(name) == expected:
                minimum, maximum = self.SIGNAL_RANGES.get(name, [0, 255])
                return {"signal_name": name, "value": value, "minimum": minimum, "maximum": maximum, "unit": "raw", "cycle_time_ms": self.CYCLE_TIME_MS, "source_node_id": self.NODE_ID, "message_name": self.MESSAGE_NAME, "message_id": self.MESSAGE_ID}
        return None

    def _legacy_handle_sovd_request(self, request, nodes, transport):
        operation = str(request.get("operation", "readDataByIdentifier")).lower().replace("-", "_")
        if operation in {"read_did", "read_data_by_identifier", "read_diagnostic_data", "readdatabyidentifier", "readdiagnosticdata"}:
            raw_did = request.get("data_id", request.get("did"))
            try:
                did = int(raw_did, 16) if isinstance(raw_did, str) and not raw_did.lower().startswith("0x") else int(raw_did, 0) if isinstance(raw_did, str) else raw_did
            except (TypeError, ValueError) as exc:
                raise ValueError("data_id must be a 16-bit DID") from exc
            if type(did) is not int or not 0 <= did <= 0xFFFF:
                raise ValueError("data_id must be a 16-bit DID")
            request_bytes = [0x22, did >> 8, did & 0xFF]
            operation_data = {"operation": "read_data_by_identifier", "data_id": f"0x{did:04X}"}
        elif operation in {"read_dtcs", "read_dtc_information", "readdtcinformation"}:
            request_bytes = [0x19, 0x01]
            operation_data = {"operation": "read_dtc_information"}
        elif operation in {"tester_present", "keep_alive"}:
            request_bytes = [0x3E, 0x00]
            operation_data = {"operation": "tester_present"}
        else:
            raise ValueError("unsupported SOVD diagnostic operation")

        component_id = request.get("component_id")
        target = nodes.get(component_id)
        if target is None:
            raise ValueError("component_id is not registered")
        route = [self.NODE_ID]
        transports = []
        if target.NODE_ID == self.NODE_ID:
            uds_result = self.handle_uds_request(request_bytes, request.get("context"))
            transports.append("local UDS")
        elif getattr(target, "ROLE", "") == "hpc":
            peer_response = transport["peer_sovd"](self.NODE_ID, target.NODE_ID, request)
            return peer_response
        elif getattr(target, "ROLE", "") == "zone_controller":
            doip_result = transport["doip"](self.NODE_ID, target.NODE_ID, target.NODE_ID, request_bytes, request.get("context"))
            uds_result = doip_result["uds_result"]
            route.append(target.NODE_ID)
            transports.append("DoIP over Automotive Ethernet")
        elif getattr(target, "ROLE", "ecu") == "ecu":
            parent_id = target.CONNECTED_TO
            if target.SAFETY_CRITICAL and parent_id == self.NODE_ID:
                can_result = transport["can_uds"](self.NODE_ID, target.NODE_ID, request_bytes, request.get("context"))
                uds_result = can_result["uds_result"]
                route.append(target.NODE_ID)
                transports.append("UDS over CAN/CAN-FD")
            elif target.SAFETY_CRITICAL:
                return transport["peer_sovd"](self.NODE_ID, parent_id, request)
            else:
                zcu_id = self.ZCU_ROUTES.get(target.NODE_ID)
                if zcu_id is None:
                    raise ValueError("no vehicle-HPC route is configured for this ECU")
                doip_result = transport["doip"](self.NODE_ID, zcu_id, target.NODE_ID, request_bytes, request.get("context"))
                uds_result = doip_result["uds_result"]
                route.extend([zcu_id, target.NODE_ID])
                transports.extend(["DoIP over Automotive Ethernet", target.PROTOCOL])
        else:
            raise ValueError("unsupported SOVD target role")

        return {
            "status": "completed" if uds_result.get("positive_response") else "rejected",
            "vehicle_id": request.get("vehicle_id", "simulated-vehicle"),
            "component_id": target.NODE_ID,
            **operation_data,
            "result": uds_result,
            "routing": {"path": route, "transports": transports},
            "simulated": True,
        }

    def handle_uds_request(self, request_bytes, context=None):
        if isinstance(request_bytes, (bytes, bytearray)):
            request_bytes = list(request_bytes)
        if not isinstance(request_bytes, list) or not request_bytes or any(type(value) is not int or not 0 <= value <= 255 for value in request_bytes):
            raise ValueError("request_bytes must be a non-empty byte array")
        req = list(request_bytes)
        sid = req[0]
        context = context if isinstance(context, dict) else {}
        state = self._uds_state
        state.setdefault("session", 0x01)
        state.setdefault("unlocked", False)
        state.setdefault("seed", None)
        state.setdefault("security_failures", 0)
        state.setdefault("dtcs", {})
        state.setdefault("dtc_enabled", True)
        state.setdefault("communication_enabled", True)
        state.setdefault("routines", {})
        state.setdefault("flash", None)
        state.setdefault("firmware", {"version": "SIM-1.0", "simulated": True})
        names = {0x10: "DiagnosticSessionControl", 0x11: "ECUReset", 0x14: "ClearDiagnosticInformation", 0x19: "ReadDTCInformation", 0x22: "ReadDataByIdentifier", 0x27: "SecurityAccess", 0x28: "CommunicationControl", 0x31: "RoutineControl", 0x34: "RequestDownload", 0x36: "TransferData", 0x37: "RequestTransferExit", 0x3E: "TesterPresent", 0x85: "ControlDTCSetting"}
        service = names.get(sid, "Unknown")

        def reply(data, **extra):
            response = bytes(data)
            return {"ecu_id": self.NODE_ID, "service": f"0x{sid:02X}", "service_name": service, "positive_response": True, "request_bytes": req, "response_bytes": list(response), "response_hex": response.hex(" ").upper(), **extra}

        def reject(nrc):
            response = bytes([0x7F, sid, nrc])
            return {"ecu_id": self.NODE_ID, "service": f"0x{sid:02X}", "service_name": service, "positive_response": False, "request_bytes": req, "response_bytes": list(response), "response_hex": response.hex(" ").upper(), "nrc": f"0x{nrc:02X}"}

        def protected():
            return state["session"] != 0x03 or not state["unlocked"]

        if f"0x{sid:02X}" not in getattr(self, "UDS_SUPPORTED_SERVICES", []):
            return reject(0x11)
        if sid == 0x10:
            if len(req) != 2: return reject(0x13)
            sub = req[1] & 0x7F
            if sub not in (1, 2, 3): return reject(0x12)
            state["session"] = sub
            if sub == 1:
                state["unlocked"] = False
                state["seed"] = None
                state["flash"] = None
            return reply([0x50, req[1], 0, 0x32, 1, 0xF4], session=sub)
        if sid == 0x11:
            if len(req) != 2: return reject(0x13)
            if req[1] & 0x7F not in (1, 3): return reject(0x12)
            state.update(session=1, unlocked=False, seed=None, flash=None)
            return reply([0x51, req[1]], simulated_reset=True)
        if sid == 0x14:
            if len(req) != 4: return reject(0x13)
            if protected(): return reject(0x33)
            group = int.from_bytes(req[1:4], "big")
            if group not in (0, 0xFFFFFF): return reject(0x31)
            state["dtcs"].clear()
            return reply([0x54], cleared=True)
        if sid == 0x19:
            if len(req) < 2: return reject(0x13)
            sub = req[1] & 0x7F
            records = []
            for code, description in getattr(self, "DTC_CATALOG", {}).items():
                item = state["dtcs"].get(code, {})
                records.append({"code": code, "description": description, "status_byte": item.get("status_byte", 0), "active": code in state["dtcs"]})
            if sub == 1 and len(req) == 2: mask = 0xFF; selected = records
            elif sub == 2 and len(req) == 3:
                mask = req[2]; selected = [item for item in records if item["status_byte"] & mask]
            elif sub == 0x0A and len(req) == 2: return reply([0x59, req[1], 1], dtc_count=len(records))
            else: return reject(0x12 if sub not in (1, 2, 0x0A) else 0x13)
            data = bytearray([0x59, req[1], mask, len(selected)])
            for item in selected: data.extend(bytes.fromhex(item["code"][2:]) + bytes([item["status_byte"]]))
            return reply(data, dtcs=selected)
        if sid == 0x22:
            if len(req) < 3 or len(req) % 2 == 0: return reject(0x13)
            data = bytearray([0x62]); values = []
            for pos in range(1, len(req), 2):
                did = (req[pos] << 8) | req[pos + 1]; key = f"0x{did:04X}"
                name = getattr(self, "UDS_DIDS", {}).get(key)
                standard = {0xF180: self.NODE_ID, 0xF181: "SIM-1.0", 0xF183: "normal", 0xF184: json.dumps(state["dtcs"], sort_keys=True), 0xF185: getattr(self, "ROLE", "ecu"), 0xF186: getattr(self, "ZONE", "central"), 0xF187: self.PROTOCOL, 0xF188: json.dumps(state["firmware"], sort_keys=True), 0xF1A0: json.dumps(self.SIGNALS, sort_keys=True)}
                if name is None and did not in standard: return reject(0x31)
                value = str(standard.get(did, json.dumps({"name": name, "signals": self.SIGNALS, "firmware": state["firmware"]}, sort_keys=True)))
                data.extend(bytes(req[pos:pos + 2]) + value.encode("utf-8")); values.append({"did": key, "value": value})
            return reply(data, values=values)
        if sid == 0x27:
            if len(req) < 2: return reject(0x13)
            sub = req[1]
            if state["session"] != 3: return reject(0x7E)
            if sub in (1, 3) and len(req) == 2:
                if state["security_failures"] >= 3: return reject(0x36)
                seed = secrets.token_bytes(8); state["seed"] = {"value": seed.hex(), "level": sub}
                return reply([0x67, sub, *seed], seed=seed.hex())
            if sub in (2, 4) and len(req) == 10:
                saved = state.get("seed")
                if not saved or sub != saved["level"] + 1: return reject(0x24)
                seed = bytes.fromhex(saved["value"]); state["seed"] = None
                expected = hmac.new(("node-security:" + self.NODE_ID).encode(), seed, hashlib.sha256).digest()[:8]
                if not hmac.compare_digest(expected, bytes(req[2:])):
                    state["security_failures"] += 1; return reject(0x35)
                state.update(unlocked=True, security_failures=0)
                return reply([0x67, sub], security_unlocked=True)
            return reject(0x13 if sub in (2, 4) else 0x12)
        if sid == 0x28:
            if len(req) != 3: return reject(0x13)
            sub = req[1] & 0x7F
            if sub not in (0, 1, 2, 3): return reject(0x12)
            if protected(): return reject(0x33)
            state["communication_enabled"] = sub in (0, 3)
            return reply([0x68, req[1], req[2]], communication_enabled=state["communication_enabled"])
        if sid == 0x31:
            if len(req) < 4: return reject(0x13)
            sub = req[1] & 0x7F; rid = f"0x{req[2]:02X}{req[3]:02X}"
            name = getattr(self, "UDS_RIDS", {}).get(rid)
            if sub not in (1, 2, 3): return reject(0x12)
            if name is None: return reject(0x31)
            if protected(): return reject(0x33)
            default = {"name": name, "status": "requested", "result": "not_run", "simulated": True}
            result = state["routines"].setdefault(rid, default)
            if sub == 1: result.update(status="completed", result="pass")
            elif sub == 2: result.update(status="stopped", result="not_run")
            return reply([0x71, req[1], req[2], req[3], 0 if result["result"] == "pass" else 1], routine_id=rid, routine_name=name, routine_state=result)
        if sid == 0x34:
            if len(req) < 4: return reject(0x13)
            if protected(): return reject(0x33)
            manifest = context.get("manifest")
            if not isinstance(manifest, dict): return reject(0x13)
            version, size, digest, signature = (manifest.get(k) for k in ("version", "image_size", "sha256", "signature"))
            if manifest.get("ecu_id") != self.NODE_ID or not isinstance(version, str) or type(size) is not int or not 1 <= size <= 1048576 or not isinstance(digest, str) or len(digest) != 64 or not isinstance(signature, str): return reject(0x13)
            signed = json.dumps({"ecu_id": self.NODE_ID, "version": version, "image_size": size, "sha256": digest.lower()}, sort_keys=True, separators=(",", ":")).encode()
            expected = hmac.new(("firmware-signature:" + self.NODE_ID).encode(), signed, hashlib.sha256).hexdigest()
            if not hmac.compare_digest(expected, signature.lower()): return reject(0x35)
            transport = "can_local" if self.PROTOCOL in ("CAN", "CAN-FD") else "ethernet_ota"
            if context.get("transport") != transport: return reject(0x31)
            state["flash"] = {"manifest": dict(manifest), "transport": transport, "next": 1, "image": bytearray()}
            return reply([0x74, 0x20, 0x04, 0], transfer_ready=True, transport=transport)
        if sid == 0x36:
            if len(req) < 3: return reject(0x13)
            flash = state.get("flash")
            if protected() or flash is None: return reject(0x33)
            if req[1] != flash["next"] % 256: return reject(0x73)
            block = bytes(req[2:])
            if len(flash["image"]) + len(block) > flash["manifest"]["image_size"]: state["flash"] = None; return reject(0x71)
            flash["image"].extend(block); flash["next"] += 1
            return reply([0x76, req[1]], bytes_received=len(flash["image"]))
        if sid == 0x37:
            if len(req) != 1: return reject(0x13)
            flash = state.get("flash")
            if protected() or flash is None: return reject(0x33)
            image = bytes(flash["image"]); manifest = flash["manifest"]; digest = hashlib.sha256(image).hexdigest()
            if len(image) != manifest["image_size"] or not hmac.compare_digest(digest, manifest["sha256"].lower()): state["flash"] = None; return reject(0x72)
            state["firmware"] = {"version": manifest["version"], "sha256": digest, "transport": flash["transport"], "simulated": True}; state["flash"] = None
            return reply([0x77], firmware=state["firmware"], hardware_flash_performed=False)
        if sid == 0x3E:
            if len(req) != 2: return reject(0x13)
            if req[1] & 0x7F: return reject(0x12)
            data = [] if req[1] & 0x80 else [0x7E, req[1]]
            return reply(data, tester_present=True, suppressed=bool(req[1] & 0x80))
        if sid == 0x85:
            if len(req) != 2: return reject(0x13)
            sub = req[1] & 0x7F
            if sub not in (1, 2): return reject(0x12)
            if protected(): return reject(0x33)
            state["dtc_enabled"] = sub == 1
            return reply([0xC5, req[1]], dtc_enabled=state["dtc_enabled"])
        return reject(0x11)

    def _uds_negative_response(self, request, code, service_name):
        response = bytes([0x7F, request[0], code])
        return {"ecu_id": self.NODE_ID, "service": f"0x{request[0]:02X}", "service_name": service_name, "positive_response": False, "request_bytes": request, "response_bytes": list(response), "response_hex": response.hex(" ").upper(), "nrc": f"0x{code:02X}"}

    def perform_ota(self, package, node_instances=None):
        if not isinstance(package, dict) or package.get("target_ecu_id") != self.NODE_ID: raise ValueError("OTA package target does not match this node")
        source = package.get("source_hpc_id"); trusted = set(getattr(self, "TRUSTED_SOURCES", ()))
        direct = self.CONNECTED_TO if isinstance(self.CONNECTED_TO, (list, tuple, set)) else ([self.CONNECTED_TO] if self.CONNECTED_TO else [])
        if source not in trusted and source not in {"hpc-vehicle", "hpc-adas", "hpc-cockpit"} and source not in direct: raise PermissionError("source HPC is not trusted for this node")
        try: image = bytes.fromhex(package.get("image_hex", ""))
        except (TypeError, ValueError) as exc: raise ValueError("image_hex must contain valid hexadecimal bytes") from exc
        manifest = package.get("manifest")
        if not image or not isinstance(manifest, dict) or manifest.get("ecu_id") != self.NODE_ID or manifest.get("image_size") != len(image) or manifest.get("sha256") != hashlib.sha256(image).hexdigest(): raise ValueError("firmware image does not match its manifest")
        boot = self.handle_uds_request([0x10, 3]); seed = self.handle_uds_request([0x27, 1])
        key = hmac.new(("node-security:" + self.NODE_ID).encode(), bytes(seed["response_bytes"][2:]), hashlib.sha256).digest()[:8]
        unlock = self.handle_uds_request([0x27, 2, *key])
        if not boot.get("positive_response") or not seed.get("positive_response") or not unlock.get("positive_response"): raise PermissionError("node rejected UDS programming authorization")
        transport = "can_local" if self.PROTOCOL in ("CAN", "CAN-FD") else "ethernet_ota"
        results = [boot, seed, unlock, self.handle_uds_request([0x34, 0, 0, 0], {"manifest": manifest, "transport": transport})]
        if not results[-1].get("positive_response"): return {"status": "rejected", "route": {"source_hpc_id": source, "zcu_id": package.get("zcu_id"), "target_ecu_id": self.NODE_ID}, "uds_results": results, "hardware_flash_performed": False}
        for number, start in enumerate(range(0, len(image), 4), 1):
            result = self.handle_uds_request([0x36, number % 256, *image[start:start + 4]]); results.append(result)
            if not result.get("positive_response"): return {"status": "rejected", "route": {"source_hpc_id": source, "zcu_id": package.get("zcu_id"), "target_ecu_id": self.NODE_ID}, "uds_results": results, "hardware_flash_performed": False}
        exit_result = self.handle_uds_request([0x37]); results.append(exit_result)
        return {"status": "completed" if exit_result.get("positive_response") else "rejected", "route": {"source_hpc_id": source, "zcu_id": package.get("zcu_id"), "target_ecu_id": self.NODE_ID}, "hops": [{"source_hpc_id": source, "zcu_id": package.get("zcu_id"), "target_ecu_id": self.NODE_ID, "transport": "Ethernet socket"}, {"source_hpc_id": source, "zcu_id": package.get("zcu_id"), "target_ecu_id": self.NODE_ID, "transport": "UDS over CAN/CAN-FD" if transport == "can_local" else "UDS over Automotive Ethernet"}], "uds_results": results, "firmware": exit_result.get("firmware"), "hardware_flash_performed": False}

    UDS_DIDS = {"0xF1B0": "vehicle_aggregate_status", "0xF1B1": "vehicle_compute_load"}
    UDS_RIDS = {"0x0201": "vehicle_domain_self_test", "0x0202": "aggregate_integrity_check"}
    NODE_ID = "hpc-vehicle"
    DISPLAY_NAME = "Vehicle Dynamics HPC"
    ROLE = "hpc"
    FUNCTIONAL_DOMAIN = "vehicle_compute"
    PROTOCOL = "Automotive Ethernet SOME/IP"
    NETWORK_SEGMENT = "vehicle-backbone"
    CONNECTED_TO = None
    BACKBONE_PEERS = ["hpc-adas", "hpc-cockpit"]
    ZCU_MESSAGE_SOURCES = ("zcu-front-left", "zcu-front-right", "zcu-rear-left", "zcu-rear-right")
    AGGREGATES_FROM = [
        "zcu-front-left", "zcu-front-right", "zcu-rear-left", "zcu-rear-right",
        "ecu-powertrain", "ecu-battery", "ecu-adas-radar", "ecu-front-camera", "ecu-rear-camera",
    ]
    AGGREGATES_ZONES = ["front_left", "front_right", "rear_left", "rear_right"]
    TRUSTED_SOURCES = ("hpc-adas", "hpc-cockpit")
    ZCU_ROUTES = {"ecu-body-front": "zcu-front-right", "ecu-body-rear": "zcu-rear-left", "ecu-telematics": "zcu-rear-right"}
    DOIP_LOGICAL_ADDRESS = 0x2001
    MESSAGE_ID = "0x700"
    MESSAGE_NAME = "VehicleComputeHealth"
    CYCLE_TIME_MS = 50
    MESSAGE_DEFINITIONS = [("VehicleComputeHealth", 50), ("VehicleStateEstimate", 20), ("VehicleMotionCommand", 10), ("ChassisControlStatus", 20), ("DomainAggregationHealth", 100), ("ZoneRouteHealth", 100), ("CentralSafetyState", 50), ("ComputeResourceHealth", 100), ("VehicleDTCStatus", 500), ("VehicleSecurityStatus", 100), ("VehicleHPCHeartbeat", 1000)]
    SIGNALS = {"compute_state": "online", "cpu_load_pct": 24, "memory_load_pct": 38}
    SIGNAL_RANGES = {"cpu_load_pct": [0, 100], "memory_load_pct": [0, 100]}
    MAX_MESSAGE_RATE_HZ = 2000
    MAX_MESSAGE_COUNT = 256
    MAX_PAYLOAD_BYTES = 1500
    UDS_SUPPORTED_SERVICES = ["0x10", "0x11", "0x14", "0x19", "0x22", "0x27", "0x28", "0x31", "0x34", "0x36", "0x37", "0x3E", "0x85"]
    SECURE_FEATURES = ["authenticated_domain_messages", "integrity_validation", "replay_protection", "secure_diagnostics", "signed_firmware_policy", "resource_monitoring"]
    DTC_CATALOG = {"0xC20101": "Vehicle HPC overtemperature", "0xC20102": "Vehicle HPC overload", "0xC20103": "Domain message authentication failure", "0xC20104": "Firmware verification failure"}


VehicleHPC.SOMEIP_SERVICE_ID = 0x5200
VehicleHPC.CAN_CONTROL_BASE = 0x300
VehicleHPC.DOIP_LOGICAL_ADDRESS = 0x2001
VehicleHPC.ZCU_ROUTES = {"ecu-body-front": "zcu-front-right", "ecu-body-rear": "zcu-rear-left", "ecu-telematics": "zcu-rear-right"}
VehicleHPC.MESSAGE_DEFINITIONS.extend([(f"VehicleComputeServiceEvent{index:02d}", (20, 50, 100, 250, 500)[index % 5]) for index in range(11, 30)])
