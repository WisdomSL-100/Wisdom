import copy
import hashlib
import hmac
import json
import secrets
import struct
import time
import socket
import time
from uuid import uuid4
from collections import deque
import math
import re



class ZcuRearLeft:
    def __init__(self):
        self._message_next_due = {}
        self._message_sequence = 0
        self._message_history = []
        self._uds_state = {}
        self._ota_diagnostic_events = []

    def send_messages_to_hpc(self, messages, host, port, secret, hpc_messages=None):
        payload = {"request_id": uuid4().hex, "timestamp": int(time.time()), "action": "zcu_messages", "source_node_id": self.NODE_ID, "messages": messages, "hpc_messages": hpc_messages or []}
        payload["auth"] = hmac.new(secret, json.dumps(payload, sort_keys=True, separators=(",", ":")).encode(), hashlib.sha256).hexdigest()
        frame = json.dumps(payload).encode() + b"\n"
        try:
            with socket.create_connection((host, port), timeout=1) as connection:
                connection.settimeout(1)
                with connection.makefile("rwb") as stream:
                    stream.write(frame)
                    stream.flush()
                    response_frame = stream.readline(1_048_577)
            response = json.loads(response_frame)
            signature = response.pop("auth", None)
            expected = hmac.new(secret, json.dumps(response, sort_keys=True, separators=(",", ":")).encode(), hashlib.sha256).hexdigest()
            valid = response.get("request_id") == payload["request_id"] and isinstance(signature, str) and hmac.compare_digest(signature, expected) and response.get("status") == "ok"
            if valid:
                history = getattr(self, "_received_message_history", [])
                history.extend(response.get("hpc_messages", []))
                self._received_message_history = history[-500:]
            return valid
        except (OSError, ValueError, json.JSONDecodeError):
            return False

    def emit_due_messages(self, now_ms, secret):
        emitted = []
        recipients = self.CONNECTED_TO if isinstance(self.CONNECTED_TO, list) else ([self.CONNECTED_TO] if self.CONNECTED_TO else [])
        recipients = sorted(set(recipients + list(getattr(self, "BACKBONE_PEERS", []))))
        for index, (message_name, cycle_time_ms) in enumerate(self.MESSAGE_DEFINITIONS):
            if now_ms < self._message_next_due.get(index, 0):
                continue
            self._message_sequence += 1
            message = {"source_node_id": self.NODE_ID, "recipient_node_ids": recipients, "zone": self.ZONE, "role": self.ROLE if hasattr(self, "ROLE") else "ecu", "functional_domain": self.FUNCTIONAL_DOMAIN, "protocol": self.PROTOCOL, "network_segment": self.NETWORK_SEGMENT, "message_id": f"0x{int(self.MESSAGE_ID, 16) + index:03X}", "message_name": message_name, "cycle_time_ms": cycle_time_ms, "sequence": self._message_sequence, "sampled_at_monotonic_ms": round(now_ms, 3), "signals": copy.deepcopy(self.SIGNALS), "simulated": True}
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

    def handle_doip_request(self, packet, nodes, send_can_uds, context=None):
        import struct
        raw = bytes(packet)
        if len(raw) < 12:
            raise ValueError("DoIP diagnostic packet is too short")
        version, inverse, payload_type, payload_length = struct.unpack("!BBHI", raw[:8])
        source_address, target_address = struct.unpack("!HH", raw[8:12])
        if version != 0x02 or inverse != 0xFD or payload_type != 0x8001 or payload_length != len(raw) - 8:
            raise ValueError("DoIP header or payload length is invalid")
        source_hpc = next((node for node in nodes.values() if getattr(type(node), "DOIP_LOGICAL_ADDRESS", None) == source_address and getattr(node, "ROLE", "") == "hpc"), None)
        if source_hpc is None or source_hpc.NODE_ID not in self.CONNECTED_TO:
            raise PermissionError("DoIP source HPC is not connected to this ZCU")
        target = next((node for node in nodes.values() if getattr(type(node), "DOIP_LOGICAL_ADDRESS", None) == target_address), None)
        if target is None:
            raise ValueError("DoIP target logical address is unknown")
        uds_request = list(raw[12:])
        if target.NODE_ID == self.NODE_ID:
            uds_result = self.handle_uds_request(uds_request, context)
        elif target.NODE_ID in self.DOIP_ECU_ROUTES.values() and target.CONNECTED_TO == self.NODE_ID and not target.SAFETY_CRITICAL:
            can_result = send_can_uds(self.NODE_ID, target.NODE_ID, uds_request, context)
            uds_result = can_result["uds_result"]
        else:
            raise PermissionError("DoIP target is not a local non-safety ECU behind this ZCU")
        return {"source_hpc_id": source_hpc.NODE_ID, "target_node_id": target.NODE_ID, "uds_result": uds_result}

    def handle_uds_request(self, request_bytes, context=None):
        if isinstance(request_bytes, (bytes, bytearray)):
            request_bytes = list(request_bytes)
        if not isinstance(request_bytes, list) or not request_bytes or any(type(value) is not int or not 0 <= value <= 255 for value in request_bytes):
            raise ValueError("request_bytes must be a non-empty byte array")
        req = list(request_bytes)
        sid = req[0]
        context = context if isinstance(context, dict) else {}
        self._accepted_profile_bypasses = []
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
            return {"ecu_id": self.NODE_ID, "service": f"0x{sid:02X}", "service_name": service, "positive_response": True, "request_bytes": req, "response_bytes": list(response), "response_hex": response.hex(" ").upper(), "security_bypasses": list(self._accepted_profile_bypasses), **extra}

        def reject(nrc):
            response = bytes([0x7F, sid, nrc])
            return {"ecu_id": self.NODE_ID, "service": f"0x{sid:02X}", "service_name": service, "positive_response": False, "request_bytes": req, "response_bytes": list(response), "response_hex": response.hex(" ").upper(), "nrc": f"0x{nrc:02X}", "security_bypasses": list(self._accepted_profile_bypasses)}

        def protected():
            unauthorized = state["session"] != 0x03 or not state["unlocked"]
            if unauthorized and not self.software_profile_diagnostic_access_control_enabled():
                self._record_profile_bypass("diagnostic_access_control_bypass")
                return False
            return unauthorized

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
            if len(req) < 2:
                return reject(0x13)
            if not self.software_profile_security_access_required_enabled() and req[1] in (0x02, 0x04):
                state.update(unlocked=True, seed=None, security_failures=0)
                return reply([0x67, req[1]], security_unlocked=True, security_bypass=True)
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
            profile = manifest.get("software_profile", {})
            allowed_profile_keys = {"security_access_required", "message_authentication", "replay_protection", "freshness_protection", "rate_limiting", "timing_validation", "range_validation", "message_id_validation", "diagnostic_access_control", "zonal_segmentation", "firmware_signature_required", "anti_downgrade", "ids_logging", "signal_overrides"}
            numeric_signals = {name for name, value in getattr(self, "SIGNALS", {}).items() if isinstance(value, (int, float)) and not isinstance(value, bool)}
            overrides = profile.get("signal_overrides", {}) if isinstance(profile, dict) else None
            if (not isinstance(profile, dict) or set(profile) - allowed_profile_keys
                    or any(key in profile and type(profile[key]) is not bool for key in allowed_profile_keys - {"signal_overrides"})
                    or not isinstance(overrides, dict) or len(overrides) > 8
                    or set(overrides) - numeric_signals
                    or any(isinstance(value, bool) or not isinstance(value, (int, float)) or not -1000000000 <= value <= 1000000000 for value in overrides.values())):
                return reject(0x13)
            if manifest.get("ecu_id") != self.NODE_ID or not isinstance(version, str) or type(size) is not int or not 1 <= size <= 1048576 or not isinstance(digest, str) or len(digest) != 64: return reject(0x13)
            signed_data = {"ecu_id": self.NODE_ID, "version": version, "image_size": size, "sha256": digest.lower()}
            if "software_profile" in manifest:
                signed_data["software_profile"] = manifest["software_profile"]
            current_version = state["firmware"].get("version", "SIM-1.0")
            downgrade = self._firmware_version_is_older(version, current_version)
            if downgrade and self.software_profile_anti_downgrade_enabled():
                return reject(0x31)
            if downgrade:
                self._record_profile_bypass("downgrade_protection_bypass")
            signed = json.dumps(signed_data, sort_keys=True, separators=(",", ":")).encode()
            expected = hmac.new(("firmware-signature:" + self.NODE_ID).encode(), signed, hashlib.sha256).hexdigest()
            signature_valid = isinstance(signature, str) and hmac.compare_digest(expected, signature.lower())
            if not signature_valid and self.software_profile_firmware_signature_required_enabled(): return reject(0x35)
            if not signature_valid:
                self._record_profile_bypass("firmware_signature_bypass")
            transport = "can_local" if self.PROTOCOL in ("CAN", "CAN-FD") else "ethernet_ota"
            if context.get("transport") != transport: return reject(0x31)
            state["flash"] = {"manifest": dict(manifest), "transport": transport, "next": 1, "image": bytearray()}
            return reply([0x74, 0x20, 0x04, 0], transfer_ready=True, transport=transport, firmware_signature_bypass=not signature_valid, downgrade_protection_bypass=downgrade)
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
            profile = dict(manifest.get("software_profile", {}))
            state["firmware"] = {"version": manifest["version"], "sha256": digest, "transport": flash["transport"], "software_profile": profile, "simulated": True}
            self._software_profile = profile
            state["flash"] = None
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

    def _build_ota_network_transport(self, send_socket, node_instances):
        def send_request(source_id, request_bytes, context=None):
            started = time.perf_counter()
            if getattr(self, "ROLE", "ecu") == "zone_controller":
                source = node_instances[source_id]
                packet = struct.pack("!BBHIHH", 0x02, 0xFD, 0x8001, len(request_bytes) + 4, source.DOIP_LOGICAL_ADDRESS, self.DOIP_LOGICAL_ADDRESS) + bytes(request_bytes)
                response = send_socket("doip", {"action": "doip_diagnostic", "source_hpc_id": source_id, "target_zcu_id": self.NODE_ID, "target_component_id": self.NODE_ID, "context": context, "phase": "ota", "doip_packet_hex": packet.hex().upper()})
            else:
                response = send_socket("can", {"action": "uds_request", "source_node_id": source_id, "target_node_id": self.NODE_ID, "request_bytes": request_bytes, "context": context})
            if not isinstance(response, dict) or response.get("status") != "ok":
                raise RuntimeError((response or {}).get("message", "OTA diagnostic socket request failed"))
            result = response.get("uds_result")
            if not isinstance(result, dict):
                raise RuntimeError("OTA diagnostic socket returned an invalid UDS response")
            self._record_ota_diagnostic(source_id, result, time.perf_counter() - started)
            return result

        def send_batch(source_id, requests):
            if getattr(self, "ROLE", "ecu") == "zone_controller":
                source = node_instances[source_id]
                packets = [(struct.pack("!BBHIHH", 0x02, 0xFD, 0x8001, len(item) + 4, source.DOIP_LOGICAL_ADDRESS, self.DOIP_LOGICAL_ADDRESS) + bytes(item)).hex().upper() for item in requests]
                response = send_socket("doip", {"action": "doip_diagnostic_batch", "source_hpc_id": source_id, "target_zcu_id": self.NODE_ID, "target_component_id": self.NODE_ID, "phase": "ota", "doip_packet_hexes": packets})
                transport = "DoIP"
            else:
                response = send_socket("can", {"action": "uds_batch", "source_node_id": source_id, "target_node_id": self.NODE_ID, "requests": requests})
                transport = "UDS over CAN"
            if not isinstance(response, dict) or response.get("status") != "ok":
                raise RuntimeError((response or {}).get("message", "OTA transfer socket batch failed"))
            results = response.get("uds_results")
            if not isinstance(results, list) or len(results) != len(requests) or any(not isinstance(item, dict) for item in results):
                raise RuntimeError("OTA transfer socket returned an invalid UDS batch")
            self._record_ota_diagnostic(source_id, {"service": "0x36", "service_name": "TransferData", "positive_response": all(item.get("positive_response") for item in results)}, 0, len(results), transport)
            return results

        return {"send_request": send_request, "send_batch": send_batch}

    def _record_ota_diagnostic(self, source_id, result, elapsed_seconds, block_count=None, transport=None):
        transport = transport or ("DoIP" if getattr(self, "ROLE", "ecu") == "zone_controller" else "UDS over CAN")
        event = {"event_type": "diagnostic", "timestamp": time.time(), "phase": "ota", "source_node_id": source_id, "target_node_id": self.NODE_ID, "transport_type": transport, "socket_id": "doip-gateway" if transport == "DoIP" else "can-gateway", "direction": "request / response", "service_id": result.get("service"), "response_service_id": result.get("response_bytes", [None])[0] if result.get("response_bytes") else None, "status": "positive" if result.get("positive_response") else "negative", "nrc": result.get("nrc"), "latency_ms": round(elapsed_seconds * 1000, 3)}
        if block_count is not None:
            event["transfer_block_count"] = block_count
        self._ota_diagnostic_events.append(event)
        del self._ota_diagnostic_events[:-1000]

    def perform_ota(self, package, node_instances=None, network_transport=None):
        if not isinstance(package, dict) or package.get("target_ecu_id") != self.NODE_ID:
            raise ValueError("OTA package target does not match this node")
        source = package.get("source_hpc_id")
        trusted = set(getattr(self, "TRUSTED_SOURCES", ()))
        direct = self.CONNECTED_TO if isinstance(self.CONNECTED_TO, (list, tuple, set)) else ([self.CONNECTED_TO] if self.CONNECTED_TO else [])
        if source not in trusted and source not in {"hpc-vehicle", "hpc-adas", "hpc-cockpit"} and source not in direct:
            raise PermissionError("source HPC is not trusted for this node")
        try:
            image = bytes.fromhex(package.get("image_hex", ""))
        except (TypeError, ValueError) as exc:
            raise ValueError("image_hex must contain valid hexadecimal bytes") from exc
        manifest = package.get("manifest")
        if not image or not isinstance(manifest, dict) or manifest.get("ecu_id") != self.NODE_ID or manifest.get("image_size") != len(image) or manifest.get("sha256") != hashlib.sha256(image).hexdigest():
            raise ValueError("firmware image does not match its manifest")

        node_instances = node_instances if isinstance(node_instances, dict) else {}
        role = getattr(self, "ROLE", "ecu")
        source_node = node_instances.get(source)
        if node_instances and (source_node is None or getattr(source_node, "ROLE", "") != "hpc"):
            raise PermissionError("OTA source must identify a registered HPC")
        if role == "zone_controller":
            connected_hpcs = self.CONNECTED_TO if isinstance(self.CONNECTED_TO, (list, tuple, set)) else (self.CONNECTED_TO,)
            if source not in connected_hpcs:
                raise PermissionError("source HPC is not connected to the target ZCU")
            source_transport_id = source
        elif role == "ecu":
            parent_id = self.CONNECTED_TO
            parent_node = node_instances.get(parent_id)
            is_zcu_parent = (
                getattr(parent_node, "ROLE", "") == "zone_controller"
                if node_instances
                else isinstance(parent_id, str) and parent_id.startswith("zcu-")
            )
            if is_zcu_parent:
                if package.get("zcu_id") != parent_id:
                    raise PermissionError("OTA package ZCU route does not match the ECU topology")
                connected_hpcs = parent_node.CONNECTED_TO if parent_node is not None else getattr(self, "TRUSTED_SOURCES", ())
                if source not in connected_hpcs:
                    raise PermissionError("source HPC is not connected to the target ECU's ZCU")
                source_transport_id = parent_id
            else:
                if parent_id != source:
                    raise PermissionError("source HPC is not directly connected to the target ECU")
                source_transport_id = source
        else:
            raise ValueError("UDS OTA is supported only for ECU and ZCU targets")
        if isinstance(network_transport, dict) and callable(network_transport.get("send_socket")):
            network_transport = self._build_ota_network_transport(
                network_transport["send_socket"], node_instances
            )
        uds_results = []

        def send(request_bytes, context=None):
            if network_transport is None:
                result = self.handle_uds_request(request_bytes, context)
            else:
                result = network_transport["send_request"](source_transport_id, request_bytes, context)
            uds_results.append(result)
            return result

        def trace():
            return [{"service": item.get("service"), "service_name": item.get("service_name"), "positive_response": item.get("positive_response"), "nrc": item.get("nrc")} for item in uds_results]

        session = send([0x10, 0x03])
        if not session.get("positive_response"):
            return {"status": "rejected", "reason": "programming_session_rejected", "uds_trace": trace()}
        seed_result = send([0x27, 0x01])
        if not seed_result.get("positive_response"):
            return {"status": "rejected", "reason": "security_seed_rejected", "uds_trace": trace()}
        seed = bytes(seed_result.get("response_bytes", [])[2:])
        if not seed:
            raise RuntimeError("target returned an empty UDS SecurityAccess seed")
        key = hmac.new(("node-security:" + self.NODE_ID).encode(), seed, hashlib.sha256).digest()[:8]
        unlock = send([0x27, 0x02, *key])
        if not unlock.get("positive_response"):
            return {"status": "rejected", "reason": "security_access_rejected", "uds_trace": trace()}
        transport_name = "can_local" if getattr(self, "ROLE", "ecu") == "ecu" and self.PROTOCOL in ("CAN", "CAN-FD") else "ethernet_ota"
        download = send([0x34, 0x00, 0x00, 0x00], {"manifest": manifest, "transport": transport_name})
        if not download.get("positive_response"):
            return {"status": "rejected", "reason": "request_download_rejected", "uds_trace": trace()}

        requests = [[0x36, sequence % 256, *image[start:start + 6]] for sequence, start in enumerate(range(0, len(image), 6), 1)]
        transfer_count = 0
        first_ack = last_ack = None
        for offset in range(0, len(requests), 512):
            batch = requests[offset:offset + 512]
            if network_transport is None:
                acknowledgements = [send(item) for item in batch]
            else:
                acknowledgements = network_transport["send_batch"](source_transport_id, batch)
            if not isinstance(acknowledgements, list) or len(acknowledgements) != len(batch):
                raise RuntimeError("OTA transfer returned an incomplete UDS batch")
            for acknowledgement in acknowledgements:
                if not isinstance(acknowledgement, dict) or not acknowledgement.get("positive_response"):
                    return {"status": "rejected", "reason": "transfer_data_rejected", "uds_trace": trace(), "transfer_blocks": transfer_count}
                transfer_count += 1
            if acknowledgements:
                first_ack = first_ack or acknowledgements[0]
                last_ack = acknowledgements[-1]

        exit_result = send([0x37])
        if not exit_result.get("positive_response"):
            return {"status": "rejected", "reason": "transfer_exit_rejected", "uds_trace": trace()}
        zcu_id = source_transport_id if source_transport_id != source else package.get("zcu_id")
        route_transport = "DoIP" if getattr(self, "ROLE", "ecu") == "zone_controller" else "UDS over CAN/CAN-FD" if transport_name == "can_local" else "UDS over Automotive Ethernet"
        safe_trace = trace()[:4]
        safe_trace.extend([
            {"service": "0x36", "service_name": "TransferData", "positive_response": True, "block_count": transfer_count},
            {"service": exit_result.get("service"), "service_name": exit_result.get("service_name"), "positive_response": exit_result.get("positive_response")},
        ])
        result = {
            "status": "completed",
            "route": {"source_hpc_id": source, "zcu_id": zcu_id, "target_ecu_id": self.NODE_ID},
            "hops": [
                {"source_hpc_id": source, "zcu_id": zcu_id, "target_ecu_id": self.NODE_ID, "transport": "Ethernet socket"},
                {"source_hpc_id": source, "zcu_id": zcu_id, "target_ecu_id": self.NODE_ID, "transport": route_transport},
            ],
            "uds_trace": safe_trace,
            "transfer_data": {
                "block_count": transfer_count,
                "bytes_transferred": len(image),
                "first_ack": {"service": first_ack.get("service"), "positive_response": first_ack.get("positive_response")},
                "last_ack": {"service": last_ack.get("service"), "positive_response": last_ack.get("positive_response")},
            },
            "firmware": exit_result.get("firmware"),
            "software_profile_activated": bool(manifest.get("software_profile")),
            "hardware_flash_performed": False,
        }
        if network_transport is None:
            result["uds_results"] = uds_results
        return result
    def apply_software_profile_to_signal(self, signal_layout):
        override = getattr(self, "_software_profile", {}).get("signal_overrides", {}).get(signal_layout["source_signal"])
        if override is not None:
            signal_layout["value"] = override
            signal_layout["encoded_value"] = int(round(override))
        return signal_layout

    def software_profile_security_access_required_enabled(self):
        return getattr(self, "_software_profile", {}).get("security_access_required", True)

    def software_profile_message_authentication_enabled(self):
        return getattr(self, "_software_profile", {}).get("message_authentication", True)

    def software_profile_replay_protection_enabled(self):
        return getattr(self, "_software_profile", {}).get("replay_protection", True)

    def software_profile_freshness_protection_enabled(self):
        return getattr(self, "_software_profile", {}).get("freshness_protection", True)

    def software_profile_rate_limiting_enabled(self):
        return getattr(self, "_software_profile", {}).get("rate_limiting", True)

    def software_profile_timing_validation_enabled(self):
        return getattr(self, "_software_profile", {}).get("timing_validation", True)

    def software_profile_range_validation_enabled(self):
        return getattr(self, "_software_profile", {}).get("range_validation", True)

    def software_profile_message_id_validation_enabled(self):
        return getattr(self, "_software_profile", {}).get("message_id_validation", True)

    def software_profile_diagnostic_access_control_enabled(self):
        return getattr(self, "_software_profile", {}).get("diagnostic_access_control", True)

    def software_profile_zonal_segmentation_enabled(self):
        return getattr(self, "_software_profile", {}).get("zonal_segmentation", True)

    def software_profile_firmware_signature_required_enabled(self):
        return getattr(self, "_software_profile", {}).get("firmware_signature_required", True)

    def software_profile_anti_downgrade_enabled(self):
        return getattr(self, "_software_profile", {}).get("anti_downgrade", True)

    def software_profile_ids_logging_enabled(self):
        return getattr(self, "_software_profile", {}).get("ids_logging", True)

    def _record_profile_bypass(self, category):
        bypasses = getattr(self, "_accepted_profile_bypasses", None)
        if bypasses is None:
            bypasses = []
            self._accepted_profile_bypasses = bypasses
        if category not in bypasses:
            bypasses.append(category)

    def _firmware_version_is_older(self, candidate, current):
        def components(version):
            if not isinstance(version, str):
                return ()
            return tuple(int(part) for part in re.findall(r"\d+", version))

        candidate_parts = components(candidate)
        current_parts = components(current)
        if not candidate_parts or not current_parts:
            return candidate != current
        width = max(len(candidate_parts), len(current_parts))
        candidate_parts += (0,) * (width - len(candidate_parts))
        current_parts += (0,) * (width - len(current_parts))
        return candidate_parts < current_parts
    def uds_diagnostics(self):
        runtime = self.diagnostics()
        return {"node_id": self.NODE_ID, "supported_services": list(self.UDS_SUPPORTED_SERVICES), "dids": dict(self.UDS_DIDS), "rids": dict(self.UDS_RIDS), "dtc_catalog": dict(self.DTC_CATALOG), "active_dtcs": runtime["active_dtcs"], "security_features": list(self.SECURE_FEATURES), "firmware": runtime["firmware"]}

    def run_uds_protocol_probes(self, send_socket):
        dids = list(self.UDS_DIDS)
        requests = []
        if dids:
            did = int(dids[0], 16)
            requests.append(("uds_supported_did", [0x22, did >> 8, did & 0xFF]))
        reserved_dids = {0xF180, 0xF181, 0xF183, 0xF184, 0xF185, 0xF186, 0xF187, 0xF188, 0xF1A0}
        known_dids = {int(value, 16) for value in dids} | reserved_dids
        unknown_did = secrets.randbelow(0x10000)
        while unknown_did in known_dids:
            unknown_did = secrets.randbelow(0x10000)
        unknown_rid = secrets.randbelow(0x10000)
        while f"0x{unknown_rid:04X}" in self.UDS_RIDS:
            unknown_rid = secrets.randbelow(0x10000)
        requests.extend([("uds_unsupported_did", [0x22, unknown_did >> 8, unknown_did & 0xFF]), ("uds_unsupported_rid", [0x31, 0x01, unknown_rid >> 8, unknown_rid & 0xFF]), ("uds_malformed_length", [0x22])])
        categories = {}
        events = []
        attempted = rejected = 0
        for category, request_bytes in requests:
            response = send_socket({"action": "uds_request", "node_id": self.NODE_ID, "request_bytes": request_bytes, "sandboxed_uds_probe": True})
            data = response.get("data") if isinstance(response, dict) else None
            result = data.get("uds_result") if isinstance(data, dict) else None
            if not isinstance(result, dict):
                raise RuntimeError(f"simulated UDS probe did not receive a valid response for {self.NODE_ID}")
            attempted += 1
            if result.get("positive_response") is not True:
                rejected += 1
                categories[category] = categories.get(category, 0) + 1
                events.append((category, f"Simulator rejected bounded {category} probe with NRC {result.get('nrc', 'unknown')}.", "dropped"))
        response = send_socket({"action": "uds_security_probe", "node_id": self.NODE_ID, "sandboxed_uds_probe": True})
        data = response.get("data") if isinstance(response, dict) else None
        result = data.get("uds_result") if isinstance(data, dict) else None
        if not isinstance(result, dict):
            raise RuntimeError(f"simulated SecurityAccess probe did not receive a valid response for {self.NODE_ID}")
        attempted += 1
        category = "uds_security_access" if result.get("positive_response") is not True else "uds_security_access_bypass"
        if category == "uds_security_access":
            rejected += 1
            detail = "Simulator rejected a bounded incorrect SecurityAccess key."
            action = "dropped"
        else:
            detail = "Target accepted an incorrect SecurityAccess key; installed software does not enforce the required authorization."
            action = "accepted"
        categories[category] = categories.get(category, 0) + 1
        events.append((category, detail, action))
        return {"attempted": attempted, "rejected": rejected, "category_counts": categories, "security_events": events}

    def handle_uds_batch(self, requests, sandboxed=False):
        if not isinstance(requests, list) or not 1 <= len(requests) <= 512:
            raise ValueError("UDS batch must contain 1 to 512 requests")
        if any(not isinstance(item, list) or not item or any(type(value) is not int or not 0 <= value <= 255 for value in item) for item in requests):
            raise ValueError("UDS batch requests must be non-empty byte arrays")
        handle = self.sandboxed_uds_request if sandboxed else self.handle_uds_request
        return [handle(item) for item in requests]

    def sandboxed_uds_request(self, request_bytes):
        previous_state = self._uds_state
        self._uds_state = copy.deepcopy(previous_state)
        self._uds_state.update(session=0x01, unlocked=False, seed=None, security_failures=0)
        try:
            return self.handle_uds_request(request_bytes)
        finally:
            self._uds_state = previous_state

    def sandboxed_security_access_probe(self):
        previous_state = self._uds_state
        self._uds_state = copy.deepcopy(previous_state)
        self._uds_state.update(session=0x01, unlocked=False, seed=None, security_failures=0)
        try:
            session_result = self.handle_uds_request([0x10, 0x03])
            seed_result = self.handle_uds_request([0x27, 0x01])
            if seed_result.get("positive_response") is not True:
                raise RuntimeError("simulated ECU did not provide a SecurityAccess seed")
            seed = bytes(seed_result["response_bytes"][2:])
            expected_key = hmac.new(("node-security:" + self.NODE_ID).encode(), seed, hashlib.sha256).digest()[:8]
            incorrect_key = bytes([expected_key[0] ^ 0x01, *expected_key[1:]])
            return {
                "uds_result": self.handle_uds_request([0x27, 0x02, *incorrect_key]),
                "security_probe_results": {"session_control": session_result, "seed_request": seed_result},
            }
        finally:
            self._uds_state = previous_state
    UDS_DIDS = {"0xF1B0": "rear_left_route_status", "0xF1B1": "rear_left_child_health"}
    UDS_RIDS = {"0x1301": "rear_left_bus_self_test", "0x1302": "rear_left_route_integrity_check"}
    NODE_ID = "zcu-rear-left"
    DISPLAY_NAME = "Rear-left Zone Controller"
    ZONE = "rear_left"
    ROLE = "zone_controller"
    FUNCTIONAL_DOMAIN = "zonal_gateway"
    PROTOCOL = "Automotive Ethernet SOME/IP"
    NETWORK_SEGMENT = "vehicle-backbone"
    CONNECTED_TO = ["hpc-vehicle", "hpc-cockpit"]
    TRUSTED_SOURCES = ("hpc-vehicle", "hpc-cockpit")
    MESSAGE_ID = "0x012"
    MESSAGE_NAME = "RearLeftZoneHealth"
    CYCLE_TIME_MS = 100
    MESSAGE_DEFINITIONS = [("RearLeftZoneHealth", 100), ("RearLeftRouteTable", 500), ("RearLeftBusLoad", 100), ("RearLeftBodyRoute", 100), ("RearLeftBatteryRoute", 100), ("RearLeftTimingHealth", 100), ("RearLeftAuthenticationStatus", 250), ("RearLeftDTCStatus", 1000), ("RearLeftSecurityStatus", 500), ("RearLeftHeartbeat", 1000)]
    SIGNALS = {"gateway_state": "online", "child_ecu_count": 2, "forwarded_frames_per_sec": 310}
    SIGNAL_RANGES = {"child_ecu_count": [0, 16], "forwarded_frames_per_sec": [0, 5000]}
    MAX_MESSAGE_RATE_HZ = 2000
    MAX_MESSAGE_COUNT = 256
    MAX_PAYLOAD_BYTES = 1500
    UDS_SUPPORTED_SERVICES = ["0x10", "0x11", "0x14", "0x19", "0x22", "0x27", "0x28", "0x31", "0x34", "0x36", "0x37", "0x3E", "0x85"]
    SECURE_FEATURES = ["zone_message_authentication", "integrity_validation", "replay_protection", "secure_diagnostics", "signed_firmware_policy", "child_ecu_isolation"]
    DTC_CATALOG = {"0xC10301": "Rear-left zone bus-off", "0xC10302": "Rear body ECU communication timeout", "0xC10303": "Battery ECU communication timeout", "0xC10304": "Zone authentication failure", "0xC10305": "Zone firmware signature failure"}

    def seal_network_message(self, message, secret):
        message.pop("auth_tag", None)
        key = hmac.new(
            secret, b"node-message:" + self.NODE_ID.encode(), hashlib.sha256
        ).digest()
        message["auth_tag"] = hmac.new(
            key,
            json.dumps(message, sort_keys=True, separators=(",", ":")).encode(),
            hashlib.sha256,
        ).hexdigest()

    def encode_wire_message(self, original, index, catalog_entry, secret):
        message = original
        message["direction"] = "tx"
        message["periodicity_ms"] = message["cycle_time_ms"]
        message["sent_at_unix_ms"] = int(time.time() * 1000)
        signal_layout = self.apply_software_profile_to_signal(
            copy.deepcopy(catalog_entry["signal_layout"])
        )
        message["signal_layout"] = signal_layout
        message["signals"] = {signal_layout["name"]: signal_layout["value"]}
        signed_value = signal_layout["encoded_value"] < 0
        signal_bytes = signal_layout["encoded_value"].to_bytes(
            8, "big", signed=signed_value
        )
        message["signal_payload_hex"] = signal_bytes.hex().upper()
        if self.PROTOCOL in {"CAN", "CAN-FD"}:
            can_id = catalog_entry["can_id"]
            message.update(
                {
                    "transport_type": self.PROTOCOL,
                    "message_id": f"0x{can_id:03X}",
                    "can_frame": {
                        "can_id": can_id,
                        "can_id_hex": f"0x{can_id:03X}",
                        "dlc": 8,
                        "data_hex": signal_bytes.hex().upper(),
                    },
                }
            )
        else:
            service_id = int(catalog_entry["someip_service_id"], 16)
            method_id = index + 1
            payload = json.dumps(
                {
                    "source_node_id": self.NODE_ID,
                    "event": message["message_name"],
                    "signals": message["signals"],
                    "signal_layout": signal_layout,
                    "periodicity_ms": message["periodicity_ms"],
                },
                sort_keys=True,
                separators=(",", ":"),
            ).encode()
            request_id = (
                (int(hashlib.sha256(self.NODE_ID.encode()).hexdigest()[:4], 16) << 16)
                | (message["sequence"] & 0xFFFF)
            )
            header = struct.pack(
                "!HHII4B",
                service_id,
                method_id,
                len(payload) + 8,
                request_id,
                1,
                1,
                0x02,
                0,
            )
            message.update(
                {
                    "transport_type": "SOME/IP over TCP",
                    "someip": {
                        "service_id": f"0x{service_id:04X}",
                        "method_or_event_id": f"0x{method_id:04X}",
                        "client_id": f"0x{request_id >> 16:04X}",
                        "session_id": f"0x{request_id & 0xFFFF:04X}",
                        "protocol_version": 1,
                        "interface_version": 1,
                        "message_type": "notification",
                        "length": len(payload) + 8,
                        "packet_hex": (header + payload).hex().upper(),
                    },
                }
            )
        if self.software_profile_message_authentication_enabled():
            self.seal_network_message(message, secret)
        else:
            message["auth_tag"] = "0" * 64
        return message

    def encode_service_relay(self, original, index, secret, relay_role):
        service_id = self.SOMEIP_SERVICE_ID
        method_id = index % 30 + 1
        payload = json.dumps(
            {
                "source_node_id": original["source_node_id"],
                "message_name": original["message_name"],
                "signal_layout": original["signal_layout"],
                "signal_payload_hex": original["signal_payload_hex"],
                "original_transport": original["transport_type"],
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        request_id = (
            (int(hashlib.sha256(self.NODE_ID.encode()).hexdigest()[:4], 16) << 16)
            | (original["sequence"] & 0xFFFF)
        )
        header = struct.pack(
            "!HHII4B",
            service_id,
            method_id,
            len(payload) + 8,
            request_id,
            1,
            1,
            0x02,
            0,
        )
        relay = {
            "source_node_id": self.NODE_ID,
            "relayed_source_node_id": original["source_node_id"],
            f"relayed_by_{relay_role}_id": self.NODE_ID,
            "recipient_node_ids": ["hpc-vehicle"],
            "message_name": original["message_name"],
            "cycle_time_ms": original["cycle_time_ms"],
            "periodicity_ms": original["periodicity_ms"],
            "sequence": original["sequence"],
            "sampled_at_monotonic_ms": original["sampled_at_monotonic_ms"],
            "signals": original["signals"],
            "signal_layout": original["signal_layout"],
            "signal_payload_hex": original["signal_payload_hex"],
            "origin_message": original,
            "transport_type": "SOME/IP over TCP",
            "someip": {
                "service_id": f"0x{service_id:04X}",
                "method_or_event_id": f"0x{method_id:04X}",
                "client_id": f"0x{request_id >> 16:04X}",
                "session_id": f"0x{request_id & 0xFFFF:04X}",
                "protocol_version": 1,
                "interface_version": 1,
                "message_type": "notification",
                "length": len(payload) + 8,
                "packet_hex": (header + payload).hex().upper(),
            },
        }
        self.seal_network_message(relay, secret)
        return relay

    def verify_network_message(self, message, secret):
        signature = message.get("auth_tag")
        if not isinstance(signature, str):
            return False
        unsigned = {key: value for key, value in message.items() if key != "auth_tag"}
        key = hmac.new(
            secret, b"node-message:" + self.NODE_ID.encode(), hashlib.sha256
        ).digest()
        expected = hmac.new(
            key,
            json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode(),
            hashlib.sha256,
        ).hexdigest()
        return hmac.compare_digest(expected, signature)

    def validate_service_relay(self, relay, nodes, secret, relay_role):
        origin = relay.get("origin_message") if isinstance(relay, dict) else None
        origin_id = origin.get("source_node_id") if isinstance(origin, dict) else None
        source = nodes.get(relay.get(f"relayed_by_{relay_role}_id")) if isinstance(relay, dict) else None
        if source is None or not isinstance(origin, dict):
            return "relay source or origin message is invalid", origin_id, origin

        if relay_role == "zcu":
            connected_hpcs = source.CONNECTED_TO
            connected_hpcs = (
                connected_hpcs
                if isinstance(connected_hpcs, (list, tuple, set))
                else [connected_hpcs]
            )
            allowed_origin = (
                getattr(source, "ROLE", "") == "zone_controller"
                and self.NODE_ID in connected_hpcs
                and (
                    origin_id == source.NODE_ID
                    or (
                origin_id in nodes
                and getattr(nodes[origin_id], "ROLE", "ecu") == "ecu"
                and getattr(nodes[origin_id], "ZONE", None) == source.ZONE
                and not getattr(nodes[origin_id], "SAFETY_CRITICAL", False)
                    )
                )
            )
        elif relay_role == "hpc":
            source_hpc = source
            allowed_origin = (
                getattr(self, "ROLE", "") == "hpc"
                and source_hpc is not None
                and getattr(source_hpc, "ROLE", "") == "hpc"
                and source_hpc.NODE_ID in getattr(self, "BACKBONE_PEERS", ())
                and origin_id in nodes
                and getattr(nodes[origin_id], "ROLE", "ecu") == "ecu"
                and getattr(nodes[origin_id], "SAFETY_CRITICAL", False)
                and getattr(nodes[origin_id], "CONNECTED_TO", None)
                == source_hpc.NODE_ID
            )
            source = source_hpc
        else:
            return "unsupported relay role", origin_id, origin

        relay_id = relay.get(f"relayed_by_{relay_role}_id")
        if (
            not allowed_origin
            or source is None
            or relay_id != source.NODE_ID
            or not source.verify_network_message(relay, secret)
        ):
            return "relay authentication or source authorization failed", origin_id, origin
        try:
            raw = bytes.fromhex(relay["someip"]["packet_hex"])
            service_id, method_id, length = struct.unpack("!HHI", raw[:8])
        except (KeyError, TypeError, ValueError, struct.error):
            return "malformed SOME/IP relay packet", origin_id, origin
        if (
            len(raw) < 16
            or service_id != source.SOMEIP_SERVICE_ID
            or not 1 <= method_id <= 30
            or length != len(raw) - 8
            or raw[12:14] != b"\x01\x01"
        ):
            return "SOME/IP relay header does not match source service", origin_id, origin
        return None, origin_id, origin

    def authorize_uds_route(self, source):

        self._accepted_profile_bypasses = []
        authorized = self._authorize_uds_route_secure(source)
        if authorized:
            return True
        if not self.software_profile_zonal_segmentation_enabled():
            self._record_profile_bypass("zonal_segmentation_bypass")
            return True
        return False

    def _authorize_uds_route_secure(self, source):
        if source is None or getattr(self, "ROLE", "ecu") != "ecu":
            return False
        source_role = getattr(source, "ROLE", "")
        if source_role == "hpc":
            return (
                getattr(self, "SAFETY_CRITICAL", False)
                and getattr(self, "CONNECTED_TO", None) == source.NODE_ID
            )
        if source_role == "zone_controller":
            return (
                not getattr(self, "SAFETY_CRITICAL", False)
                and getattr(self, "CONNECTED_TO", None) == source.NODE_ID
                and getattr(self, "ZONE", None) == getattr(source, "ZONE", None)
            )
        return False

    def validate_network_message(
        self,
        message,
        expected,
        transport,
        receiver_id,
        receiver_spec,
        secret,
        check_periodicity=True,
        sequence_scope="default",
    ):
        if (
            not isinstance(message, dict)
            or message.get("source_node_id") != self.NODE_ID
        ):
            return "unknown or mismatched source node", False
        if message.get("message_name") != expected["message_name"]:
            return "message name is not declared by the transmitting node", False
        self._accepted_profile_bypasses = []
        if not self.verify_network_message(message, secret):
            if self.software_profile_message_authentication_enabled():
                return "node message authentication tag is invalid", False
            self._record_profile_bypass("message_authentication_bypass")
        sequence = message.get("sequence")
        if type(sequence) is not int or sequence < 1:
            return "message sequence is invalid", False
        self._freshness_protection_bypass_accepted = False
        sent_at_unix_ms = message.get("sent_at_unix_ms")
        if (
            type(sent_at_unix_ms) is not int
            or abs(int(time.time() * 1000) - sent_at_unix_ms) > 5000
        ):
            if self.software_profile_freshness_protection_enabled():
                return "message freshness timestamp is missing, stale, or outside allowed clock skew", False
            self._freshness_protection_bypass_accepted = True
            self._record_profile_bypass("freshness_protection_bypass")

        if not hasattr(self, "_message_rate_windows"):
            self._message_rate_windows = {}
        rate_key = f"{receiver_id}:{sequence_scope}"
        rate_window = self._message_rate_windows.setdefault(rate_key, deque())
        now_seconds = time.monotonic()
        while rate_window and now_seconds - rate_window[0] >= 1.0:
            rate_window.popleft()
        max_rate = max(1, int(getattr(self, "MAX_MESSAGE_RATE_HZ", 1000)))
        if len(rate_window) >= max_rate:
            if self.software_profile_rate_limiting_enabled():
                return "message flood rate exceeds the node's declared per-second limit", False
            self._record_profile_bypass("rate_limiting_bypass")
        rate_window.append(now_seconds)

        sequence_key = (
            f"{expected['message_id']}:{transport}:{receiver_id}:{sequence_scope}"
        )
        if not hasattr(self, "_last_message_sequences"):
            self._last_message_sequences = {}
            self._last_message_times = {}
        previous_sequence = self._last_message_sequences.get(sequence_key)
        replay_accepted = False
        if previous_sequence is not None and sequence <= previous_sequence:
            if self.software_profile_replay_protection_enabled():
                return "replayed or out-of-order message sequence", False
            replay_accepted = True
            self._record_profile_bypass("replay_protection_bypass")
        if (
            message.get("cycle_time_ms") != expected["cycle_time_ms"]
            or message.get("periodicity_ms") != expected["cycle_time_ms"]
        ):
            if self.software_profile_timing_validation_enabled():
                return "declared message periodicity differs from node contract", False
            self._record_profile_bypass("timing_validation_bypass")
        layout = message.get("signal_layout")
        expected_layout = expected["signal_layout"]
        if (
            not isinstance(layout, dict)
            or layout.get("name") != expected_layout["name"]
            or layout.get("minimum") != expected_layout["minimum"]
            or layout.get("maximum") != expected_layout["maximum"]
        ):
            return "signal layout or threshold differs from node contract", False
        value = layout.get("encoded_value")
        if type(value) is not int:
            return "signal value is malformed", False
        if value < layout["minimum"] or value > layout["maximum"]:
            if self.software_profile_range_validation_enabled():
                return "signal value is outside its declared threshold", False
            self._record_profile_bypass("range_validation_bypass")

        if transport == "can":
            frame = message.get("can_frame")
            if not isinstance(frame, dict):
                return "CAN frame is missing", False
            if expected["can_id"] is not None:
                expected_can_id = expected["can_id"]
                if self.PROTOCOL not in {"CAN", "CAN-FD"}:
                    return "source is not authorized to transmit ECU CAN messages", False
                allowed_target = self.CONNECTED_TO
            else:
                expected_can_id = expected["can_control_id"]
                source_role = getattr(self, "ROLE", "ecu")
                if source_role == "zone_controller":
                    route_allowed = (
                        receiver_spec.get("role") == "ecu"
                        and receiver_spec.get("zone") == self.ZONE
                        and not receiver_spec.get("safety_critical")
                    )
                else:
                    route_allowed = (
                        receiver_spec.get("role") == "ecu"
                        and receiver_spec.get("safety_critical")
                        and receiver_spec.get("connected_to") == self.NODE_ID
                    )
                if not route_allowed:
                    if self.software_profile_zonal_segmentation_enabled():
                        return "controller CAN destination violates the vehicle hierarchy", False
                    self._record_profile_bypass("zonal_segmentation_bypass")
                allowed_target = receiver_id
            if (
                frame.get("can_id") != expected_can_id
                or message.get("message_id") != f"0x{expected_can_id:03X}"
            ):
                if self.software_profile_message_id_validation_enabled():
                    return "CAN identifier differs from the node catalog", False
                self._record_profile_bypass("message_id_validation_bypass")
            if (
                frame.get("dlc") != 8
                or frame.get("data_hex") != message.get("signal_payload_hex")
                or frame.get("data_hex")
                != value.to_bytes(8, "big", signed=value < 0).hex().upper()
            ):
                return "CAN payload must be the declared 8-byte signal value", False
            if allowed_target != receiver_id:
                if self.software_profile_zonal_segmentation_enabled():
                    return "CAN frame destination violates the node routing hierarchy", False
                self._record_profile_bypass("zonal_segmentation_bypass")
        else:
            if getattr(self, "ROLE", "ecu") not in {"hpc", "zone_controller"}:
                return "source is not authorized to transmit SOME/IP", False
            packet = message.get("someip", {}).get("packet_hex")
            try:
                raw = bytes.fromhex(packet)
                if len(raw) < 16:
                    return "SOME/IP packet header is malformed", False
                service_id, method_id, length = struct.unpack("!HHI", raw[:8])
            except (TypeError, ValueError, struct.error):
                return "SOME/IP packet header is malformed", False
            if (
                service_id != int(expected["someip_service_id"], 16)
                or method_id != int(expected["someip_method_id"], 16)
            ):
                if self.software_profile_message_id_validation_enabled():
                    return "SOME/IP service or method differs from the node catalog", False
                self._record_profile_bypass("message_id_validation_bypass")
            if (
                length != len(raw) - 8
                or raw[12] != 1
                or raw[13] != 1
            ):
                return "SOME/IP version or length does not match catalog", False

        sampled_at_monotonic_ms = message.get("sampled_at_monotonic_ms")
        if (
            type(sampled_at_monotonic_ms) not in (int, float)
            or not math.isfinite(sampled_at_monotonic_ms)
            or sampled_at_monotonic_ms < 0
        ):
            if self.software_profile_timing_validation_enabled():
                return "message timing timestamp is malformed", False
            self._record_profile_bypass("timing_validation_bypass")
            now_ms = 0.0
        else:
            now_ms = float(sampled_at_monotonic_ms)
        if check_periodicity:
            previous = self._last_message_times.get(sequence_key)
            if previous is not None:
                interval = now_ms - previous
                period = expected["cycle_time_ms"]
                tolerance = max(15, period * 0.75)
                violation = interval < max(0, period - tolerance) or interval > period + tolerance
                if violation:
                    self._last_message_times[sequence_key] = now_ms
                    if self.software_profile_timing_validation_enabled():
                        if interval < max(0, period - tolerance):
                            return (
                                f"message flood rate is too high; observed interval {interval:.1f} ms "
                                f"for a {period} ms message",
                                False,
                            )
                        return (
                            f"observed periodicity {interval:.1f} ms differs from expected {period} ms",
                            False,
                        )
                    self._record_profile_bypass("timing_validation_bypass")
            self._last_message_times[sequence_key] = now_ms
        self._last_message_sequences[sequence_key] = max(
            sequence, previous_sequence or sequence
        )
        return None, replay_accepted

    def _encode_someip_request(self, target, method_id, body):
        request_id = (
            (int(hashlib.sha256(self.NODE_ID.encode()).hexdigest()[:4], 16) << 16)
            | (int(time.time() * 1000) & 0xFFFF)
        )
        return struct.pack(
            "!HHII4B",
            target.SOMEIP_SERVICE_ID,
            method_id,
            len(body) + 8,
            request_id,
            1,
            1,
            0,
            0,
        ) + body

    def build_someip_signal_request(self, target, signal_name):
        if getattr(self, "ROLE", "") != "hpc":
            raise PermissionError("SOME/IP signal requester must be an HPC")
        if getattr(target, "ROLE", "") not in {"hpc", "zone_controller"}:
            raise ValueError("SOME/IP signal target must be an HPC or ZCU")
        if not isinstance(signal_name, str) or not signal_name.strip():
            raise ValueError("signal_name must be a non-empty string")
        body = json.dumps(
            {
                "signal_name": signal_name.strip(),
                "requester_node_id": self.NODE_ID,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        return self._encode_someip_request(target, 0x0100, body).hex().upper()

    def build_someip_sovd_request(self, target, sovd_request):
        if (
            getattr(self, "ROLE", "") != "hpc"
            or getattr(target, "ROLE", "") != "hpc"
            or target.NODE_ID == self.NODE_ID
            or target.NODE_ID not in getattr(self, "BACKBONE_PEERS", ())
        ):
            raise PermissionError("SOME/IP SOVD target must be a registered HPC peer")
        body = json.dumps(
            sovd_request, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        return self._encode_someip_request(target, 0x0101, body).hex().upper()

    def _decode_someip_request(self, packet_hex, service_id, method_id):
        try:
            raw = bytes.fromhex(packet_hex)
            if len(raw) < 16:
                raise ValueError("SOME/IP request header is truncated")
            (
                received_service_id,
                received_method_id,
                length,
                request_id,
                protocol_version,
                interface_version,
                message_type,
                return_code,
            ) = struct.unpack("!HHII4B", raw[:16])
            body = json.loads(raw[16:])
        except (TypeError, ValueError, struct.error, json.JSONDecodeError) as exc:
            raise ValueError("malformed SOME/IP request") from exc
        if (
            received_service_id != service_id
            or received_method_id != method_id
            or length != len(raw) - 8
            or protocol_version != 1
            or interface_version != 1
            or message_type != 0
            or return_code != 0
            or not isinstance(body, dict)
        ):
            raise ValueError("SOME/IP request header does not match the node service")
        return raw, request_id, body

    def _authenticate_someip_hpc(self, requester_id, nodes):
        requester = nodes.get(requester_id)
        if requester is None or getattr(requester, "ROLE", "") != "hpc":
            raise PermissionError("SOME/IP requester must be a registered HPC")
        if requester_id == self.NODE_ID and getattr(self, "ROLE", "") == "hpc":
            return requester
        if getattr(self, "ROLE", "") == "zone_controller":
            connected = self.CONNECTED_TO
            if requester_id not in (
                connected if isinstance(connected, (list, tuple, set)) else [connected]
            ):
                raise PermissionError("requesting HPC is not connected to this ZCU")
        elif getattr(self, "ROLE", "") == "hpc":
            if (
                requester_id not in getattr(self, "BACKBONE_PEERS", ())
                or self.NODE_ID not in getattr(requester, "BACKBONE_PEERS", ())
            ):
                raise PermissionError("requesting HPC is not a SOME/IP peer")
        else:
            raise PermissionError("node does not provide a SOME/IP service")
        return requester

    def handle_someip_signal_request(self, payload, nodes):
        requester_id = payload.get("requester_node_id", "hpc-vehicle")
        self._authenticate_someip_hpc(requester_id, nodes)
        raw, request_id, request_data = self._decode_someip_request(
            payload.get("someip_request_packet_hex"),
            self.SOMEIP_SERVICE_ID,
            0x0100,
        )
        if request_data.get("requester_node_id") != requester_id:
            raise PermissionError("SOME/IP requester identity does not match its packet")
        signal_name = request_data.get("signal_name")
        if not isinstance(signal_name, str) or not signal_name.strip():
            raise ValueError("SOME/IP signal request is missing signal_name")

        aggregated = (
            self.aggregated_zcu_messages()
            if self.NODE_ID == "hpc-vehicle"
            else None
        )
        value = self.handle_signal_request(signal_name, aggregated)
        found = value is not None
        response_data = {
            "found": found,
            "target_node_id": self.NODE_ID,
            "requester_node_id": requester_id,
            "service_id": f"0x{self.SOMEIP_SERVICE_ID:04X}",
            "method_id": "0x0100",
            "transport": "authenticated SOME/IP over TCP",
            "someip_request_packet_hex": raw.hex().upper(),
            **(
                value
                or {
                    "signal_name": signal_name,
                    "error": "signal is not available at this service",
                }
            ),
        }
        response_body = json.dumps(
            response_data, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        response_packet = struct.pack(
            "!HHII4B",
            self.SOMEIP_SERVICE_ID,
            0x0100,
            len(response_body) + 8,
            request_id,
            1,
            1,
            0x80,
            0 if found else 0x01,
        ) + response_body
        response_data["someip_response_packet_hex"] = response_packet.hex().upper()
        return {
            "request_id": payload.get("request_id"),
            "timestamp": int(time.time()),
            "status": "ok",
            "service_response": response_data,
        }

    def handle_someip_sovd_request(self, payload, nodes, transport):
        source_id = payload.get("source_hpc_id")
        source = nodes.get(source_id)
        if (
            getattr(self, "ROLE", "") != "hpc"
            or source is None
            or getattr(source, "ROLE", "") != "hpc"
            or source_id == self.NODE_ID
            or source_id not in getattr(self, "BACKBONE_PEERS", ())
            or self.NODE_ID not in getattr(source, "BACKBONE_PEERS", ())
        ):
            raise PermissionError("SOME/IP SOVD source is not an HPC peer")
        raw, request_id, packet_request = self._decode_someip_request(
            payload.get("someip_packet_hex"),
            self.SOMEIP_SERVICE_ID,
            0x0101,
        )
        sovd_request = payload.get("sovd_request")
        if not isinstance(sovd_request, dict) or packet_request != sovd_request:
            raise ValueError("SOME/IP SOVD payload does not match its request")
        result = self.handle_sovd_request(sovd_request, nodes, transport)
        response_body = json.dumps(
            result, sort_keys=True, separators=(",", ":")
        ).encode("utf-8")
        response_packet = struct.pack(
            "!HHII4B",
            self.SOMEIP_SERVICE_ID,
            0x0101,
            len(response_body) + 8,
            request_id,
            1,
            1,
            0x80,
            0 if result.get("status") == "completed" else 0x01,
        ) + response_body
        return {
            "request_id": payload.get("request_id"),
            "timestamp": int(time.time()),
            "status": "ok",
            "sovd_response": result,
            "someip_response_packet_hex": response_packet.hex().upper(),
        }

ZcuRearLeft.SOMEIP_SERVICE_ID = 0x5103
ZcuRearLeft.CAN_CONTROL_BASE = 0x440
ZcuRearLeft.DOIP_LOGICAL_ADDRESS = 0x3003
ZcuRearLeft.DOIP_ECU_ROUTES = {"ecu-body-rear": "ecu-body-rear"}
ZcuRearLeft.MESSAGE_DEFINITIONS.extend([(f"RearLeftServiceEvent{index:02d}", (20, 50, 100, 250, 500)[index % 5]) for index in range(11, 31)])
