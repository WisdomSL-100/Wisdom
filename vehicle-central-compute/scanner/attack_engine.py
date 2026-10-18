from typing import Any, Dict, List


ATTACK_SCENARIOS: Dict[str, Dict[str, List[str]]] = {
    "flooding": {"zones": [], "domains": [], "roles": ["ecu", "zone_controller", "hpc"]},
    "replay_attack": {"zones": [], "domains": ["powertrain", "adas_camera", "adas_radar"], "roles": []},
    "repudiation": {"zones": [], "domains": ["telematics", "cockpit_compute"], "roles": []},
    "dos": {"zones": ["front_right", "rear_left"], "domains": ["vehicle_backbone"], "roles": ["hpc"]},
    "tampering": {"zones": [], "domains": ["powertrain", "battery_management", "body_control"], "roles": []},
    "spoofing": {"zones": [], "domains": ["telematics", "cockpit_compute"], "roles": []},
    "unauthorized_diagnostics": {"zones": [], "domains": [], "roles": ["ecu", "zone_controller", "hpc"]},
    "cross_zone_access": {"zones": ["front_left", "front_right", "rear_left", "rear_right"], "domains": [], "roles": ["zone_controller"]},
    "invalid_firmware": {"zones": [], "domains": [], "roles": ["ecu", "zone_controller", "hpc"]},
    "ids_auditability_regression": {"zones": [], "domains": [], "roles": ["ecu", "zone_controller", "hpc"]},
}
SEVERITY_LOAD = {"low": 1.2, "medium": 2.0, "high": 3.5, "critical": 5.0}


def create_attack_frames(
    attack_type: str,
    severity: str,
    network_snapshot: Dict[str, Any],
    target_node_ids: List[str] | None = None,
) -> List[Dict[str, Any]]:
    if attack_type not in ATTACK_SCENARIOS:
        raise ValueError(f"Unsupported attack type: {attack_type}")
    if severity not in SEVERITY_LOAD:
        raise ValueError(f"Unsupported severity: {severity}")

    scenario = ATTACK_SCENARIOS[attack_type]
    frames = []
    for node in network_snapshot.get("nodes", []):
        if not isinstance(node, dict) or not isinstance(node.get("id"), str):
            continue
        selected = (
            node.get("zone") in scenario["zones"]
            or node.get("functional_domain") in scenario["domains"]
            or node.get("role") in scenario["roles"]
        )
        if target_node_ids is not None:
            selected = node["id"] in target_node_ids
        if not selected:
            continue

        maximum_rate = node.get("max_message_rate_hz", 500)
        maximum_count = node.get("max_message_count", 64)
        baseline = node.get("baseline_message", {})
        frame = {
            "target_ecu_id": node["id"],
            "attack_type": attack_type,
            "severity": severity,
            "zone": node.get("zone"),
            "source_ecu_id": node.get("connected_to"),
            "claimed_source_ecu_id": node.get("connected_to"),
            "protocol": node.get("protocol"),
            "message_id": node.get("message_id"),
            "sequence": node.get("last_sequence", 1) + 1,
            "message_rate_hz": max(1, int(maximum_rate * 0.5)),
            "message_count": 1,
            "payload_size_bytes": min(node.get("max_payload_bytes", 64), 32),
            "signals": baseline.get("signals", {}),
            "authenticated": True,
            "integrity_valid": True,
            "diagnostic_request": False,
            "connection_count": 1,
        }

        if attack_type == "flooding":
            frame["message_rate_hz"] = int(maximum_rate * SEVERITY_LOAD[severity])
            frame["message_count"] = min(
                512, max(maximum_count, int(maximum_rate * SEVERITY_LOAD[severity]))
            )
        elif attack_type == "dos":
            frame["message_rate_hz"] = int(maximum_rate * SEVERITY_LOAD[severity] * 0.8)
            frame["message_count"] = min(
                512,
                max(
                    maximum_count,
                    int(maximum_rate * SEVERITY_LOAD[severity] * 0.8),
                ),
            )
            frame["connection_count"] = int(64 * SEVERITY_LOAD[severity])
        elif attack_type == "replay_attack":
            frame["sequence"] = node.get("last_sequence", 1)
        elif attack_type == "repudiation":
            frame["authenticated"] = False
            frame["diagnostic_request"] = True
        elif attack_type == "tampering":
            frame["integrity_valid"] = False
            for signal, bounds in node.get("signal_ranges", {}).items():
                if signal in frame["signals"]:
                    frame["signals"] = {**frame["signals"], signal: bounds[1] + 1}
                    break
        elif attack_type == "spoofing":
            frame["claimed_source_ecu_id"] = "ecu-unregistered"
        elif attack_type == "unauthorized_diagnostics":
            frame["diagnostic_request"] = True
            frame["request_bytes"] = [0x34, 0x00, 0x00, 0x00]
        elif attack_type == "cross_zone_access":
            frame["route_violation"] = True
        elif attack_type == "invalid_firmware":
            frame["firmware_signature_valid"] = False
        elif attack_type == "ids_auditability_regression":
            frame["auditability_check"] = True

        frames.append(frame)

    if not frames and target_node_ids is None:
        raise ValueError(f"No vehicle nodes match the {attack_type} scenario")
    return frames