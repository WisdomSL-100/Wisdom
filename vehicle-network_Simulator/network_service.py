import copy
import hashlib
import hmac
import json
import logging
import os
import secrets
import socket
import socketserver
import struct
import threading
import time
from collections import Counter
from typing import Any, Dict
from uuid import uuid4

from flask import Flask, jsonify, request
from ecus.ecu_adas_radar import AdasRadarECU
from ecus.ecu_battery import BatteryManagementECU
from ecus.ecu_body_front import FrontBodyECU
from ecus.ecu_body_rear import RearBodyECU
from ecus.ecu_front_camera import FrontCameraECU
from ecus.ecu_powertrain import PowertrainECU
from ecus.ecu_rear_camera import RearCameraECU
from ecus.ecu_telematics import TelematicsECU
from ecus.hpc_adas import AdasHPC
from ecus.hpc_cockpit import CockpitHPC
from ecus.hpc_vehicle_node import VehicleHPC
from ecus.zcu_front_left import ZcuFrontLeft
from ecus.zcu_front_right import ZcuFrontRight
from ecus.zcu_rear_left import ZcuRearLeft
from ecus.zcu_rear_right import ZcuRearRight

app = Flask(__name__)
PORT = int(os.getenv("PORT", "5001"))
SOCKET_PORT = int(os.getenv("SOCKET_PORT", "6001"))
HPC_INGRESS_HOST = os.getenv("HPC_INGRESS_HOST", "127.0.0.1")
HPC_INGRESS_PORT = int(os.getenv("HPC_INGRESS_PORT", "6002"))
CAN_SOCKET_HOST = os.getenv("CAN_SOCKET_HOST", "127.0.0.1")
CAN_SOCKET_PORT = int(os.getenv("CAN_SOCKET_PORT", "6003"))
DOIP_SOCKET_HOST = os.getenv("DOIP_SOCKET_HOST", "127.0.0.1")
DOIP_SOCKET_PORT = int(os.getenv("DOIP_SOCKET_PORT", "6004"))
ZCU_CAN_SOCKET_PORT = int(os.getenv("ZCU_CAN_SOCKET_PORT", "6003"))
ZCU_HPC_TCP_SOCKET_PORT = int(os.getenv("ZCU_HPC_TCP_SOCKET_PORT", "6004"))
CLOUD_HPC_SOCKET_PORT = int(os.getenv("CLOUD_HPC_SOCKET_PORT", "6005"))
MAX_FRAME_BYTES = 8_388_608
SOCKET_STATUS = "starting"
HPC_INGRESS_STATUS = "starting"
CAN_SOCKET_STATUS = "starting"
DOIP_SOCKET_STATUS = "starting"
ZCU_HPC_TCP_SOCKET_STATUS = "not_applicable"
CLOUD_HPC_SOCKET_STATUS = "not_applicable"
USED_REQUEST_IDS: Dict[str, float] = {}
REQUEST_LOCK = threading.Lock()
ALL_NODE_TYPES = [VehicleHPC, AdasHPC, CockpitHPC, ZcuFrontLeft, ZcuFrontRight, ZcuRearLeft, ZcuRearRight, PowertrainECU, BatteryManagementECU, AdasRadarECU, FrontCameraECU, RearCameraECU, FrontBodyECU, RearBodyECU, TelematicsECU]
NODE_TYPES_BY_ID = {node_type.NODE_ID: node_type for node_type in ALL_NODE_TYPES}
VEHICLE_NODE_ID = os.getenv("VEHICLE_NODE_ID")
if VEHICLE_NODE_ID and VEHICLE_NODE_ID not in NODE_TYPES_BY_ID:
    raise ValueError(f"VEHICLE_NODE_ID is not a registered node: {VEHICLE_NODE_ID}")
NODE_TYPES = (
    [NODE_TYPES_BY_ID[VEHICLE_NODE_ID]]
    if VEHICLE_NODE_ID
    else ALL_NODE_TYPES
)
NODE_INSTANCES = {node_type.NODE_ID: node_type() for node_type in NODE_TYPES}
NODE_REGISTRY = {
    node_type.NODE_ID: node_type.__new__(node_type)
    for node_type in ALL_NODE_TYPES
}
NODE_REGISTRY.update(NODE_INSTANCES)
STARTED_AT = time.monotonic()
SCHEDULER_STOP = threading.Event()
SCHEDULER_THREAD = None
MESSAGE_LOCK = threading.RLock()
PENDING_HPC_MESSAGES: Dict[str, list[Dict[str, Any]]] = {}
ACTIVE_SECURITY_EVENTS: list[Dict[str, Any]] = []
DIAGNOSTIC_ACTIVITY: list[Dict[str, Any]] = []
DIAGNOSTIC_ACTIVITY_LOCK = threading.Lock()
SOCKET_ACTIVITY_EVENTS: list[Dict[str, Any]] = []
SOCKET_ACTIVITY_LOCK = threading.Lock()
NETWORK_VALIDATION_LOCK = threading.RLock()
SCAN_ACTIVITY_PHASE = "idle"
SCAN_ACTIVITY_PHASE_UPDATED_AT = time.time()
ACTIVE_ATTACK_STOP_EVENT = threading.Event()
ACTIVE_ATTACK_LOCK = threading.Lock()
ACTIVE_ATTACK_RUNNING = False
VEHICLE_SERVICE_STATES = {"in_service", "out_of_service"}
VEHICLE_SERVICE_STATE = os.getenv("VEHICLE_SERVICE_STATE", "out_of_service")
GATEWAY_CONFIGURATION_VERSION = os.getenv(
    "GATEWAY_CONFIGURATION_VERSION", "simulator-config-v1"
)
SERVICE_STATE_LOCK = threading.Lock()
if VEHICLE_SERVICE_STATE not in VEHICLE_SERVICE_STATES:
    raise ValueError("VEHICLE_SERVICE_STATE must be in_service or out_of_service")
AUTHORIZED_TEST_SCENARIOS = {
    "flooding": {"zones": ["front_left", "rear_left"], "domains": [], "roles": ["zone_controller"]},
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
AUTHORIZED_TEST_CATEGORIES = {
    "flooding": "periodicity_violation",
    "replay_attack": "replay_detected",
    "repudiation": "invalid_authentication",
    "dos": "denial_of_service",
    "tampering": "signal_out_of_range",
    "spoofing": "invalid_authentication",
    "unauthorized_diagnostics": "diagnostic_access_denied",
    "cross_zone_access": "invalid_route",
    "invalid_firmware": "secure_flash_failure",
    "ids_auditability_regression": "invalid_authentication",
}
SECURITY_LEVEL_POLICY = {
    "hardened": {"maximum_severity": "medium"},
    "elevated": {"maximum_severity": "high"},
    "standard": {"maximum_severity": "critical"},
}
_SEVERITY_RANK = {name: index for index, name in enumerate(("low", "medium", "high", "critical"))}
SECURITY_PROFILE_LOCK = threading.RLock()
SECURITY_PROFILE_PATH = os.getenv("VEHICLE_SECURITY_PROFILE_PATH", "")


def _scenario_matches_node(node_id: str, scenario: Dict[str, Any]) -> bool:
    node = NODES[node_id]
    return (
        node["zone"] in scenario["zones"]
        or node["functional_domain"] in scenario["domains"]
        or node["role"] in scenario["roles"]
    )


def get_node_security_profiles() -> Dict[str, Any]:
    with SECURITY_PROFILE_LOCK:
        profiles = [
            {
                "node_id": node_id,
                "display_name": NODES[node_id]["display_name"],
                "role": NODES[node_id]["role"],
                "zone": NODES[node_id]["zone"],
                "protocol": NODES[node_id]["protocol"],
                "security_level": profile["security_level"],
                "maximum_severity": SECURITY_LEVEL_POLICY[
                    profile["security_level"]
                ]["maximum_severity"],
                "susceptible_attacks": list(profile["susceptible_attacks"]),
            }
            for node_id, profile in sorted(NODE_SECURITY_PROFILES.items())
        ]
    return {
        "security_levels": {
            level: {
                "maximum_severity": values["maximum_severity"],
            }
            for level, values in SECURITY_LEVEL_POLICY.items()
        },
        "attack_types": sorted(AUTHORIZED_TEST_SCENARIOS),
        "nodes": profiles,
    }


def configure_node_security_profile(payload: Dict[str, Any]) -> Dict[str, Any]:
    node_id = payload.get("node_id")
    security_level = payload.get("security_level")
    susceptible_attacks = payload.get("susceptible_attacks")
    if not isinstance(node_id, str) or node_id not in NODE_SECURITY_PROFILES:
        raise ValueError("node_id must identify a registered simulated node")
    if (
        not isinstance(security_level, str)
        or security_level not in SECURITY_LEVEL_POLICY
    ):
        raise ValueError(
            "security_level must be hardened, elevated, or standard"
        )
    if (
        not isinstance(susceptible_attacks, list)
        or any(
            not isinstance(attack_type, str)
            or attack_type not in AUTHORIZED_TEST_SCENARIOS
            for attack_type in susceptible_attacks
        )
        or len(susceptible_attacks) != len(set(susceptible_attacks))
    ):
        raise ValueError("susceptible_attacks must be unique supported attack types")
    with SECURITY_PROFILE_LOCK:
        previous = NODE_SECURITY_PROFILES[node_id]
        NODE_SECURITY_PROFILES[node_id] = {
            "security_level": security_level,
            "susceptible_attacks": sorted(susceptible_attacks),
        }
        try:
            _persist_node_security_profiles()
        except OSError:
            NODE_SECURITY_PROFILES[node_id] = previous
            raise
    return get_node_security_profiles()


def _load_node_security_profiles() -> None:
    if not SECURITY_PROFILE_PATH or not os.path.exists(SECURITY_PROFILE_PATH):
        return
    with open(SECURITY_PROFILE_PATH, encoding="utf-8") as profile_file:
        stored = json.load(profile_file)
    if not isinstance(stored, dict):
        raise ValueError("stored vehicle security profiles must be an object")
    for node_id, profile in stored.items():
        if (
            node_id not in NODE_SECURITY_PROFILES
            or not isinstance(profile, dict)
            or profile.get("security_level") not in SECURITY_LEVEL_POLICY
            or not isinstance(profile.get("susceptible_attacks"), list)
            or any(
                not isinstance(attack_type, str)
                or attack_type not in AUTHORIZED_TEST_SCENARIOS
                for attack_type in profile["susceptible_attacks"]
            )
            or len(profile["susceptible_attacks"])
            != len(set(profile["susceptible_attacks"]))
        ):
            raise ValueError("stored vehicle security profile is invalid")
        NODE_SECURITY_PROFILES[node_id] = {
            "security_level": profile["security_level"],
            "susceptible_attacks": sorted(profile["susceptible_attacks"]),
        }


def _persist_node_security_profiles() -> None:
    if not SECURITY_PROFILE_PATH:
        return
    directory = os.path.dirname(SECURITY_PROFILE_PATH)
    if directory:
        os.makedirs(directory, exist_ok=True)
    temporary_path = f"{SECURITY_PROFILE_PATH}.tmp"
    with open(temporary_path, "w", encoding="utf-8") as profile_file:
        json.dump(NODE_SECURITY_PROFILES, profile_file, sort_keys=True)
        profile_file.write("\n")
    os.replace(temporary_path, SECURITY_PROFILE_PATH)


def socket_secret() -> bytes:
    secret = os.getenv("VEHICLE_SOCKET_SECRET", "").encode("utf-8")
    if len(secret) < 32:
        raise RuntimeError("VEHICLE_SOCKET_SECRET must contain at least 32 bytes")
    return secret


def _message_signal_layout(node_type: Any, index: int, message_name: str) -> Dict[str, Any]:
    signals = getattr(node_type, "SIGNALS", {})
    signal_names = list(signals) or ["heartbeat"]
    source_name = signal_names[index % len(signal_names)]
    value = signals.get(source_name, 0)
    configured_range = getattr(node_type, "SIGNAL_RANGES", {}).get(source_name)
    if isinstance(value, (int, float)) and not isinstance(value, bool):
        encoded_value = int(round(value))
        minimum, maximum = configured_range or (0, max(255, encoded_value))
        encoding = "integer"
    else:
        enum_values = {"offline": 0, "online": 1, "normal": 1, "locked": 1, "unlocked": 2, "active": 1, "inactive": 0}
        encoded_value = enum_values.get(str(value).lower(), 0)
        minimum, maximum = 0, max(1, encoded_value)
        encoding = "enum"
    return {
        "name": f"{message_name}_{source_name}",
        "source_signal": source_name,
        "start_bit": 0,
        "bit_length": 64,
        "byte_order": "big_endian",
        "encoding": encoding,
        "value": value,
        "encoded_value": encoded_value,
        "minimum": minimum,
        "maximum": maximum,
        "unit": "raw",
    }


def _node_spec(node_type: Any) -> Dict[str, Any]:
    fields = ("DISPLAY_NAME", "ZONE", "ROLE", "FUNCTIONAL_DOMAIN", "SAFETY_CRITICAL", "PROTOCOL", "NETWORK_SEGMENT", "CONNECTED_TO", "BACKBONE_PEERS", "AGGREGATES_FROM", "AGGREGATES_ZONES", "TRUSTED_SOURCES", "MESSAGE_ID", "MESSAGE_NAME", "CYCLE_TIME_MS", "SIGNALS", "SIGNAL_RANGES", "MESSAGE_DEFINITIONS", "MAX_MESSAGE_RATE_HZ", "MAX_MESSAGE_COUNT", "MAX_PAYLOAD_BYTES", "UDS_SUPPORTED_SERVICES", "UDS_DIDS", "UDS_RIDS", "SECURE_FEATURES", "DTC_CATALOG", "DOIP_LOGICAL_ADDRESS", "DOIP_ECU_ROUTES")
    defaults = {"ZONE": "central", "ROLE": "ecu", "FUNCTIONAL_DOMAIN": "vehicle_control", "SAFETY_CRITICAL": False, "PROTOCOL": "Automotive Ethernet", "NETWORK_SEGMENT": "vehicle-backbone", "CONNECTED_TO": None, "BACKBONE_PEERS": [], "AGGREGATES_FROM": [], "AGGREGATES_ZONES": [], "TRUSTED_SOURCES": [], "SIGNALS": {}, "SIGNAL_RANGES": {}, "MESSAGE_DEFINITIONS": [], "MAX_MESSAGE_RATE_HZ": 500, "MAX_MESSAGE_COUNT": 64, "MAX_PAYLOAD_BYTES": 64, "UDS_SUPPORTED_SERVICES": [], "UDS_DIDS": {}, "UDS_RIDS": {}, "SECURE_FEATURES": [], "DTC_CATALOG": {}, "DOIP_LOGICAL_ADDRESS": None, "DOIP_ECU_ROUTES": {}}
    spec = {"id": node_type.NODE_ID, **{field.lower(): getattr(node_type, field, defaults.get(field)) for field in fields}}
    spec["flash_transport"] = "can_local" if spec["protocol"] in {"CAN", "CAN-FD"} else "ethernet_ota"
    base_id = int(getattr(node_type, "MESSAGE_ID", "0x100"), 16)
    can_node = spec["protocol"] in {"CAN", "CAN-FD"}
    service_id = getattr(node_type, "SOMEIP_SERVICE_ID", None)
    spec["someip_service_id"] = (
        f"0x{service_id:04X}" if service_id is not None else None
    )
    can_control_base = getattr(node_type, "CAN_CONTROL_BASE", None)
    spec["message_catalog"] = [
        {
            "message_id": f"0x{base_id + index:03X}" if can_node else f"0x{service_id:04X}:{index + 1:04X}",
            "direction": "tx",
            "transport": spec["protocol"],
            "can_id": base_id + index if can_node else None,
            "can_control_id": can_control_base + index if can_control_base is not None else None,
            "someip_service_id": f"0x{service_id:04X}" if service_id is not None else None,
            "someip_method_id": f"0x{index + 1:04X}" if service_id is not None else None,
            "message_name": name,
            "cycle_time_ms": cycle,
            "signal_layout": _message_signal_layout(node_type, index, name),
            "signals": dict(spec["signals"]),
        }
        for index, (name, cycle) in enumerate(spec["message_definitions"])
    ]
    return spec


NODES = {node_type.NODE_ID: _node_spec(node_type) for node_type in ALL_NODE_TYPES}

for receiving_id, receiving_node in NODES.items():
    rx_catalog = []
    for source_id, source_node in NODES.items():
        source_targets = source_node["connected_to"] or []
        source_targets = [source_targets] if isinstance(source_targets, str) else list(source_targets)
        source_transport = source_node["protocol"]
        if source_node["role"] in {"zone_controller", "hpc"}:
            if source_node["role"] == "zone_controller":
                source_targets.extend(
                    node_id for node_id, node_spec in NODES.items()
                    if node_spec["role"] == "ecu" and node_spec["zone"] == source_node["zone"] and not node_spec["safety_critical"]
                )
                source_transport = "CAN-FD"
            else:
                source_targets.extend(
                    node_id for node_id, node_spec in NODES.items()
                    if node_spec["role"] == "ecu" and node_spec["safety_critical"] and node_spec["connected_to"] == source_id
                )
                source_transport = "CAN-FD"
            if receiving_id in source_node["backbone_peers"]:
                source_targets.append(receiving_id)
                source_transport = "Automotive Ethernet SOME/IP"
            if receiving_id in (source_node["connected_to"] or []):
                source_transport = "Automotive Ethernet SOME/IP"
            if receiving_node["role"] == "zone_controller" and source_id in receiving_node["connected_to"]:
                source_targets.append(receiving_id)
                source_transport = "Automotive Ethernet SOME/IP"
        if receiving_id in source_targets:
            for index, message in enumerate(source_node["message_catalog"]):
                rx_id = message["can_control_id"] if source_transport == "CAN-FD" and message["can_control_id"] is not None else message["message_id"]
                rx_catalog.append({**message, "message_id": rx_id, "direction": "rx", "source_node_id": source_id, "transport": source_transport})
    receiving_node["rx_message_catalog"] = rx_catalog

NODE_TRAFFIC_STATS = {
    node_id: {"tx_generated": 0, "tx_delivered": 0, "rx_accepted": 0, "security_event_count": 0}
    for node_id in NODES
}
REMOTE_NODE_SNAPSHOTS: Dict[str, Dict[str, Any]] = {}
REMOTE_SNAPSHOT_REFRESH_LOCK = threading.Lock()
REMOTE_SNAPSHOT_REFRESHED_AT = 0.0
REMOTE_SNAPSHOT_REFRESH_INTERVAL_SECONDS = 0.5
NODE_SECURITY_PROFILES = {
    node_id: {
        "security_level": (
            "hardened"
            if node["role"] == "hpc"
            else "elevated"
            if node["role"] == "zone_controller"
            else "standard"
        ),
        "susceptible_attacks": sorted(
            attack_type
            for attack_type, scenario in AUTHORIZED_TEST_SCENARIOS.items()
            if _scenario_matches_node(node_id, scenario)
        ),
    }
    for node_id, node in NODES.items()
}
_load_node_security_profiles()


def build_topology() -> Dict[str, Any]:
    nodes = list(NODES.values())
    links = []
    for node in nodes:
        parents = node["connected_to"] or []
        for parent in [parents] if isinstance(parents, str) else parents:
            links.append({"source": node["id"], "target": parent, "protocol": node["protocol"], "network_segment": node["network_segment"], "direction": "bidirectional_vehicle_network"})
        for peer in node["backbone_peers"]:
            if node["id"] < peer:
                links.append({"source": node["id"], "target": peer, "protocol": "Automotive Ethernet", "network_segment": "vehicle-backbone", "direction": "bidirectional_backbone_peer"})
    zones = []
    for zone in ("front_left", "front_right", "rear_left", "rear_right"):
        members = [node for node in nodes if node["zone"] == zone]
        zcu = next((node for node in members if node["role"] == "zone_controller"), None)
        domains = zcu["connected_to"] if zcu else []
        zones.append({"zone_id": zone, "zone_controller_id": zcu["id"] if zcu else None, "domain_controller_ids": domains, "node_ids": [node["id"] for node in members]})
    vehicle_hpc = NODES["hpc-vehicle"]
    aggregate_nodes = [node for node in nodes if node["role"] == "zone_controller" or (node["role"] == "ecu" and (node["safety_critical"] or node["zone"] in vehicle_hpc["aggregates_zones"]))]
    aggregate = {"aggregator_id": "hpc-vehicle", "zones": vehicle_hpc["aggregates_zones"], "source_zcu_ids": [node_id for node_id in vehicle_hpc["aggregates_from"] if NODES[node_id]["role"] == "zone_controller"], "direct_safety_ecu_ids": [node_id for node_id in vehicle_hpc["aggregates_from"] if NODES[node_id]["role"] == "ecu" and NODES[node_id]["safety_critical"]], "source_node_ids": [node["id"] for node in aggregate_nodes], "node_count": len(aggregate_nodes), "messages": []}
    role_counts = {}
    protocol_counts = {}
    for node in nodes:
        role_counts[node["role"]] = role_counts.get(node["role"], 0) + 1
        protocol_counts[node["protocol"]] = protocol_counts.get(node["protocol"], 0) + 1
    return {"network_type": "zonal_vehicle_architecture", "node_count": len(nodes), "role_counts": role_counts, "protocol_counts": protocol_counts, "zones": zones, "nodes": nodes, "links": links, "hpc_vehicle_data": aggregate, "integrations": [{"source": "vehicle-network.socket", "target": "vehicle-central-compute.container", "protocol": "TCP socket", "status": "implemented_simulated_authenticated_socket", "data": ["cyclic messages", "topology", "diagnostics", "UDS", "DTCs", "HPC aggregate"]}]}


def signed_content(payload: Dict[str, Any]) -> bytes:
    unsigned = {key: value for key, value in payload.items() if key != "auth"}
    return json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_payload(payload: Dict[str, Any]) -> Dict[str, Any]:
    signed = dict(payload)
    signed["auth"] = hmac.new(socket_secret(), signed_content(signed), hashlib.sha256).hexdigest()
    return signed


def verify_request(payload: Dict[str, Any]) -> bool:
    request_id = payload.get("request_id")
    timestamp = payload.get("timestamp")
    signature = payload.get("auth")
    if not isinstance(request_id, str) or not isinstance(timestamp, int) or not isinstance(signature, str):
        return False
    if abs(int(time.time()) - timestamp) > 30:
        return False
    try:
        expected = hmac.new(socket_secret(), signed_content(payload), hashlib.sha256).hexdigest()
    except RuntimeError:
        return False
    if not hmac.compare_digest(expected, signature):
        return False
    with REQUEST_LOCK:
        now = time.time()
        expired_ids = [key for key, created in USED_REQUEST_IDS.items() if now - created > 60]
        for key in expired_ids:
            USED_REQUEST_IDS.pop(key, None)
        if request_id in USED_REQUEST_IDS:
            return False
        USED_REQUEST_IDS[request_id] = now
    return True


def diagnostics_records(topology: Dict[str, Any]) -> list[Dict[str, Any]]:
    records = []
    for node_id in NODES:
        spec = NODES[node_id]
        remote_snapshot = REMOTE_NODE_SNAPSHOTS.get(node_id)
        node = NODE_INSTANCES.get(node_id)
        if remote_snapshot is not None:
            record = copy.deepcopy(remote_snapshot["diagnostics"])
        elif node is not None:
            record = node.diagnostics()
        else:
            continue
        record.update({
            "zone": spec["zone"],
            "role": spec["role"],
            "safety_critical": spec["safety_critical"],
            "uds_supported_services": spec["uds_supported_services"],
            "uds_dids": spec["uds_dids"],
            "uds_rids": spec["uds_rids"],
            "dtc_catalog": spec["dtc_catalog"],
            "secure_features": spec["secure_features"],
            "flash_transport": spec["flash_transport"],
        })
        record["received_network_messages"] = (
            copy.deepcopy(remote_snapshot.get("received_messages", [])[-20:])
            if remote_snapshot is not None
            else list(getattr(node, "_received_message_history", [])[-20:])
        )
        records.append(record)
    return records


def _seal_node_message(node_id: str, message: Dict[str, Any], secret: bytes) -> None:
    message.pop("auth_tag", None)
    key = hmac.new(
        secret, b"node-message:" + node_id.encode(), hashlib.sha256
    ).digest()
    message["auth_tag"] = hmac.new(
        key,
        json.dumps(message, sort_keys=True, separators=(",", ":")).encode(),
        hashlib.sha256,
    ).hexdigest()


def _encode_wire_message(node_id: str, original: Dict[str, Any], index: int, secret: bytes) -> Dict[str, Any]:
    catalog_entry = NODES[node_id]["message_catalog"][index]
    node = NODE_INSTANCES[node_id]
    message = node.encode_wire_message(original, index, catalog_entry, secret)
    NODE_TRAFFIC_STATS[node_id]["tx_generated"] += 1
    return message


def node_behavior_report() -> list[Dict[str, Any]]:
    software_profile_keys = (
        "security_access_required",
        "message_authentication",
        "replay_protection",
        "freshness_protection",
        "rate_limiting",
        "timing_validation",
        "range_validation",
        "message_id_validation",
        "diagnostic_access_control",
        "zonal_segmentation",
        "firmware_signature_required",
        "anti_downgrade",
        "ids_logging",
    )
    ids_category_fields = {
        "message_flood": "ids_flood_event_count",
        "periodicity_violation": "ids_timing_violation_count",
        "malformed_data": "ids_malformed_data_count",
        "signal_out_of_range": "ids_range_violation_count",
        "can_id_mismatch": "ids_message_id_mismatch_count",
        "invalid_authentication": "ids_authentication_failure_count",
        "freshness_failure": "ids_freshness_failure_count",
        "freshness_protection_bypass": "ids_freshness_failure_count",
        "replay_detected": "ids_replay_failure_count",
        "replay_protection_bypass": "ids_replay_failure_count",
        "message_authentication_bypass": "ids_authentication_failure_count",
        "rate_limiting_bypass": "ids_flood_event_count",
        "timing_validation_bypass": "ids_timing_violation_count",
        "range_validation_bypass": "ids_range_violation_count",
        "message_id_validation_bypass": "ids_message_id_mismatch_count",
        "zonal_segmentation_bypass": "ids_route_policy_bypass_count",
        "diagnostic_access_control_bypass": "ids_diagnostic_access_bypass_count",
        "firmware_signature_bypass": "ids_firmware_signature_bypass_count",
        "downgrade_protection_bypass": "ids_downgrade_protection_bypass_count",
        "ids_logging_bypass": "ids_logging_bypass_count",
        "secure_flash_failure": "ids_secure_flash_failure_count",
        "security_access_failure": "ids_security_access_failure_count",
        "security_access_bypass": "ids_security_access_failure_count",
        "uds_security_access_bypass": "ids_security_access_failure_count",
    }
    ids_counts = {node_id: Counter() for node_id in NODES}
    for event in ACTIVE_SECURITY_EVENTS:
        if not isinstance(event, dict):
            continue
        node_id = event.get("node_id")
        field = ids_category_fields.get(event.get("category"))
        if node_id in ids_counts and field:
            ids_counts[node_id][field] += 1
    records = []
    for node_id, spec in NODES.items():
        node = NODE_INSTANCES.get(node_id)
        profile = getattr(node, "_software_profile", None)
        if not isinstance(profile, dict):
            remote_diagnostics = REMOTE_NODE_SNAPSHOTS.get(node_id, {}).get(
                "diagnostics", {}
            )
            firmware = remote_diagnostics.get("firmware", {})
            profile = firmware.get("software_profile", {})
        profile = profile if isinstance(profile, dict) else {}
        record = {
            "node_id": node_id,
            "tx_catalog_count": len(spec["message_catalog"]),
            "rx_catalog_count": len(spec["rx_message_catalog"]),
            **(
                REMOTE_NODE_SNAPSHOTS.get(node_id, {}).get(
                    "traffic", NODE_TRAFFIC_STATS[node_id]
                )
            ),
            **{
                field: ids_counts[node_id][field]
                for field in ids_category_fields.values()
            },
            "behavior_state": "variation_detected" if NODE_TRAFFIC_STATS[node_id]["security_event_count"] else "within_declared_contract",
            "protocol": spec["protocol"],
        }
        record.update(
            {
                f"software_profile_{key}_enabled": profile.get(key, True)
                for key in software_profile_keys
            }
        )
        records.append(record)
    return records


def _send_internal_socket(
    port: int, payload: Dict[str, Any], host: str = "127.0.0.1"
) -> Dict[str, Any] | None:
    request = {"request_id": uuid4().hex, "timestamp": int(time.time()), **payload}
    try:
        with socket.create_connection((host, port), timeout=3) as connection:
            connection.settimeout(3)
            with connection.makefile("rwb") as stream:
                stream.write(json.dumps(sign_payload(request)).encode() + b"\n")
                stream.flush()
                frame = stream.readline(MAX_FRAME_BYTES + 1)
        if not frame or len(frame) > MAX_FRAME_BYTES:
            return None
        response = json.loads(frame)
        signature = response.pop("auth", None)
        expected = hmac.new(socket_secret(), signed_content(response), hashlib.sha256).hexdigest()
        if response.get("request_id") != request["request_id"] or not isinstance(signature, str) or not hmac.compare_digest(signature, expected):
            return None
        return response
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError):
        return None


def _send_node_socket(node_id: str, payload: Dict[str, Any]) -> Dict[str, Any]:
    if node_id not in NODE_REGISTRY:
        raise ValueError("node socket target is not registered")
    prefix = os.getenv("VEHICLE_NODE_HOST_PREFIX", "vehicle-node-")
    port = int(os.getenv("VEHICLE_NODE_SOCKET_PORT", "6001"))
    routed = os.getenv("VEHICLE_NODE_SOCKET_ROUTING") == "1"
    target_role = NODES[node_id]["role"]
    source_role = NODES.get(VEHICLE_NODE_ID, {}).get("role")
    is_cloud_hpc_request = routed and VEHICLE_NODE_ID is None and target_role == "hpc"
    is_zcu_hpc_request = (
        routed
        and source_role == "zone_controller"
        and target_role == "hpc"
        and payload.get("action") == "zcu_relay"
    )
    is_hpc_zcu_request = (
        routed
        and source_role == "hpc"
        and target_role == "zone_controller"
        and payload.get("action") in {"doip_diagnostic", "doip_diagnostic_batch"}
    )
    if is_cloud_hpc_request and payload.get("action") != "node_snapshot":
        port = CLOUD_HPC_SOCKET_PORT
    elif is_zcu_hpc_request or is_hpc_zcu_request:
        port = ZCU_HPC_TCP_SOCKET_PORT
    response = _send_internal_socket(port, payload, f"{prefix}{node_id}")
    if response is None or response.get("status") != "ok":
        if is_cloud_hpc_request and payload.get("action") != "node_snapshot":
            _record_socket_activity(
                "cloud-hpc-tcp",
                "central-compute",
                node_id,
                "dropped",
                {"message_name": payload.get("action"), "transport_type": "Authenticated TCP"},
                (response or {}).get("message", "Cloud-to-HPC socket is unavailable"),
            )
        raise RuntimeError(
            (response or {}).get("message", f"node socket {node_id} is unavailable")
        )
    data = response.get("data")
    if not isinstance(data, dict):
        raise RuntimeError(f"node socket {node_id} returned an invalid payload")
    if is_cloud_hpc_request:
        _record_socket_activity(
            "cloud-hpc-tcp",
            "central-compute",
            node_id,
            "accepted",
            {"message_name": payload.get("action"), "transport_type": "Authenticated TCP"},
            "Authenticated cloud-to-HPC request completed",
        )
    return data


def _send_controller_can_socket(
    controller_id: str, payload: Dict[str, Any]
) -> Dict[str, Any]:
    if NODES.get(controller_id, {}).get("role") not in {
        "zone_controller",
        "hpc",
    }:
        raise ValueError("CAN socket target must be a registered ZCU or HPC")
    host = f"{os.getenv('VEHICLE_NODE_HOST_PREFIX', 'vehicle-node-')}{controller_id}"
    response = _send_internal_socket(
        ZCU_CAN_SOCKET_PORT,
        payload,
        host,
    )
    if response is None or response.get("status") != "ok":
        raise RuntimeError(
            (response or {}).get(
                "message", f"Controller CAN socket {controller_id} is unavailable"
            )
        )
    data = response.get("data")
    if not isinstance(data, dict):
        raise RuntimeError(f"Controller CAN socket {controller_id} returned invalid data")
    return data


def _send_transport_frame(transport: str, payload: Dict[str, Any]) -> Dict[str, Any] | None:
    ports = {"can": CAN_SOCKET_PORT, "doip": DOIP_SOCKET_PORT}
    if transport not in ports:
        raise ValueError("unsupported vehicle transport")
    return _send_internal_socket(ports[transport], payload)


def _store_received_messages(node_id: str, messages: list[Dict[str, Any]]) -> None:
    node = NODE_INSTANCES[node_id]
    history = getattr(node, "_received_message_history", None)
    if history is None:
        history = []
        node._received_message_history = history
    history.extend(messages)
    del history[:-500]
    NODE_TRAFFIC_STATS[node_id]["rx_accepted"] += len(messages)


def _record_socket_activity(
    socket_id: str,
    source_node_id: str,
    target_node_id: str,
    action: str,
    message: Dict[str, Any] | None = None,
    detail: str = "",
) -> Dict[str, Any]:
    message = message if isinstance(message, dict) else {}
    can_frame = message.get("can_frame")
    if not isinstance(can_frame, dict):
        can_frame = {}
    role_prefix = (
        "zcu"
        if socket_id.startswith("zone_controller-can")
        else "hpc"
        if socket_id.startswith("hpc-can")
        else None
    )
    if role_prefix:
        socket_id = f"{role_prefix}-can"
    elif socket_id.startswith("zcu-hpc-tcp"):
        socket_id = "zcu-hpc-tcp"
    elif socket_id.startswith("hpc-peer-tcp"):
        socket_id = "hpc-peer-tcp"
    event = {
        "event_id": uuid4().hex,
        "timestamp": time.time(),
        "event_type": (
            "attack_marker"
            if action == "simulated_marker_only"
            else "socket_frame"
        ),
        "socket_id": socket_id,
        "phase": message.get("phase", SCAN_ACTIVITY_PHASE),
        "attack_generated": message.get("attack_generated") is True,
        "attack_type": message.get("attack_type"),
        "source_node_id": source_node_id,
        "target_node_id": target_node_id,
        "action": action,
        "transport_type": message.get("transport_type", "CAN/CAN-FD"),
        "message_name": message.get("message_name"),
        "message_id": message.get("message_id"),
        "can_id": can_frame.get("can_id"),
        "can_id_hex": can_frame.get("can_id_hex"),
        "dlc": can_frame.get("dlc"),
        "data_hex": can_frame.get("data_hex"),
        "someip_service_id": message.get("someip", {}).get("service_id")
        if isinstance(message.get("someip"), dict)
        else None,
        "someip_method_id": message.get("someip", {}).get("method_or_event_id")
        if isinstance(message.get("someip"), dict)
        else None,
        "packet_length": message.get("someip", {}).get("length")
        if isinstance(message.get("someip"), dict)
        else None,
        "packet_hex": (
            message.get("someip", {}).get("packet_hex")
            if isinstance(message.get("someip"), dict)
            else message.get("doip_packet_hex")
        ),
        "message_length_bytes": message.get("message_length_bytes"),
        "frame_index": message.get("frame_index"),
        "frame_count": message.get("frame_count"),
        "firmware_version": message.get("firmware_version"),
        "update_framework": message.get("update_framework"),
        "previous_partition": message.get("previous_partition"),
        "active_partition": message.get("active_partition"),
        "detail": detail,
    }
    with SOCKET_ACTIVITY_LOCK:
        SOCKET_ACTIVITY_EVENTS.append(event)
        if len(SOCKET_ACTIVITY_EVENTS) > 1000:
            priority = [
                item for item in SOCKET_ACTIVITY_EVENTS
                if item.get("attack_generated") is True
                or item.get("phase") == "ota"
                or item.get("event_type") == "attack_marker"
            ][-300:]
            keep = {id(item) for item in priority}
            regular = [
                item for item in SOCKET_ACTIVITY_EVENTS if id(item) not in keep
            ][-(1000 - len(priority)):]
            kept = {id(item) for item in regular} | keep
            SOCKET_ACTIVITY_EVENTS[:] = [
                item for item in SOCKET_ACTIVITY_EVENTS if id(item) in kept
            ]
    return event


def _uds_service_label(request_bytes: list[int] | bytes) -> str:
    if not request_bytes:
        return "UDS"
    service_names = {
        0x10: "DiagnosticSessionControl",
        0x11: "ECUReset",
        0x14: "ClearDiagnosticInformation",
        0x19: "ReadDTCInformation",
        0x22: "ReadDataByIdentifier",
        0x27: "SecurityAccess",
        0x28: "CommunicationControl",
        0x31: "RoutineControl",
        0x34: "RequestDownload",
        0x36: "TransferData",
        0x37: "RequestTransferExit",
        0x3E: "TesterPresent",
        0x85: "ControlDTCSetting",
    }
    service_id = request_bytes[0]
    if service_id == 0x7F and len(request_bytes) > 1:
        service_id = request_bytes[1]
    elif 0x40 <= service_id <= 0x7E:
        service_id -= 0x40
    return service_names.get(service_id, f"UDS 0x{service_id:02X}")


def _record_doip_socket_activity(
    source_id: str,
    zcu_id: str,
    target_id: str,
    packet_hex: str,
    action: str,
    context: Dict[str, Any] | None = None,
    detail: str = "",
    phase: str | None = None,
) -> None:
    try:
        packet = bytes.fromhex(packet_hex)
    except ValueError:
        packet = b""
    uds_payload = packet[12:] if len(packet) >= 12 else b""
    _record_socket_activity(
        "zcu-hpc-tcp",
        source_id,
        zcu_id,
        action,
        {
            "phase": "ota" if phase == "ota" else phase or SCAN_ACTIVITY_PHASE,
            "attack_generated": phase == "attack",
            "message_name": "DoIP UDS request / response",
            "message_id": _uds_service_label(uds_payload),
            "transport_type": "DoIP over authenticated TCP",
            "doip_packet_hex": packet_hex,
            "message_length_bytes": len(uds_payload),
        },
        detail or f"DoIP target {target_id}; {_uds_service_label(uds_payload)}",
    )


def _record_someip_socket_activity(
    source_id: str,
    target_id: str,
    packet_hex: str,
    action: str,
    detail: str,
) -> None:
    packet = bytes.fromhex(packet_hex)
    if len(packet) < 16:
        raise ValueError("SOME/IP socket activity packet is truncated")
    service_id, method_id = struct.unpack("!HH", packet[:4])
    socket_id = (
        "zcu-hpc-tcp"
        if any(
            NODES.get(node_id, {}).get("role") == "zone_controller"
            for node_id in (source_id, target_id)
        )
        else "cloud-hpc-tcp"
    )
    _record_socket_activity(
        socket_id,
        source_id,
        target_id,
        action,
        {
            "phase": "diagnostic",
            "message_name": "SOME/IP signal service",
            "message_id": f"service 0x{service_id:04X} method 0x{method_id:04X}",
            "transport_type": "Authenticated SOME/IP over TCP",
            "someip": {
                "service_id": f"0x{service_id:04X}",
                "method_or_event_id": f"0x{method_id:04X}",
                "length": int.from_bytes(packet[4:8], "big"),
                "packet_hex": packet_hex,
            },
        },
        detail,
    )


def _record_hpc_ota_socket_activity(
    target_id: str,
    package: Dict[str, Any],
    action: str,
    result: Dict[str, Any] | None = None,
    detail: str = "",
) -> None:
    manifest = package.get("manifest")
    manifest = manifest if isinstance(manifest, dict) else {}
    previous_partition = (
        result.get("previous_partition") if isinstance(result, dict) else None
    )
    active_partition = (
        result.get("active_partition") if isinstance(result, dict) else None
    )
    version = manifest.get("version")
    size = manifest.get("image_size")
    message = {
        "phase": "ota",
        "attack_generated": package.get("attack_generated") is True,
        "message_name": "HPC A/B OTA update",
        "message_id": "A/B partition swap",
        "transport_type": "Authenticated TCP / JSON Lines",
        "update_framework": (
            result.get("update_framework", "A/B partition swap")
            if isinstance(result, dict)
            else "A/B partition swap"
        ),
    }
    if isinstance(version, str):
        message["firmware_version"] = version
    if type(size) is int:
        message["message_length_bytes"] = size
    if isinstance(previous_partition, str):
        message["previous_partition"] = previous_partition
    if isinstance(active_partition, str):
        message["active_partition"] = active_partition
    if isinstance(detail, str):
        detail = detail[:500]
    _record_socket_activity(
        "cloud-hpc-tcp",
        "central-compute",
        target_id,
        action,
        message,
        detail
        or (
            f"{action}: version {version or 'unknown'}; "
            f"image size {size if type(size) is int else 'unknown'} bytes; "
            f"status {result.get('status', 'unknown') if isinstance(result, dict) else 'pending'}"
        ),
    )


def _isotp_payload_frames(payload: list[int]) -> list[bytes]:
    if not payload or len(payload) > 4095 or any(
        type(value) is not int or not 0 <= value <= 0xFF for value in payload
    ):
        raise ValueError("UDS CAN payload must contain 1 to 4095 bytes")
    if len(payload) <= 7:
        frame_data = bytes([len(payload), *payload])
        return [frame_data.ljust(8, b"\x00")]
    frames = [
        bytes([0x10 | (len(payload) >> 8), len(payload) & 0xFF, *payload[:6]]).ljust(
            8, b"\x00"
        )
    ]
    offset = 6
    sequence = 1
    while offset < len(payload):
        chunk = payload[offset : offset + 7]
        frames.append(bytes([0x20 | (sequence & 0x0F), *chunk]).ljust(8, b"\x00"))
        offset += len(chunk)
        sequence += 1
    return frames


def _record_uds_can_exchange(
    controller_id: str,
    ecu_id: str,
    request_bytes: list[int],
    response_bytes: list[int],
) -> None:
    ecu_ids = [
        node_id for node_id, spec in NODES.items() if spec["role"] == "ecu"
    ]
    ecu_index = ecu_ids.index(ecu_id)
    exchanges = (
        (controller_id, ecu_id, 0x7E0 + ecu_index, request_bytes, "request"),
        (ecu_id, controller_id, 0x7E8 + ecu_index, response_bytes, "response"),
    )
    for source_id, target_id, can_id, payload, direction in exchanges:
        frames = _isotp_payload_frames(payload)
        for frame_index, frame_data in enumerate(frames, start=1):
            message = {
                "message_name": f"UDS {direction}",
                "message_id": f"0x{can_id:03X}",
                "transport_type": f"UDS over {NODES[ecu_id]['protocol']}",
                "message_length_bytes": len(payload),
                "frame_index": frame_index,
                "frame_count": len(frames),
                "can_frame": {
                    "can_id": can_id,
                    "can_id_hex": f"0x{can_id:03X}",
                    "dlc": len(frame_data),
                    "data_hex": frame_data.hex().upper(),
                },
            }
            _record_socket_activity(
                (
                    "zcu-can"
                    if NODES[controller_id]["role"] == "zone_controller"
                    else "hpc-can"
                ),
                source_id,
                target_id,
                "accepted",
                message,
                f"ISO-TP UDS {direction} frame {frame_index}/{len(frames)}; "
                f"UDS message length {len(payload)} bytes",
            )


def _raise_security_event(source_id: str, observed_at: str, category: str, detail: str, message: Dict[str, Any] | None = None, action: str = "dropped") -> Dict[str, Any]:
    observer = NODE_REGISTRY.get(observed_at)
    if (
        observer is not None
        and not observer.software_profile_ids_logging_enabled()
    ):
        return {
            "event_id": uuid4().hex,
            "timestamp": time.time(),
            "node_id": source_id,
            "detected_at_node_id": observed_at,
            "category": category,
            "event_type": "ids_alert",
            "severity": "medium",
            "detail": detail,
            "action": action,
            "hierarchy_route": [],
            "message_name": message.get("message_name") if isinstance(message, dict) else None,
            "observed_message_id": message.get("message_id") if isinstance(message, dict) else None,
            "suppressed_by_node_profile": True,
        }
    source = NODES.get(source_id, {})
    parent = source.get("connected_to")
    if isinstance(parent, list):
        parent = parent[0] if parent else None
    if source.get("role") == "ecu" and source.get("safety_critical"):
        route = [parent] if parent else []
    elif source.get("role") == "ecu":
        route = [parent, "hpc-vehicle"] if parent else ["hpc-vehicle"]
    elif source.get("role") == "zone_controller":
        route = [source_id, "hpc-vehicle"]
    else:
        route = [source_id]
    event = {
        "event_id": uuid4().hex,
        "timestamp": time.time(),
        "node_id": source_id,
        "detected_at_node_id": observed_at,
        "category": category,
        "event_type": "ids_alert",
        "severity": (
            "critical"
            if category in {"secure_flash_failure", "security_access_bypass"}
            else "high"
            if category
            in {
                "invalid_authentication",
                "can_id_mismatch",
                "someip_header_mismatch",
                "freshness_failure",
                "freshness_protection_bypass",
                "replay_detected",
                "security_access_failure",
                "message_authentication_bypass",
                "rate_limiting_bypass",
                "timing_validation_bypass",
                "range_validation_bypass",
                "message_id_validation_bypass",
                "zonal_segmentation_bypass",
                "diagnostic_access_control_bypass",
                "firmware_signature_bypass",
                "downgrade_protection_bypass",
            }
            else "medium"
        ),
        "detail": detail,
        "action": action,
        "hierarchy_route": [node_id for node_id in route if node_id],
        "message_name": message.get("message_name") if isinstance(message, dict) else None,
        "observed_message_id": message.get("message_id") if isinstance(message, dict) else None,
    }
    if source_id in NODE_TRAFFIC_STATS:
        NODE_TRAFFIC_STATS[source_id]["security_event_count"] += 1
    ACTIVE_SECURITY_EVENTS.append(event)
    del ACTIVE_SECURITY_EVENTS[:-2000]
    for route_node_id in event["hierarchy_route"]:
        if route_node_id in NODE_INSTANCES:
            local_events = getattr(NODE_INSTANCES[route_node_id], "_security_event_history", None)
            if local_events is None:
                local_events = []
                NODE_INSTANCES[route_node_id]._security_event_history = local_events
            local_events.append(event)
            del local_events[:-500]
    return event


def _catalog_entry(source_id: str, message: Dict[str, Any]) -> tuple[int, Dict[str, Any]] | None:
    for index, entry in enumerate(NODES.get(source_id, {}).get("message_catalog", [])):
        if entry["message_name"] == message.get("message_name"):
            return index, entry
    return None


def _verify_node_signature(source_id: str, message: Dict[str, Any]) -> bool:
    node = NODE_REGISTRY.get(source_id)
    if node is None:
        return False
    try:
        return node.verify_network_message(message, socket_secret())
    except RuntimeError:
        return False


def _validation_failure_category(reason: str) -> str:
    lowered = reason.lower()
    if "flood" in lowered or "rate exceeds" in lowered:
        return "message_flood"
    if "freshness" in lowered or "stale" in lowered or "clock skew" in lowered:
        return "freshness_failure"
    if "replay" in lowered or "out-of-order" in lowered:
        return "replay_detected"
    if "periodicity" in lowered or "periodic" in lowered or "timing" in lowered:
        return "periodicity_violation"
    if "malformed" in lowered or "invalid data" in lowered or "payload length" in lowered:
        return "malformed_data"
    if "signal" in lowered or "threshold" in lowered or "range" in lowered:
        return "signal_out_of_range"
    if "identifier" in lowered or "can id" in lowered:
        return "can_id_mismatch"
    if "authentication" in lowered or "signature" in lowered or "auth tag" in lowered:
        return "invalid_authentication"
    if "some/ip" in lowered or "packet" in lowered or "header" in lowered:
        return "someip_header_mismatch"
    return "invalid_route"


def _record_uds_security_result(
    node_id: str, source_id: str | None, result: Dict[str, Any]
) -> None:
    service = result.get("service")
    if service == "0x27":
        if result.get("positive_response") is True and result.get("security_bypass"):
            _raise_security_event(
                node_id,
                node_id,
                "security_access_bypass",
                "Node accepted SecurityAccess without verifying the requested key.",
                {"message_name": "SecurityAccess"},
                action="accepted",
            )
        elif result.get("positive_response") is not True:
            _raise_security_event(
                source_id or node_id,
                node_id,
                "security_access_failure",
                "Node rejected a UDS SecurityAccess attempt.",
                {"message_name": "SecurityAccess"},
            )
    if (
        service in {"0x34", "0x36", "0x37"}
        and result.get("positive_response") is not True
    ):
        _raise_security_event(
            source_id or node_id,
            node_id,
            "secure_flash_failure",
            "Node rejected a secure firmware transfer request.",
            {"message_name": result.get("service_name", "FirmwareTransfer")},
        )
    bypass_details = {
        "message_authentication_bypass": "Node accepted a message without message authentication.",
        "rate_limiting_bypass": "Node accepted traffic without per-node rate limiting.",
        "timing_validation_bypass": "Node accepted traffic without timing validation.",
        "range_validation_bypass": "Node accepted an out-of-range signal value.",
        "message_id_validation_bypass": "Node accepted a message with an unvalidated identifier.",
        "zonal_segmentation_bypass": "Node accepted a request outside its zonal route policy.",
        "diagnostic_access_control_bypass": "Node accepted a protected diagnostic request without authorization.",
        "firmware_signature_bypass": "Node accepted a firmware image without a valid signature.",
        "downgrade_protection_bypass": "Node accepted a firmware downgrade.",
    }
    for category in result.get("security_bypasses", []):
        detail = bypass_details.get(category)
        if detail:
            _raise_security_event(
                node_id,
                node_id,
                category,
                detail,
                {"message_name": result.get("service_name", "UDS")},
                action="accepted",
            )
    activated_profile = result.get("firmware", {}).get("software_profile", {})
    if (
        service in {"0x37", None}
        and isinstance(activated_profile, dict)
        and activated_profile.get("ids_logging") is False
    ):
        _raise_security_event(
            node_id,
            "network_service",
            "ids_logging_bypass",
            "OTA installed software with node-local IDS logging disabled.",
            {"message_name": "RequestTransferExit"},
            action="accepted",
        )


def _validate_message(source_id: str, message: Dict[str, Any], transport: str, receiver_id: str, check_periodicity: bool = True, sequence_scope: str = "default") -> str | None:
    if source_id not in NODES or receiver_id not in NODES:
        return "unknown or mismatched source node"
    if not isinstance(message, dict):
        return "malformed message data: message must be an object"
    try:
        with NETWORK_VALIDATION_LOCK:
            entry_match = _catalog_entry(source_id, message)
            if entry_match is None:
                return "message name is not declared by the transmitting node"
            _, expected = entry_match
            source_node = NODE_REGISTRY[source_id]
            reason, replay_accepted = source_node.validate_network_message(
                message,
                expected,
                transport,
                receiver_id,
                NODES[receiver_id],
                socket_secret(),
                check_periodicity,
                sequence_scope,
            )
            freshness_bypass_accepted = getattr(
                source_node, "_freshness_protection_bypass_accepted", False
            )
            profile_bypasses = list(
                getattr(source_node, "_accepted_profile_bypasses", ())
            )
    except (AttributeError, KeyError, TypeError, ValueError, struct.error) as exc:
        return f"malformed message data: {exc}"
    if replay_accepted and not reason:
        _raise_security_event(
            source_id,
            receiver_id,
            "replay_detected",
            "OTA-installed software accepted a replay because replay protection is disabled",
            message,
            action="accepted",
        )
    if freshness_bypass_accepted and not reason:
        _raise_security_event(
            source_id,
            receiver_id,
            "freshness_protection_bypass",
            "OTA-installed software accepted a message without valid freshness protection",
            message,
            action="accepted",
        )
    bypass_details = {
        "message_authentication_bypass": "OTA-installed software accepted a message without authentication.",
        "rate_limiting_bypass": "OTA-installed software accepted traffic without rate limiting.",
        "timing_validation_bypass": "OTA-installed software accepted traffic without timing validation.",
        "range_validation_bypass": "OTA-installed software accepted an out-of-range signal value.",
        "message_id_validation_bypass": "OTA-installed software accepted a message with an unvalidated identifier.",
        "zonal_segmentation_bypass": "OTA-installed software accepted a message outside its zonal route policy.",
    }
    if not reason:
        for category in profile_bypasses:
            if category in {"freshness_protection_bypass", "replay_protection_bypass"}:
                continue
            detail = bypass_details.get(category)
            if detail:
                _raise_security_event(
                    source_id,
                    receiver_id,
                    category,
                    detail,
                    message,
                    action="accepted",
                )
    return reason


def _encode_service_relay(relay_node_id: str, original: Dict[str, Any], index: int, secret: bytes, relay_role: str) -> Dict[str, Any]:
    return NODE_INSTANCES[relay_node_id].encode_service_relay(
        original, index, secret, relay_role
    )


def _encode_zcu_relay(zcu_id: str, original: Dict[str, Any], index: int, secret: bytes) -> Dict[str, Any]:
    return _encode_service_relay(zcu_id, original, index, secret, "zcu")


def _refresh_remote_node_snapshots() -> None:
    if VEHICLE_NODE_ID is not None:
        return
    global REMOTE_SNAPSHOT_REFRESHED_AT
    if (
        REMOTE_NODE_SNAPSHOTS
        and time.monotonic() - REMOTE_SNAPSHOT_REFRESHED_AT
        < REMOTE_SNAPSHOT_REFRESH_INTERVAL_SECONDS
    ):
        return

    with REMOTE_SNAPSHOT_REFRESH_LOCK:
        if (
            REMOTE_NODE_SNAPSHOTS
            and time.monotonic() - REMOTE_SNAPSHOT_REFRESHED_AT
            < REMOTE_SNAPSHOT_REFRESH_INTERVAL_SECONDS
        ):
            return
        for node_id in NODES:
            snapshot = _send_node_socket(node_id, {"action": "node_snapshot"})
            if snapshot.get("node_id") != node_id:
                raise RuntimeError(
                    f"Node socket {node_id} returned a mismatched snapshot identity"
                )
            if not isinstance(snapshot.get("diagnostics"), dict) or not isinstance(
                snapshot.get("uds_diagnostics"), dict
            ):
                raise RuntimeError(
                    f"Node socket {node_id} returned an invalid snapshot"
                )
            REMOTE_NODE_SNAPSHOTS[node_id] = snapshot
            traffic = snapshot.get("traffic")
            if isinstance(traffic, dict):
                NODE_TRAFFIC_STATS[node_id].update(traffic)
            for event in snapshot.get("security_events", []):
                if isinstance(event, dict) and event.get("event_id") not in {
                    existing.get("event_id") for existing in ACTIVE_SECURITY_EVENTS
                }:
                    ACTIVE_SECURITY_EVENTS.append(event)
        del ACTIVE_SECURITY_EVENTS[:-2000]
        REMOTE_SNAPSHOT_REFRESHED_AT = time.monotonic()


def poll_node_messages() -> None:
    if VEHICLE_NODE_ID is None and os.getenv("VEHICLE_NODE_SOCKET_ROUTING") == "1":
        _refresh_remote_node_snapshots()
        return
    now_ms = (time.monotonic() - STARTED_AT) * 1000
    secret = socket_secret()
    emitted_by_node = {}
    with MESSAGE_LOCK:
        for node_id, node in NODE_INSTANCES.items():
            emitted_by_node[node_id] = [_encode_wire_message(node_id, message, index, secret) for index, message in enumerate(node.emit_due_messages(now_ms, secret))]
    for hpc_id in ("hpc-vehicle", "hpc-adas", "hpc-cockpit"):
        PENDING_HPC_MESSAGES[hpc_id] = emitted_by_node[hpc_id]
    for source_id, node in NODE_INSTANCES.items():
        source_spec = NODES[source_id]
        can_frames = []
        if source_spec["protocol"] in {"CAN", "CAN-FD"}:
            can_frames.extend(emitted_by_node[source_id])
        elif source_spec["role"] in {"zone_controller", "hpc"}:
            if source_spec["role"] == "zone_controller":
                targets = [node_id for node_id, spec in NODES.items() if spec["role"] == "ecu" and spec["zone"] == source_spec["zone"] and not spec["safety_critical"]]
            else:
                targets = [node_id for node_id, spec in NODES.items() if spec["role"] == "ecu" and spec["safety_critical"] and spec["connected_to"] == source_id]
            for index, message in enumerate(emitted_by_node[source_id]):
                for target_id in targets:
                    command = dict(message)
                    can_id = NODES[source_id]["message_catalog"][index]["can_control_id"]
                    command.update({"recipient_node_ids": [target_id], "transport_type": "CAN-FD", "message_id": f"0x{can_id:03X}", "can_frame": {"can_id": can_id, "can_id_hex": f"0x{can_id:03X}", "dlc": 8, "data_hex": message["signal_payload_hex"]}})
                    _seal_node_message(source_id, command, secret)
                    can_frames.append(command)
        if can_frames:
            response = _send_internal_socket(CAN_SOCKET_PORT, {"action": "can_frames", "source_node_id": source_id, "frames": can_frames})
            if response and response.get("status") == "ok":
                for delivery in response.get("delivered", []):
                    _store_received_messages(delivery["node_id"], delivery["messages"])

    for node_id, node in NODE_INSTANCES.items():
        if getattr(node, "ROLE", "") != "zone_controller":
            continue
        zone_messages = list(emitted_by_node[node_id])
        zone = NODES[node_id]["zone"]
        for child_id in NODE_INSTANCES:
            if NODES[child_id]["role"] == "ecu" and NODES[child_id]["zone"] == zone and not NODES[child_id]["safety_critical"]:
                zone_messages.extend(emitted_by_node[child_id])
        relayed = [
            node.encode_service_relay(message, index, secret, "zcu")
            for index, message in enumerate(zone_messages)
        ]
        hpc_messages = [message for hpc_id in node.CONNECTED_TO if hpc_id in PENDING_HPC_MESSAGES for message in PENDING_HPC_MESSAGES[hpc_id]]
        if relayed or hpc_messages:
            node.send_messages_to_hpc(relayed, HPC_INGRESS_HOST, HPC_INGRESS_PORT, secret, hpc_messages)


def recent_node_messages(limit: int = 500) -> list[Dict[str, Any]]:
    if VEHICLE_NODE_ID is None and os.getenv("VEHICLE_NODE_SOCKET_ROUTING") == "1":
        _refresh_remote_node_snapshots()
        messages = [
            message
            for snapshot in REMOTE_NODE_SNAPSHOTS.values()
            for message in snapshot.get("recent_messages", [])
        ]
    else:
        messages = [
            message
            for node in NODE_INSTANCES.values()
            for message in node._message_history
        ]
    return sorted(messages, key=lambda message: message["sampled_at_monotonic_ms"])[-limit:]


def active_dtcs() -> list[Dict[str, Any]]:
    if VEHICLE_NODE_ID is None and os.getenv("VEHICLE_NODE_SOCKET_ROUTING") == "1":
        _refresh_remote_node_snapshots()
    return [
        {"node_id": node_id, **dtc}
        for node_id in NODES
        for dtc in (
            REMOTE_NODE_SNAPSHOTS.get(node_id, {}).get("diagnostics")
            or NODE_INSTANCES[node_id].diagnostics()
        )["active_dtcs"]
    ]


def uds_diagnostics() -> list[Dict[str, Any]]:
    if VEHICLE_NODE_ID is None and os.getenv("VEHICLE_NODE_SOCKET_ROUTING") == "1":
        _refresh_remote_node_snapshots()
        return [
            copy.deepcopy(snapshot["uds_diagnostics"])
            for _, snapshot in sorted(REMOTE_NODE_SNAPSHOTS.items())
        ]
    return [node.uds_diagnostics() for node in NODE_INSTANCES.values()]


def _recent_socket_activity(limit: int) -> list[Dict[str, Any]]:
    activity = list(SOCKET_ACTIVITY_EVENTS)
    if os.getenv("VEHICLE_NODE_SOCKET_ROUTING") == "1":
        for snapshot in REMOTE_NODE_SNAPSHOTS.values():
            activity.extend(snapshot.get("socket_activity", []))
    events = {
        event.get("event_id"): event
        for event in activity
        if isinstance(event, dict) and isinstance(event.get("event_id"), str)
    }
    sorted_events = sorted(
        events.values(),
        key=lambda event: event.get("timestamp", 0),
    )
    priority_events = [
        event
        for event in sorted_events
        if event.get("attack_generated") is True
        or event.get("phase") == "ota"
        or event.get("event_type") == "attack_marker"
    ][-(limit * 3 // 4):]
    remaining = limit - len(priority_events)
    regular_events = [
        event
        for event in sorted_events
        if event.get("attack_generated") is not True
        and event.get("phase") != "ota"
        and event.get("event_type") != "attack_marker"
    ][-remaining:] if remaining else []
    return [
        {key: value for key, value in event.items() if key != "packet_hex"}
        for event in sorted(
            [*regular_events, *priority_events],
            key=lambda event: event.get("timestamp", 0),
        )
    ]


def _socket_id_for_node(node_id: str | None) -> str:
    spec = NODES.get(node_id or "")
    if spec is None:
        return "cloud-hpc-tcp"
    if spec["role"] == "ecu":
        parent_id = spec["connected_to"]
        return (
            "hpc-can"
            if NODES.get(parent_id, {}).get("role") == "hpc"
            else "zcu-can"
        )
    if spec["role"] == "zone_controller":
        return "zcu-hpc-tcp"
    return "cloud-hpc-tcp"


def network_observability() -> Dict[str, Any]:
    poll_node_messages()
    routed = os.getenv("VEHICLE_NODE_SOCKET_ROUTING") == "1"

    def controller_status(role: str, status_key: str) -> str:
        controller_ids = [
            node_id for node_id, spec in NODES.items() if spec["role"] == role
        ]
        statuses = [
            REMOTE_NODE_SNAPSHOTS.get(node_id, {}).get(status_key, "unavailable")
            for node_id in controller_ids
        ]
        if statuses and all(status == "listening" for status in statuses):
            return "listening"
        if any(status == "listening" for status in statuses):
            return "partially listening"
        return "unavailable" if routed else "in-process simulation"

    zcu_hpc_statuses = [
        REMOTE_NODE_SNAPSHOTS.get(node_id, {}).get(
            "zcu_hpc_tcp_socket_status", "unavailable"
        )
        for node_id, spec in NODES.items()
        if spec["role"] in {"zone_controller", "hpc"}
    ]
    zcu_hpc_status = (
        "listening"
        if zcu_hpc_statuses and all(status == "listening" for status in zcu_hpc_statuses)
        else "partially listening"
        if any(status == "listening" for status in zcu_hpc_statuses)
        else "unavailable"
        if routed
        else "in-process simulation"
    )

    socket_endpoints = [
        {
            "socket_id": "zcu-can",
            "name": "ZCU CAN socket",
            "service": "vehicle-node-zcu-*",
            "transport": "TCP / authenticated CAN frame envelope",
            "protocols": ["CAN", "CAN-FD", "UDS"],
            "host": "ZCU node containers",
            "port": ZCU_CAN_SOCKET_PORT,
            "status": controller_status("zone_controller", "can_socket_status"),
            "direction": "Local non-safety ECU <-> owning ZCU",
            "security": "HMAC-authenticated frame envelope, CAN-ID/DLC/payload and route validation",
        },
        {
            "socket_id": "hpc-can",
            "name": "HPC CAN socket",
            "service": "vehicle-node-hpc-*",
            "transport": "TCP / authenticated CAN frame envelope",
            "protocols": ["CAN", "CAN-FD", "UDS"],
            "host": "HPC node containers",
            "port": ZCU_CAN_SOCKET_PORT,
            "status": controller_status("hpc", "can_socket_status"),
            "direction": "Local safety-critical ECU <-> owning HPC",
            "security": "HMAC-authenticated frame envelope, CAN-ID/DLC/payload and route validation",
        },
        {
            "socket_id": "zcu-hpc-tcp",
            "name": "HPC-ZCU TCP socket",
            "service": "vehicle-node-hpc-*",
            "transport": "Authenticated TCP / JSON Lines",
            "protocols": ["SOME/IP", "DoIP relay"],
            "host": "HPC node containers",
            "port": ZCU_HPC_TCP_SOCKET_PORT,
            "status": zcu_hpc_status,
            "direction": "Connected ZCU <-> HPC",
            "security": "HMAC-authenticated relay with ZCU authorization and SOME/IP validation",
        },
        {
            "socket_id": "cloud-hpc-tcp",
            "name": "Cloud-HPC socket",
            "service": "vehicle-node-hpc-*",
            "transport": "Authenticated TCP / JSON Lines",
            "protocols": ["UDS", "OTA", "SOME/IP", "SOVD", "diagnostics"],
            "host": "HPC node containers",
            "port": CLOUD_HPC_SOCKET_PORT,
            "status": controller_status("hpc", "cloud_hpc_socket_status"),
            "direction": "Cloud / central compute -> HPC",
            "security": "HMAC-authenticated requests with HPC-owned service authorization",
        },
    ]
    traffic_by_protocol: Dict[str, Dict[str, int]] = {}
    for node_id, spec in NODES.items():
        protocol = spec["protocol"]
        metrics = traffic_by_protocol.setdefault(
            protocol,
            {
                "tx_generated": 0,
                "tx_delivered": 0,
                "rx_accepted": 0,
                "security_event_count": 0,
            },
        )
        for metric in metrics:
            metrics[metric] += NODE_TRAFFIC_STATS[node_id][metric]

    event_categories = Counter(
        event.get("category", "unknown")
        for event in ACTIVE_SECURITY_EVENTS
        if isinstance(event, dict)
    )
    diagnostic_result = run_network_diagnostics()
    supported_services = set()
    did_count = 0
    rid_count = 0
    for record in uds_diagnostics():
        supported_services.update(record["supported_services"])
        did_count += len(record["dids"])
        rid_count += len(record["rids"])

    return {
        "observed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "network": {
            "node_count": len(NODES),
            "zone_count": len(build_topology()["zones"]),
        },
        "sockets": socket_endpoints,
        "traffic_by_protocol": traffic_by_protocol,
        "security_events": {
            "retained_event_count": len(ACTIVE_SECURITY_EVENTS),
            "category_counts": dict(sorted(event_categories.items())),
        },
        "uds": {
            **diagnostic_result,
            "supported_service_count": len(supported_services),
            "did_count": did_count,
            "rid_count": rid_count,
        },
    }


def network_activity(limit: int = 100) -> Dict[str, Any]:
    if type(limit) is not int or not 1 <= limit <= 200:
        raise ValueError("activity limit must be an integer between 1 and 200")
    poll_node_messages()
    sensitive_location_terms = (
        "latitude",
        "longitude",
        "gnssposition",
        "gpsposition",
        "gpslocation",
        "geocoordinate",
        "coordinates",
    )

    def contains_sensitive_location(value: Any) -> bool:
        if not isinstance(value, str):
            return False
        normalized = "".join(character for character in value.lower() if character.isalnum())
        return any(term in normalized for term in sensitive_location_terms)

    message_fields = {
        "sampled_at_monotonic_ms",
        "source_node_id",
        "received_by_node_id",
        "message_name",
        "message_id",
        "transport_type",
        "direction",
        "sequence",
        "periodicity_ms",
        "signals",
    }
    messages = []
    for message in recent_node_messages(limit):
        if contains_sensitive_location(message.get("message_name")):
            continue
        item = {
            key: message[key]
            for key in message_fields
            if key in message
        }
        signals = item.get("signals")
        if isinstance(signals, dict):
            item["signals"] = {
                str(name)[:80]: value
                for name, value in signals.items()
                if isinstance(name, str)
                and not contains_sensitive_location(name)
                and (
                    value is None
                    or type(value) in (int, float, bool)
                    or (isinstance(value, str) and len(value) <= 120)
                )
            }
        sampled_at = item.get("sampled_at_monotonic_ms")
        if type(sampled_at) in (int, float):
            message_age_seconds = max(
                0,
                (time.monotonic() - STARTED_AT) - sampled_at / 1000,
            )
            item["timestamp"] = round(time.time() - message_age_seconds, 3)
        someip = message.get("someip")
        if isinstance(someip, dict):
            if isinstance(someip.get("service_id"), str):
                item["service_id"] = someip["service_id"][:24]
            method_id = someip.get("method_or_event_id")
            if isinstance(method_id, str):
                item["method_id"] = method_id[:24]
        messages.append(item)

    event_fields = {
        "event_id",
        "timestamp",
        "node_id",
        "detected_at_node_id",
        "category",
        "severity",
        "detail",
        "action",
        "message_name",
        "observed_message_id",
    }
    events = [
        {
            key: event[key]
            for key in event_fields
            if key in event
            and not (
                key in {"message_name", "detail"}
                and contains_sensitive_location(event[key])
            )
            and (
                event[key] is None
                or type(event[key]) in (int, float, bool)
                or (
                    isinstance(event[key], str)
                    and len(event[key]) <= 500
                )
            )
        }
        for event in (
            [e for e in ACTIVE_SECURITY_EVENTS if e.get("action") == "simulated_test_event"][-limit // 2:]
            + [e for e in ACTIVE_SECURITY_EVENTS if e.get("action") != "simulated_test_event"][-(limit - limit // 2):]
        )
    ]
    with DIAGNOSTIC_ACTIVITY_LOCK:
        diagnostics = copy.deepcopy(DIAGNOSTIC_ACTIVITY[-limit:])
    node_diagnostics = [
        event
        for node in NODE_INSTANCES.values()
        for event in getattr(node, "_ota_diagnostic_events", [])
    ]
    diagnostics = sorted(
        [*diagnostics, *node_diagnostics],
        key=lambda event: event.get("timestamp", 0),
    )[-limit:]
    for message in messages:
        source_id = message.get("source_node_id")
        message["socket_id"] = _socket_id_for_node(
            source_id if isinstance(source_id, str) else None
        )
        message["event_type"] = "traffic"
    for event in events:
        if event.get("action") == "simulated_test_event":
            event["event_type"] = "attack"
            event["phase"] = "attack"
            event["attack_generated"] = True
            event["socket_id"] = _socket_id_for_node(
                event.get("node_id")
                if isinstance(event.get("node_id"), str)
                else None
            )
        else:
            event["event_type"] = "security"
            event["socket_id"] = _socket_id_for_node(
                event.get("node_id")
                if isinstance(event.get("node_id"), str)
                else None
            )
    for event in diagnostics:
        target_id = event.get("target_node_id")
        event["socket_id"] = _socket_id_for_node(
            target_id if isinstance(target_id, str) else None
        )
    return {
        "observed_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "messages": messages,
        "security_events": events,
        "diagnostics": diagnostics,
        "scan_phase": SCAN_ACTIVITY_PHASE,
        "scan_phase_updated_at": SCAN_ACTIVITY_PHASE_UPDATED_AT,
        "attack_active": ACTIVE_ATTACK_RUNNING,
        "socket_events": _recent_socket_activity(limit),
    }


def set_scan_activity_phase(phase: str) -> Dict[str, Any]:
    global SCAN_ACTIVITY_PHASE, SCAN_ACTIVITY_PHASE_UPDATED_AT
    allowed_phases = {
        "idle",
        "before_attack",
        "protocol_probes",
        "attack",
        "after_attack",
    }
    if phase not in allowed_phases:
        raise ValueError("unsupported scan activity phase")
    SCAN_ACTIVITY_PHASE = phase
    SCAN_ACTIVITY_PHASE_UPDATED_AT = time.time()
    if phase != "idle":
        with DIAGNOSTIC_ACTIVITY_LOCK:
            DIAGNOSTIC_ACTIVITY.append(
                {
                    "event_type": "phase",
                    "timestamp": time.time(),
                    "phase": phase,
                    "detail": f"Scan phase: {phase.replace('_', ' ')}",
                }
            )
            del DIAGNOSTIC_ACTIVITY[:-1000]
    if (
        VEHICLE_NODE_ID is None
        and os.getenv("VEHICLE_NODE_SOCKET_ROUTING") == "1"
    ):
        for node_id in NODES:
            _send_node_socket(
                node_id,
                {"action": "scan_activity_phase", "phase": phase},
            )
    return {"status": "ok", "scan_phase": phase}


def request_attack_stop() -> Dict[str, Any]:
    with ACTIVE_ATTACK_LOCK:
        if not ACTIVE_ATTACK_RUNNING:
            return {
                "status": "inactive",
                "message": "No simulated attack is currently active.",
                "attack_active": False,
            }
        ACTIVE_ATTACK_STOP_EVENT.set()
    with DIAGNOSTIC_ACTIVITY_LOCK:
        DIAGNOSTIC_ACTIVITY.append(
            {
                "event_type": "phase",
                "timestamp": time.time(),
                "phase": SCAN_ACTIVITY_PHASE,
                "detail": "Operator requested stop; post-attack diagnostics will still run.",
            }
        )
        del DIAGNOSTIC_ACTIVITY[:-1000]
    return {
        "status": "stop_requested",
        "message": "Stop requested; post-attack diagnostics will still run.",
        "attack_active": True,
    }


def _node_hpc_sovd_transport() -> Dict[str, Any]:
    def can_uds(source_hpc_id, target_ecu_id, request_bytes, context=None):
        return _send_controller_can_socket(
            source_hpc_id,
            {
                "action": "hpc_uds",
                "source_hpc_id": source_hpc_id,
                "target_node_id": target_ecu_id,
                "request_bytes": request_bytes,
                "context": context,
            },
        )

    def doip(source_hpc_id, target_zcu_id, target_component_id, request_bytes, context=None):
        source = NODE_REGISTRY[source_hpc_id]
        target = NODE_REGISTRY[target_component_id]
        source_address = getattr(type(source), "DOIP_LOGICAL_ADDRESS", None)
        target_address = getattr(type(target), "DOIP_LOGICAL_ADDRESS", None)
        if source_address is None or target_address is None:
            raise ValueError("DoIP logical address is missing from an HPC or target node")
        packet = struct.pack(
            "!BBHIHH",
            0x02,
            0xFD,
            0x8001,
            len(request_bytes) + 4,
            source_address,
            target_address,
        ) + bytes(request_bytes)
        return _send_node_socket(
            target_zcu_id,
            {
                "action": "doip_diagnostic",
                "source_hpc_id": source_hpc_id,
                "target_component_id": target_component_id,
                "context": context,
                "doip_packet_hex": packet.hex().upper(),
            },
        )

    def peer_sovd(source_hpc_id, target_hpc_id, sovd_request):
        source = NODE_REGISTRY[source_hpc_id]
        target = NODE_REGISTRY[target_hpc_id]
        packet_hex = source.build_someip_sovd_request(target, sovd_request)
        response = _send_node_socket(
            target_hpc_id,
            {
                "action": "hpc_sovd_request",
                "source_hpc_id": source_hpc_id,
                "someip_packet_hex": packet_hex,
                "sovd_request": sovd_request,
            },
        )
        return response["sovd_response"]

    return {"can_uds": can_uds, "doip": doip, "peer_sovd": peer_sovd}


def _node_ota_transport() -> Dict[str, Any]:
    node = NODE_INSTANCES[VEHICLE_NODE_ID]
    parent_id = getattr(node, "CONNECTED_TO", None)
    parent = NODE_REGISTRY.get(parent_id) if isinstance(parent_id, str) else None
    is_zcu_parent = getattr(parent, "ROLE", "") == "zone_controller"

    def send_request(source_id, request_bytes, context=None):
        if is_zcu_parent:
            response = _send_controller_can_socket(
                parent_id,
                {
                    "action": "can_uds",
                    "source_zcu_id": parent_id,
                    "target_node_id": VEHICLE_NODE_ID,
                    "request_bytes": request_bytes,
                    "context": context,
                },
            )
        elif getattr(parent, "ROLE", "") == "hpc":
            response = _send_controller_can_socket(
                parent_id,
                {
                    "action": "hpc_uds",
                    "source_hpc_id": parent_id,
                    "target_node_id": VEHICLE_NODE_ID,
                    "request_bytes": request_bytes,
                    "context": context,
                },
            )
        else:
            response = _send_node_socket(
                VEHICLE_NODE_ID,
                {
                    "action": "uds_request",
                    "source_node_id": source_id,
                    "request_bytes": request_bytes,
                    "context": context,
                },
            )
        return response["uds_result"]

    def send_batch(source_id, requests):
        if is_zcu_parent:
            response = _send_controller_can_socket(
                parent_id,
                {
                    "action": "can_uds_batch",
                    "source_zcu_id": parent_id,
                    "target_node_id": VEHICLE_NODE_ID,
                    "requests": requests,
                },
            )
        elif getattr(parent, "ROLE", "") == "hpc":
            response = _send_controller_can_socket(
                parent_id,
                {
                    "action": "hpc_uds_batch",
                    "source_hpc_id": parent_id,
                    "target_node_id": VEHICLE_NODE_ID,
                    "requests": requests,
                },
            )
        else:
            response = _send_node_socket(
                VEHICLE_NODE_ID,
                {
                    "action": "uds_batch",
                    "source_node_id": source_id,
                    "requests": requests,
                },
            )
        results = response.get("uds_results")
        if not isinstance(results, list):
            raise RuntimeError("node OTA transfer returned an invalid UDS batch")
        return results

    return {"send_request": send_request, "send_batch": send_batch}


def node_socket_action(payload: Dict[str, Any]) -> Dict[str, Any]:
    if VEHICLE_NODE_ID is None:
        raise RuntimeError("node socket actions require VEHICLE_NODE_ID")
    node = NODE_INSTANCES[VEHICLE_NODE_ID]
    action = payload.get("action")

    if action == "node_snapshot":
        return {
            "node_id": VEHICLE_NODE_ID,
            "diagnostics": node.diagnostics(),
            "uds_diagnostics": node.uds_diagnostics(),
            "recent_messages": copy.deepcopy(
                getattr(node, "_message_history", [])[-100:]
            ),
            "received_messages": copy.deepcopy(
                getattr(node, "_received_message_history", [])[-100:]
            ),
            "security_events": copy.deepcopy(
                getattr(node, "_security_event_history", [])[-100:]
            ),
            "ota_diagnostic_events": copy.deepcopy(
                getattr(node, "_ota_diagnostic_events", [])[-100:]
            ),
            "socket_activity": _recent_socket_activity(200),
            "can_socket_status": (
                CAN_SOCKET_STATUS
                if getattr(node, "ROLE", "") in {"zone_controller", "hpc"}
                else "not_applicable"
            ),
            "zcu_hpc_tcp_socket_status": ZCU_HPC_TCP_SOCKET_STATUS,
            "cloud_hpc_socket_status": CLOUD_HPC_SOCKET_STATUS,
            "aggregate_messages": (
                node.aggregated_zcu_messages()
                if VEHICLE_NODE_ID == "hpc-vehicle"
                else []
            ),
            "traffic": dict(NODE_TRAFFIC_STATS[VEHICLE_NODE_ID]),
        }

    if action == "scan_activity_phase":
        return set_scan_activity_phase(payload.get("phase"))

    if action == "can_frames":
        controller_role = getattr(node, "ROLE", "")
        if controller_role not in {"zone_controller", "hpc"}:
            raise ValueError("the node CAN socket is available only on ZCUs and HPCs")
        source_id = payload.get("source_node_id")
        source_spec = NODES.get(source_id)
        frames = payload.get("frames")
        valid_local_ecu = (
            source_spec is not None
            and source_spec["role"] == "ecu"
            and source_spec["connected_to"] == VEHICLE_NODE_ID
            and (
                (controller_role == "zone_controller" and not source_spec["safety_critical"])
                or (controller_role == "hpc" and source_spec["safety_critical"])
            )
        )
        if (
            not valid_local_ecu
            or not isinstance(frames, list)
            or not frames
            or len(frames) > 256
        ):
            raise PermissionError(
                "CAN frames must originate from a local ECU authorized for this controller"
            )
        accepted_count = 0
        dropped_count = 0
        forwarded_count = 0
        for message in frames:
            reason = None
            frame = message.get("can_frame") if isinstance(message, dict) else None
            if not isinstance(frame, dict):
                reason = "CAN frame metadata is missing"
            else:
                can_id = frame.get("can_id")
                dlc = frame.get("dlc")
                data_hex = frame.get("data_hex")
                max_dlc = 64 if source_spec["protocol"] == "CAN-FD" else 8
                if (
                    type(can_id) is not int
                    or not 0 <= can_id <= 0x7FF
                    or type(dlc) is not int
                    or not 0 <= dlc <= max_dlc
                    or not isinstance(data_hex, str)
                    or len(data_hex) != dlc * 2
                    or any(char not in "0123456789abcdefABCDEF" for char in data_hex)
                ):
                    reason = "CAN identifier, DLC, or payload length is invalid"
            if reason is None:
                reason = _validate_message(
                    source_id,
                    message,
                    "can",
                    VEHICLE_NODE_ID,
                )
            if reason is not None:
                category = _validation_failure_category(reason)
                _raise_security_event(
                    source_id,
                    VEHICLE_NODE_ID,
                    category,
                    reason,
                    message if isinstance(message, dict) else None,
                )
                _record_socket_activity(
                    "zcu-can" if controller_role == "zone_controller" else "hpc-can",
                    source_id,
                    VEHICLE_NODE_ID,
                    "dropped",
                    message if isinstance(message, dict) else None,
                    reason,
                )
                dropped_count += 1
                continue

            received = copy.deepcopy(message)
            received.update(
                {
                    "direction": "rx",
                    "received_by_node_id": VEHICLE_NODE_ID,
                    "received_at_monotonic_ms": round(time.monotonic() * 1000, 3),
                }
            )
            _store_received_messages(VEHICLE_NODE_ID, [received])
            _record_socket_activity(
                "zcu-can" if controller_role == "zone_controller" else "hpc-can",
                source_id,
                VEHICLE_NODE_ID,
                "accepted",
                received,
            )
            accepted_count += 1
            if controller_role == "zone_controller":
                relay = node.encode_service_relay(
                    message, message.get("sequence", 0), socket_secret(), "zcu"
                )
                for hpc_id in node.CONNECTED_TO:
                    if getattr(NODE_REGISTRY.get(hpc_id), "ROLE", "") != "hpc":
                        continue
                    _send_node_socket(
                        hpc_id,
                        {
                            "action": "zcu_relay",
                            "source_zcu_id": VEHICLE_NODE_ID,
                            "messages": [relay],
                        },
                    )
                    _record_socket_activity(
                        f"zcu-hpc-tcp:{VEHICLE_NODE_ID}",
                        VEHICLE_NODE_ID,
                        hpc_id,
                        "forwarded",
                        relay,
                        "Authenticated ZCU-to-HPC relay",
                    )
                    NODE_TRAFFIC_STATS[VEHICLE_NODE_ID]["tx_delivered"] += 1
                    forwarded_count += 1
            elif VEHICLE_NODE_ID == "hpc-vehicle":
                node.receive_direct_can_messages([received])
            else:
                relay = node.encode_service_relay(
                    message, message.get("sequence", 0), socket_secret(), "hpc"
                )
                _send_node_socket(
                    "hpc-vehicle",
                    {
                        "action": "hpc_peer_messages",
                        "source_hpc_id": VEHICLE_NODE_ID,
                        "messages": [relay],
                    },
                )
                _record_socket_activity(
                    f"hpc-peer-tcp:{VEHICLE_NODE_ID}",
                    VEHICLE_NODE_ID,
                    "hpc-vehicle",
                    "forwarded",
                    relay,
                    "Authenticated HPC peer relay",
                )
                NODE_TRAFFIC_STATS[VEHICLE_NODE_ID]["tx_delivered"] += 1
                forwarded_count += 1
        return {
            "accepted_frames": accepted_count,
            "dropped_frames": dropped_count,
            "forwarded_frames": forwarded_count,
        }

    if action == "receive_message":
        source_id = payload.get("source_node_id")
        message = payload.get("message")
        if not isinstance(message, dict) or message.get("source_node_id") != source_id:
            raise ValueError("node message source does not match its socket envelope")
        source_spec = NODES.get(source_id)
        if source_spec is None:
            raise ValueError("node message source is not registered")
        transport = (
            "can"
            if source_spec["protocol"] in {"CAN", "CAN-FD"}
            else "someip"
        )
        reason = _validate_message(
            source_id, message, transport, VEHICLE_NODE_ID
        )
        if reason:
            category = _validation_failure_category(reason)
            _raise_security_event(
                source_id, VEHICLE_NODE_ID, category, reason, message
            )
            _record_socket_activity(
                (
                    "zcu-hpc-tcp"
                    if getattr(node, "ROLE", "") == "zone_controller"
                    and source_spec["role"] == "hpc"
                    else _socket_id_for_node(VEHICLE_NODE_ID)
                ),
                source_id,
                VEHICLE_NODE_ID,
                "dropped",
                message,
                reason,
            )
            raise PermissionError(reason)
        received = copy.deepcopy(message)
        received.update(
            {
                "direction": "rx",
                "received_by_node_id": VEHICLE_NODE_ID,
                "received_at_monotonic_ms": round(time.monotonic() * 1000, 3),
            }
        )
        _store_received_messages(VEHICLE_NODE_ID, [received])
        _record_socket_activity(
            (
                "zcu-hpc-tcp"
                if getattr(node, "ROLE", "") == "zone_controller"
                and source_spec["role"] == "hpc"
                else _socket_id_for_node(VEHICLE_NODE_ID)
            ),
            source_id,
            VEHICLE_NODE_ID,
            "accepted",
            received,
            "Authenticated SOME/IP message received by simulator node",
        )
        if getattr(node, "ROLE", "") == "zone_controller":
            relay = node.encode_service_relay(
                message, message.get("sequence", 0), socket_secret(), "zcu"
            )
            forwarded = 0
            for hpc_id in node.CONNECTED_TO:
                if getattr(NODE_REGISTRY.get(hpc_id), "ROLE", "") == "hpc":
                    _send_node_socket(
                        hpc_id,
                        {
                            "action": "zcu_relay",
                            "source_zcu_id": VEHICLE_NODE_ID,
                            "messages": [relay],
                        },
                    )
                    NODE_TRAFFIC_STATS[VEHICLE_NODE_ID]["tx_delivered"] += 1
                    forwarded += 1
            return {"accepted": True, "forwarded_hpc_count": forwarded}
        if (
            getattr(node, "ROLE", "") == "hpc"
            and VEHICLE_NODE_ID != "hpc-vehicle"
            and source_spec["role"] == "ecu"
            and source_spec["safety_critical"]
        ):
            relay = node.encode_service_relay(
                message, message.get("sequence", 0), socket_secret(), "hpc"
            )
            _send_node_socket(
                "hpc-vehicle",
                {
                    "action": "hpc_peer_messages",
                    "source_hpc_id": VEHICLE_NODE_ID,
                    "messages": [relay],
                },
            )
        return {"accepted": True, "forwarded_hpc_count": 0}

    if action == "zcu_relay":
        if getattr(node, "ROLE", "") != "hpc":
            raise ValueError("ZCU relay messages must target an HPC")
        source_id = payload.get("source_zcu_id")
        relays = payload.get("messages")
        if (
            source_id not in NODE_REGISTRY
            or not isinstance(relays, list)
            or not relays
        ):
            raise ValueError("ZCU relay envelope is invalid")
        accepted = []
        for relay in relays:
            reason, origin_id, origin = node.validate_service_relay(
                relay, NODE_REGISTRY, socket_secret(), "zcu"
            )
            if reason is None and relay.get("relayed_by_zcu_id") != source_id:
                reason = "ZCU relay source does not match socket source"
            if reason is None:
                origin_transport = (
                    "someip" if origin_id == source_id else "can"
                )
                reason = _validate_message(
                    origin_id,
                    origin,
                    origin_transport,
                    source_id if origin_id != source_id else VEHICLE_NODE_ID,
                    check_periodicity=False,
                    sequence_scope=f"zcu-relay:{source_id}",
                )
            if reason:
                _raise_security_event(
                    origin_id or source_id,
                    VEHICLE_NODE_ID,
                    _validation_failure_category(reason),
                    reason,
                    relay,
                )
                _record_socket_activity(
                    "zcu-hpc-tcp",
                    source_id,
                    VEHICLE_NODE_ID,
                    "dropped",
                    relay,
                    reason,
                )
                raise PermissionError(reason)
            accepted.append(origin)
            _record_socket_activity(
                "zcu-hpc-tcp",
                source_id,
                VEHICLE_NODE_ID,
                "accepted",
                relay,
                "Authenticated ZCU-to-HPC relay accepted",
            )
        node.receive_zcu_messages(source_id, accepted)
        return {"accepted_count": len(accepted)}

    if action == "hpc_peer_messages":
        if VEHICLE_NODE_ID != "hpc-vehicle":
            raise ValueError("HPC peer relays must target the vehicle HPC")
        source_id = payload.get("source_hpc_id")
        relays = payload.get("messages")
        if (
            source_id not in NODE_REGISTRY
            or not isinstance(relays, list)
            or not relays
        ):
            raise ValueError("HPC peer relay envelope is invalid")
        accepted = []
        for relay in relays:
            reason, origin_id, origin = node.validate_service_relay(
                relay, NODE_REGISTRY, socket_secret(), "hpc"
            )
            if reason is None and relay.get("relayed_by_hpc_id") != source_id:
                reason = "HPC relay source does not match socket source"
            if reason is None:
                reason = _validate_message(
                    origin_id,
                    origin,
                    "can",
                    source_id,
                    check_periodicity=False,
                    sequence_scope=f"hpc-peer-relay:{source_id}",
                )
            if reason:
                _raise_security_event(
                    origin_id or source_id,
                    VEHICLE_NODE_ID,
                    _validation_failure_category(reason),
                    reason,
                    relay,
                )
                _record_socket_activity(
                    "hpc-peer-tcp",
                    source_id,
                    VEHICLE_NODE_ID,
                    "dropped",
                    relay,
                    reason,
                )
                raise PermissionError(reason)
            accepted.append(origin)
            _record_socket_activity(
                "hpc-peer-tcp",
                source_id,
                VEHICLE_NODE_ID,
                "accepted",
                relay,
                "Authenticated HPC peer relay accepted",
            )
        node.receive_hpc_peer_messages(source_id, accepted)
        return {"accepted_count": len(accepted)}

    if action in {"uds_request", "uds_batch", "uds_security_probe"}:
        requested_node_id = payload.get("node_id", payload.get("target_node_id"))
        if requested_node_id is not None and requested_node_id != VEHICLE_NODE_ID:
            raise ValueError("UDS target does not match this node socket")
        role = getattr(node, "ROLE", "ecu")
        source_id = payload.get("source_node_id")
        if source_id is None and action in {"uds_request", "uds_batch"} and role == "ecu":
            parent_id = getattr(node, "CONNECTED_TO", None)
            parent = NODE_REGISTRY.get(parent_id)
            if getattr(parent, "ROLE", "") == "zone_controller":
                route_action = "can_uds" if action == "uds_request" else "can_uds_batch"
                return _send_controller_can_socket(
                    parent_id,
                    {
                        "action": route_action,
                        "source_zcu_id": parent_id,
                        "target_node_id": VEHICLE_NODE_ID,
                        "request_bytes": payload.get("request_bytes"),
                        "requests": payload.get("requests"),
                        "context": payload.get("context"),
                    },
                )
            if getattr(parent, "ROLE", "") == "hpc":
                route_action = "hpc_uds" if action == "uds_request" else "hpc_uds_batch"
                return _send_controller_can_socket(
                    parent_id,
                    {
                        "action": route_action,
                        "source_hpc_id": parent_id,
                        "target_node_id": VEHICLE_NODE_ID,
                        "request_bytes": payload.get("request_bytes"),
                        "requests": payload.get("requests"),
                        "context": payload.get("context"),
                    },
                )
        if source_id is None and role == "hpc":
            source_id = VEHICLE_NODE_ID
        if source_id is None and role == "zone_controller":
            connected = getattr(node, "CONNECTED_TO", ())
            source_id = next(iter(connected), None) if connected else None
        source = NODE_REGISTRY.get(source_id)
        if role == "ecu":
            route_authorized = node.authorize_uds_route(source)
            if route_authorized:
                _record_uds_security_result(
                    VEHICLE_NODE_ID,
                    source_id if isinstance(source_id, str) else None,
                    {
                        "service_name": "UDSRoute",
                        "security_bypasses": list(
                            getattr(node, "_accepted_profile_bypasses", ())
                        ),
                    },
                )
            if not route_authorized:
                raise PermissionError("UDS route violates the node's safety/zonal policy")
        elif source is None or getattr(source, "ROLE", "") != "hpc":
            raise PermissionError("UDS requester must be a registered HPC")

        if action == "uds_request":
            request_bytes = payload.get("request_bytes")
            if payload.get("sandboxed_uds_probe") is True:
                if not isinstance(request_bytes, list):
                    raise ValueError("sandboxed UDS probe requires a byte array")
                result = node.sandboxed_uds_request(request_bytes)
            else:
                result = node.handle_uds_request(request_bytes, payload.get("context"))
            _record_uds_security_result(
                VEHICLE_NODE_ID,
                source_id if isinstance(source_id, str) else None,
                result,
            )
            return {"uds_result": result}
        if action == "uds_batch":
            results = node.handle_uds_batch(payload.get("requests"))
            for result in results:
                _record_uds_security_result(
                    VEHICLE_NODE_ID,
                    source_id if isinstance(source_id, str) else None,
                    result,
                )
            return {"uds_results": results}
        if payload.get("sandboxed_uds_probe") is not True:
            raise PermissionError("SecurityAccess probes must use isolated node state")
        return node.sandboxed_security_access_probe()

    if action == "sandboxed_ota_probe":
        package = payload.get("package")
        if not isinstance(package, dict) or package.get("target_ecu_id") != VEHICLE_NODE_ID:
            raise ValueError("OTA probe package target does not match this node")
        previous_state = copy.deepcopy(getattr(node, "_uds_state", {}))
        previous_profile = copy.deepcopy(getattr(node, "_software_profile", {}))
        previous_partitions = copy.deepcopy(
            getattr(node, "_firmware_partitions", None)
        )
        previous_partition = getattr(node, "_active_partition", None)
        try:
            result = node_socket_action({**payload, "action": "ota_flash"})
            if isinstance(result, dict):
                _record_uds_security_result(
                    VEHICLE_NODE_ID,
                    package.get("source_hpc_id")
                    if isinstance(package.get("source_hpc_id"), str)
                    else None,
                    {
                        "service_name": "SecureFlashProbe",
                        "security_bypasses": result.get("security_bypasses", []),
                        "firmware": result.get("firmware", {}),
                    },
                )
            return result
        finally:
            node._uds_state = previous_state
            node._software_profile = previous_profile
            if previous_partitions is not None:
                node._firmware_partitions = previous_partitions
            elif hasattr(node, "_firmware_partitions"):
                delattr(node, "_firmware_partitions")
            if previous_partition is not None:
                node._active_partition = previous_partition

    if action == "ota_flash":
        package = payload.get("package")
        if not isinstance(package, dict):
            raise ValueError("OTA package must be a JSON object")
        if package.get("target_ecu_id") != VEHICLE_NODE_ID:
            raise ValueError("OTA package target does not match this node")
        if getattr(node, "ROLE", "") == "hpc":
            _record_hpc_ota_socket_activity(
                VEHICLE_NODE_ID, package, "received"
            )
        try:
            network_transport = _node_ota_transport()
            if getattr(node, "ROLE", "") == "zone_controller":
                def send_zcu_doip(channel, request_payload):
                    if channel != "doip":
                        raise ValueError("ZCU OTA diagnostics must use DoIP")
                    return _send_node_socket(VEHICLE_NODE_ID, request_payload)

                network_transport = {"send_socket": send_zcu_doip}
            result = node.perform_ota(
                package,
                node_instances=NODE_REGISTRY,
                network_transport=network_transport,
            )
            if getattr(node, "ROLE", "") == "hpc":
                result_status = (
                    result.get("status") if isinstance(result, dict) else None
                )
                _record_hpc_ota_socket_activity(
                    VEHICLE_NODE_ID,
                    package,
                    "completed" if result_status == "completed" else "rejected",
                    result,
                    result.get("reason", "") if isinstance(result, dict) else "",
                )
            return result
        except (PermissionError, ValueError) as exc:
            _raise_security_event(
                package.get("source_hpc_id", "unknown"),
                VEHICLE_NODE_ID,
                "secure_flash_failure",
                str(exc),
                {"message_name": "OTA package"},
            )
            if getattr(node, "ROLE", "") == "hpc":
                _record_hpc_ota_socket_activity(
                    VEHICLE_NODE_ID,
                    package,
                    "rejected",
                    {"status": "rejected"},
                    str(exc),
                )
            return {
                "status": "rejected",
                "reason": str(exc),
                "rejection_type": (
                    "authorization" if isinstance(exc, PermissionError) else "validation"
                ),
            }

    if action in {"can_uds", "can_uds_batch"}:
        controller_role = getattr(node, "ROLE", "")
        if controller_role != "zone_controller":
            raise ValueError("zonal CAN UDS requests must target a ZCU")
        if payload.get("source_zcu_id") != VEHICLE_NODE_ID:
            raise PermissionError("CAN UDS source does not match this ZCU socket")
        target_id = payload.get("target_node_id")
        target_spec = NODES.get(target_id)
        if (
            target_spec is None
            or target_spec["role"] != "ecu"
            or target_spec["connected_to"] != VEHICLE_NODE_ID
            or target_spec["safety_critical"]
        ):
            raise PermissionError("CAN UDS target is not a local non-safety ECU")
        if action == "can_uds":
            response = _send_node_socket(
                target_id,
                {
                    "action": "uds_request",
                    "source_node_id": VEHICLE_NODE_ID,
                    "request_bytes": payload.get("request_bytes"),
                    "context": payload.get("context"),
                },
            )
            uds_result = response.get("uds_result")
            if isinstance(uds_result, dict):
                _record_uds_can_exchange(
                    VEHICLE_NODE_ID,
                    target_id,
                    payload.get("request_bytes"),
                    uds_result.get("response_bytes", []),
                )
            return response
        results = _send_node_socket(
            target_id,
            {
                "action": "uds_batch",
                "source_node_id": VEHICLE_NODE_ID,
                "requests": payload.get("requests"),
            },
        ).get("uds_results")
        if not isinstance(results, list):
            raise RuntimeError("ZCU CAN UDS batch returned an invalid response")
        for request, result in zip(payload.get("requests", []), results):
            if isinstance(request, dict) and isinstance(result, dict):
                _record_uds_can_exchange(
                    VEHICLE_NODE_ID,
                    target_id,
                    request.get("request_bytes"),
                    result.get("response_bytes", []),
                )
        return {"uds_results": results}

    if action in {"hpc_uds", "hpc_uds_batch"}:
        if getattr(node, "ROLE", "") != "hpc":
            raise ValueError("safety ECU CAN UDS requests must target an HPC")
        if payload.get("source_hpc_id") != VEHICLE_NODE_ID:
            raise PermissionError("HPC UDS source does not match this HPC socket")
        target_id = payload.get("target_node_id")
        target_spec = NODES.get(target_id)
        if (
            target_spec is None
            or target_spec["role"] != "ecu"
            or not target_spec["safety_critical"]
            or target_spec["connected_to"] != VEHICLE_NODE_ID
        ):
            raise PermissionError("HPC UDS target is not a local safety ECU")
        if action == "hpc_uds":
            response = _send_node_socket(
                target_id,
                {
                    "action": "uds_request",
                    "source_node_id": VEHICLE_NODE_ID,
                    "request_bytes": payload.get("request_bytes"),
                    "context": payload.get("context"),
                },
            )
            uds_result = response.get("uds_result")
            if isinstance(uds_result, dict):
                _record_uds_can_exchange(
                    VEHICLE_NODE_ID,
                    target_id,
                    payload.get("request_bytes"),
                    uds_result.get("response_bytes", []),
                )
            return response
        results = _send_node_socket(
            target_id,
            {
                "action": "uds_batch",
                "source_node_id": VEHICLE_NODE_ID,
                "requests": payload.get("requests"),
            },
        ).get("uds_results")
        if not isinstance(results, list):
            raise RuntimeError("HPC CAN UDS batch returned an invalid response")
        for request, result in zip(payload.get("requests", []), results):
            if isinstance(request, dict) and isinstance(result, dict):
                _record_uds_can_exchange(
                    VEHICLE_NODE_ID,
                    target_id,
                    request.get("request_bytes"),
                    result.get("response_bytes", []),
                )
        return {"uds_results": results}

    if action == "someip_request":
        if (
            payload.get("target_node_id") is not None
            and payload.get("target_node_id") != VEHICLE_NODE_ID
        ):
            raise ValueError("SOME/IP target does not match this node socket")
        if getattr(node, "ROLE", "") not in {"hpc", "zone_controller"}:
            raise ValueError("this node does not provide a SOME/IP service")
        request_payload = dict(payload)
        requester_id = request_payload.get("requester_node_id", "hpc-vehicle")
        if not request_payload.get("someip_request_packet_hex"):
            requester = NODE_REGISTRY.get(requester_id)
            if requester is None:
                raise ValueError("SOME/IP requester is not registered")
            request_payload["someip_request_packet_hex"] = (
                requester.build_someip_signal_request(
                    node, request_payload.get("signal_name")
                )
            )
        return node.handle_someip_signal_request(request_payload, NODE_REGISTRY)

    if action == "sovd_request":
        if getattr(node, "ROLE", "") != "hpc":
            raise ValueError("SOVD requests must target an HPC gateway")
        gateway_id = payload.get("gateway_hpc_id", VEHICLE_NODE_ID)
        if gateway_id != VEHICLE_NODE_ID:
            raise ValueError("SOVD gateway does not match this node")
        return node.handle_sovd_request(
            payload, NODE_REGISTRY, _node_hpc_sovd_transport()
        )

    if action == "hpc_sovd_request":
        if getattr(node, "ROLE", "") != "hpc":
            raise ValueError("peer SOVD requests must target an HPC")
        return node.handle_someip_sovd_request(
            payload, NODE_REGISTRY, _node_hpc_sovd_transport()
        )

    if action in {"doip_diagnostic", "doip_diagnostic_batch"}:
        if getattr(node, "ROLE", "") != "zone_controller":
            raise ValueError("DoIP requests must target a ZCU")
        source_id = payload.get("source_hpc_id")
        packet_hexes = (
            payload.get("doip_packet_hexes")
            if action == "doip_diagnostic_batch"
            else [payload.get("doip_packet_hex")]
        )
        if (
            not isinstance(packet_hexes, list)
            or not 1 <= len(packet_hexes) <= 512
            or any(not isinstance(packet_hex, str) for packet_hex in packet_hexes)
        ):
            raise ValueError("DoIP request packet batch must contain 1 to 512 packets")
        context = payload.get("context")
        source_id = source_id if isinstance(source_id, str) else "unknown"

        def send_can_uds(zcu_source_id, ecu_target_id, request_bytes, context=None):
            return _send_controller_can_socket(
                zcu_source_id,
                {
                    "action": "can_uds",
                    "source_zcu_id": zcu_source_id,
                    "target_node_id": ecu_target_id,
                    "request_bytes": request_bytes,
                    "context": context,
                },
            )

        try:
            uds_results = []
            response_packet_hexes = []
            for packet_hex in packet_hexes:
                if not isinstance(packet_hex, str):
                    continue
                _record_doip_socket_activity(
                    source_id,
                    VEHICLE_NODE_ID,
                    payload.get("target_component_id", VEHICLE_NODE_ID),
                    packet_hex,
                    "received",
                    context if isinstance(context, dict) else None,
                    phase=payload.get("phase"),
                )
                packet = bytes.fromhex(packet_hex)
                result = node.handle_doip_request(
                    packet,
                    NODE_REGISTRY,
                    send_can_uds,
                    context,
                )
                if result.get("target_node_id") != payload.get("target_component_id"):
                    raise PermissionError(
                        "DoIP target does not match the requested component"
                    )
                uds_result = result.get("uds_result")
                if not isinstance(uds_result, dict):
                    raise RuntimeError("DoIP handler returned an invalid UDS result")
                uds_results.append(uds_result)
                response_bytes = uds_result.get("response_bytes", [])
                if not isinstance(response_bytes, list) or any(
                    type(value) is not int or not 0 <= value <= 0xFF
                    for value in response_bytes
                ):
                    raise RuntimeError("DoIP handler returned an invalid UDS response")
                response_packet = struct.pack(
                    "!BBHIHH",
                    0x02,
                    0xFD,
                    0x8001,
                    len(response_bytes) + 4,
                    int.from_bytes(packet[10:12], "big"),
                    int.from_bytes(packet[8:10], "big"),
                ) + bytes(response_bytes)
                response_hex = response_packet.hex().upper()
                response_packet_hexes.append(response_hex)
                _record_doip_socket_activity(
                    VEHICLE_NODE_ID,
                    source_id,
                    payload.get("target_component_id", VEHICLE_NODE_ID),
                    response_hex,
                    "sent",
                    context if isinstance(context, dict) else None,
                    f"DoIP UDS response: {uds_result.get('service_name', 'UDS')}; "
                    f"{'positive' if uds_result.get('positive_response') else 'negative'}",
                    payload.get("phase"),
                )
        except (PermissionError, ValueError) as exc:
            for packet_hex in packet_hexes:
                _record_doip_socket_activity(
                    source_id,
                    VEHICLE_NODE_ID,
                    payload.get("target_component_id", VEHICLE_NODE_ID),
                    packet_hex,
                    "dropped",
                    context if isinstance(context, dict) else None,
                    str(exc),
                    payload.get("phase"),
                )
            raise
        if action == "doip_diagnostic_batch":
            return {
                "status": "ok",
                "uds_results": uds_results,
                "doip_response_packet_hexes": response_packet_hexes,
                "route": [source_id, VEHICLE_NODE_ID, payload.get("target_component_id")],
            }
        return {
            "status": "ok",
            "uds_result": uds_results[0],
            "doip_request_packet_hex": packet_hexes[0],
            "doip_response_packet_hex": response_packet_hexes[0],
            "route": [source_id, VEHICLE_NODE_ID, payload.get("target_component_id")],
        }

    raise ValueError(f"Unsupported node socket action: {action}")


def schedule_single_node_messages() -> None:
    node = NODE_INSTANCES[VEHICLE_NODE_ID]
    source_spec = NODES[VEHICLE_NODE_ID]
    while not SCHEDULER_STOP.is_set():
        now_ms = (time.monotonic() - STARTED_AT) * 1000
        emitted = node.emit_due_messages(now_ms, socket_secret())
        for index, message in enumerate(emitted):
            try:
                encoded = _encode_wire_message(
                    VEHICLE_NODE_ID, message, index, socket_secret()
                )
                if source_spec["role"] == "zone_controller":
                    relay = node.encode_service_relay(
                        encoded, index, socket_secret(), "zcu"
                    )
                    for hpc_id in node.CONNECTED_TO:
                        if getattr(NODE_REGISTRY.get(hpc_id), "ROLE", "") == "hpc":
                            _send_node_socket(
                                hpc_id,
                                {
                                    "action": "zcu_relay",
                                    "source_zcu_id": VEHICLE_NODE_ID,
                                    "messages": [relay],
                                },
                            )
                            _record_socket_activity(
                                f"zcu-hpc-tcp:{VEHICLE_NODE_ID}",
                                VEHICLE_NODE_ID,
                                hpc_id,
                                "forwarded",
                                relay,
                                "Authenticated ZCU SOME/IP relay",
                            )
                    continue
                for recipient_id in encoded.get("recipient_node_ids", []):
                    if recipient_id not in NODE_REGISTRY:
                        continue
                    recipient_role = NODES.get(recipient_id, {}).get("role")
                    if (
                        source_spec["role"] == "ecu"
                        and recipient_role in {"zone_controller", "hpc"}
                    ):
                        result = _send_controller_can_socket(
                            recipient_id,
                            {
                                "action": "can_frames",
                                "source_node_id": VEHICLE_NODE_ID,
                                "frames": [encoded],
                            },
                        )
                        NODE_TRAFFIC_STATS[VEHICLE_NODE_ID][
                            "tx_delivered"
                        ] += int(result.get("accepted_frames", 0))
                        continue
                    _send_node_socket(
                        recipient_id,
                        {
                            "action": "receive_message",
                            "source_node_id": VEHICLE_NODE_ID,
                            "message": encoded,
                        },
                    )
                    NODE_TRAFFIC_STATS[VEHICLE_NODE_ID]["tx_delivered"] += 1
            except (OSError, RuntimeError, ValueError) as exc:
                logging.warning(
                    "Node %s could not deliver message %s: %s",
                    VEHICLE_NODE_ID,
                    message.get("message_name"),
                    exc,
                )
        SCHEDULER_STOP.wait(0.01)


def socket_action(payload: Dict[str, Any]) -> Dict[str, Any]:
    if VEHICLE_NODE_ID is not None:
        return node_socket_action(payload)
    global VEHICLE_SERVICE_STATE
    action = payload.get("action")
    if os.getenv("VEHICLE_NODE_SOCKET_ROUTING") == "1" and action in {
        "uds_request",
        "uds_batch",
        "uds_security_probe",
        "ota_flash",
        "someip_request",
        "sovd_request",
    }:
        raise PermissionError(
            "Node service requests must use the owning node's socket"
        )
    topology = build_topology()
    if action == "vehicle_service_state":
        with SERVICE_STATE_LOCK:
            return {"service_state": VEHICLE_SERVICE_STATE}
    if action == "set_vehicle_service_state":
        requested_state = payload.get("service_state")
        if not isinstance(requested_state, str) or requested_state not in VEHICLE_SERVICE_STATES:
            raise ValueError("service_state must be in_service or out_of_service")
        with SERVICE_STATE_LOCK:
            VEHICLE_SERVICE_STATE = requested_state
            return {"service_state": VEHICLE_SERVICE_STATE}
    if action == "security_profiles":
        return get_node_security_profiles()
    if action == "configure_security_profile":
        return configure_node_security_profile(payload)
    if action == "network_observability":
        return network_observability()
    if action == "network_activity":
        return network_activity(payload.get("limit", 100))
    if action == "scan_activity_phase":
        return set_scan_activity_phase(payload.get("phase"))
    if action == "authorized_attack_stop":
        return request_attack_stop()
    if action == "authorized_attack_test":
        return run_authorized_attack_test(payload)
    if action in {"snapshot", "topology"}:
        poll_node_messages()
        diagnostics = diagnostics_records(topology)
        messages = recent_node_messages()
        hpc_messages = (
            REMOTE_NODE_SNAPSHOTS.get("hpc-vehicle", {}).get(
                "aggregate_messages", []
            )
            if os.getenv("VEHICLE_NODE_SOCKET_ROUTING") == "1"
            else NODE_INSTANCES["hpc-vehicle"].aggregated_zcu_messages()
        )
        topology["hpc_vehicle_data"]["messages"] = hpc_messages
        return {
            "network_snapshot": topology,
            "gateway_configuration_version": GATEWAY_CONFIGURATION_VERSION,
            "hpc_vehicle_data": topology["hpc_vehicle_data"],
            "diagnostics": diagnostics,
            "vehicle_messages": messages,
            "node_behavior": node_behavior_report(),
            "security_events": list(ACTIVE_SECURITY_EVENTS[-500:]),
            "dtcs": active_dtcs(),
            "runtime_elapsed_ms": int((time.monotonic() - STARTED_AT) * 1000),
            "service_state": VEHICLE_SERVICE_STATE,
        }
    if action == "network_diagnostics":
        return run_network_diagnostics()
    if action == "diagnostics":
        return {"diagnostics": diagnostics_records(topology)}
    if action == "vehicle_messages":
        poll_node_messages()
        return {"vehicle_messages": recent_node_messages()}
    if action == "security_events":
        return {"security_events": list(ACTIVE_SECURITY_EVENTS[-500:]), "dtcs": active_dtcs()}
    if action == "uds_diagnostics":
        return {"uds_diagnostics": uds_diagnostics()}
    if action == "someip_request":
        return _request_signal_over_someip(payload.get("target_node_id"), payload.get("signal_name"), payload.get("requester_node_id", "hpc-vehicle"))
    if action == "sovd_request":
        return _dispatch_sovd_request(payload)
    if action == "uds_request":
        node = NODE_INSTANCES.get(payload.get("node_id"))
        if node is None:
            raise ValueError("unknown node identifier")
        request_bytes = payload.get("request_bytes")
        if payload.get("sandboxed_uds_probe") is True:
            if not isinstance(request_bytes, list):
                raise ValueError("sandboxed UDS probe requires a byte array")
            result = node.sandboxed_uds_request(request_bytes)
        else:
            result = node.handle_uds_request(request_bytes, payload.get("context"))
        _record_uds_security_result(
            node.NODE_ID,
            payload.get("source_node_id")
            if isinstance(payload.get("source_node_id"), str)
            else None,
            result,
        )
        return {"uds_result": result}
    if action == "uds_security_probe":
        node = NODE_INSTANCES.get(payload.get("node_id"))
        if node is None:
            raise ValueError("unknown node identifier")
        if payload.get("sandboxed_uds_probe") is not True:
            raise PermissionError("SecurityAccess simulation probes must be isolated")
        return node.sandboxed_security_access_probe()
    if action == "ota_flash":
        package = payload.get("package")
        if not isinstance(package, dict):
            raise ValueError("OTA package must be a JSON object")
        target_id = package.get("target_ecu_id")
        if not target_id or target_id not in NODE_INSTANCES:
            raise ValueError("target ECU is not a registered node")
        target = NODE_INSTANCES[target_id]
        if getattr(target, "ROLE", "") == "hpc":
            _record_hpc_ota_socket_activity(target_id, package, "received")
        try:
            result = target.perform_ota(
                package,
                node_instances=NODE_INSTANCES,
                network_transport={"send_socket": _send_transport_frame},
            )
            if getattr(target, "ROLE", "") == "hpc":
                result_status = (
                    result.get("status") if isinstance(result, dict) else None
                )
                _record_hpc_ota_socket_activity(
                    target_id,
                    package,
                    "completed" if result_status == "completed" else "rejected",
                    result,
                    result.get("reason", "") if isinstance(result, dict) else "",
                )
            if isinstance(result, dict):
                _record_uds_security_result(
                    target_id,
                    package.get("source_hpc_id")
                    if isinstance(package.get("source_hpc_id"), str)
                    else None,
                    {
                        "service_name": "PartitionOTA",
                        "security_bypasses": result.get("security_bypasses", []),
                        "firmware": result.get("firmware", {}),
                    },
                )
            return result
        except PermissionError as exc:
            if getattr(target, "ROLE", "") == "hpc":
                _record_hpc_ota_socket_activity(
                    target_id,
                    package,
                    "rejected",
                    {"status": "rejected"},
                    str(exc),
                )
            return {"status": "rejected", "reason": str(exc), "rejection_type": "authorization"}
        except ValueError as exc:
            if getattr(target, "ROLE", "") == "hpc":
                _record_hpc_ota_socket_activity(
                    target_id,
                    package,
                    "rejected",
                    {"status": "rejected"},
                    str(exc),
                )
            return {"status": "rejected", "reason": str(exc), "rejection_type": "validation"}
    if action == "runtime_status":
        poll_node_messages()
        return {"diagnostics": diagnostics_records(topology), "node_behavior": node_behavior_report(), "security_events": list(ACTIVE_SECURITY_EVENTS[-500:]), "dtcs": active_dtcs(), "recent_messages": recent_node_messages(100)}
    if action == "inject_frames":
        return {"status": "rejected", "message": "Untrusted attack injection is disabled; use an explicitly authorized test harness"}
    raise ValueError(f"Unsupported socket action: {action}")


def _submit_can_test_frame(source_id: str, message: Dict[str, Any]) -> Dict[str, Any]:
    if os.getenv("VEHICLE_NODE_SOCKET_ROUTING") == "1":
        controller_id = NODES[source_id]["connected_to"]
        if not isinstance(controller_id, str):
            raise RuntimeError(f"CAN probe source {source_id} has no controller route")
        response = _send_controller_can_socket(
            controller_id,
            {
                "action": "can_frames",
                "source_node_id": source_id,
                "frames": [message],
            },
        )
        return {
            "accepted_frames": response.get("accepted_frames", 0),
            "dropped_frames": response.get("dropped_frames", 0),
        }
    response = _send_internal_socket(
        CAN_SOCKET_PORT,
        {
            "action": "can_frames",
            "source_node_id": source_id,
            "frames": [message],
        },
    )
    if response is None or "dropped_frames" not in response:
        raise RuntimeError("simulated CAN test frame did not receive a valid response")
    return response


def _run_can_protocol_probes() -> Dict[str, int]:
    poll_node_messages()
    node_routing = os.getenv("VEHICLE_NODE_SOCKET_ROUTING") == "1"
    sources = [
        node_id
        for node_id, spec in NODES.items()
        if spec["role"] == "ecu"
        and spec["protocol"] in {"CAN", "CAN-FD"}
        and (
            REMOTE_NODE_SNAPSHOTS.get(node_id, {}).get("recent_messages")
            if node_routing
            else NODE_INSTANCES[node_id]._message_history
        )
    ]
    attempted = 0
    rejected = 0
    categories: Dict[str, int] = {}
    secret = socket_secret()

    for source_id in sources:
        message_history = (
            REMOTE_NODE_SNAPSHOTS.get(source_id, {}).get("recent_messages", [])
            if node_routing
            else NODE_INSTANCES[source_id]._message_history
        )
        original = next(
            (
                message
                for message in message_history
                if isinstance(message.get("can_frame"), dict)
                and message.get("recipient_node_ids")
            ),
            None,
        )
        if original is None:
            continue
        probes = []
        invalid_id = copy.deepcopy(original)
        expected_can_id = int(original["can_frame"]["can_id"])
        malformed_can_id = secrets.randbelow(0x800)
        while malformed_can_id == expected_can_id:
            malformed_can_id = secrets.randbelow(0x800)
        invalid_id["can_frame"]["can_id"] = malformed_can_id
        invalid_id["can_frame"]["can_id_hex"] = f"0x{malformed_can_id:03X}"
        invalid_id["message_id"] = f"0x{malformed_can_id:03X}"
        invalid_id["sent_at_unix_ms"] = int(time.time() * 1000)
        _seal_node_message(source_id, invalid_id, secret)
        probes.append(("can_id_mismatch", invalid_id))

        invalid_range = copy.deepcopy(original)
        layout = invalid_range["signal_layout"]
        invalid_value = int(layout["maximum"]) + secrets.randbelow(16) + 1
        layout["encoded_value"] = invalid_value
        invalid_range["signal_payload_hex"] = invalid_value.to_bytes(8, "big").hex().upper()
        invalid_range["can_frame"]["data_hex"] = invalid_range["signal_payload_hex"]
        invalid_range["sent_at_unix_ms"] = int(time.time() * 1000)
        _seal_node_message(source_id, invalid_range, secret)
        probes.append(("signal_out_of_range", invalid_range))

        invalid_auth = copy.deepcopy(original)
        invalid_auth["sent_at_unix_ms"] = int(time.time() * 1000)
        invalid_auth["auth_tag"] = "0" * 64
        probes.append(("invalid_authentication", invalid_auth))

        replay = copy.deepcopy(original)
        replay["sent_at_unix_ms"] = int(time.time() * 1000)
        _seal_node_message(source_id, replay, secret)
        probes.append(("replay_detected", replay))

        rapid_frames = []
        for offset in range(1, 4):
            rapid = copy.deepcopy(original)
            rapid["sequence"] = original["sequence"] + offset
            rapid["sampled_at_monotonic_ms"] = round(time.monotonic() * 1000, 3)
            rapid["sent_at_unix_ms"] = int(time.time() * 1000)
            _seal_node_message(source_id, rapid, secret)
            rapid_frames.append(rapid)

        for category, message in probes:
            response = _submit_can_test_frame(source_id, message)
            attempted += 1
            rejected += int(response["dropped_frames"])
            if response["dropped_frames"]:
                categories[category] = categories.get(category, 0) + 1

        if node_routing:
            controller_id = NODES[source_id]["connected_to"]
            response = _send_controller_can_socket(
                controller_id,
                {
                    "action": "can_frames",
                    "source_node_id": source_id,
                    "frames": rapid_frames,
                },
            )
        else:
            response = _send_internal_socket(
                CAN_SOCKET_PORT,
                {
                    "action": "can_frames",
                    "source_node_id": source_id,
                    "frames": rapid_frames,
                },
            )
        if response is None or "dropped_frames" not in response:
            raise RuntimeError("simulated CAN periodicity probe did not receive a valid response")
        attempted += len(rapid_frames)
        rejected += int(response["dropped_frames"])
        if response["dropped_frames"]:
            categories["periodicity_violation"] = (
                categories.get("periodicity_violation", 0)
                + int(response["dropped_frames"])
            )

    return {
        "attempted": attempted,
        "rejected": rejected,
        "target_node_count": len(sources),
        "category_counts": categories,
    }


def _run_uds_protocol_probes() -> Dict[str, int]:
    targets = list(NODE_INSTANCES)
    simulator_socket_port = int(
        os.getenv("VEHICLE_NETWORK_SOCKET_PORT", str(SOCKET_PORT))
    )
    attempted = 0
    rejected = 0
    categories: Dict[str, int] = {}

    for target_id in targets:
        result = NODE_INSTANCES[target_id].run_uds_protocol_probes(
            lambda payload: _send_internal_socket(
                simulator_socket_port, payload
            )
        )
        attempted += result["attempted"]
        rejected += result["rejected"]
        for category, count in result["category_counts"].items():
            categories[category] = categories.get(category, 0) + count
        for category, detail, action in result["security_events"]:
            _raise_security_event(
                target_id,
                "vehicle-network",
                category,
                detail,
                {"message_name": category},
                action=action,
            )

    return {
        "attempted": attempted,
        "rejected": rejected,
        "target_node_count": len(targets),
        "category_counts": categories,
    }


def _run_someip_header_probe() -> Dict[str, int]:
    poll_node_messages()
    node_routing = os.getenv("VEHICLE_NODE_SOCKET_ROUTING") == "1"
    zcu_id = next(
        (
            node_id
            for node_id, spec in NODES.items()
            if spec["role"] == "zone_controller"
            and (
                REMOTE_NODE_SNAPSHOTS.get(node_id, {}).get("recent_messages")
                if node_routing
                else NODE_INSTANCES[node_id]._message_history
            )
        ),
        None,
    )
    if zcu_id is None:
        raise RuntimeError("no simulated ZCU message is available for SOME/IP probe")
    zcu_messages = (
        REMOTE_NODE_SNAPSHOTS[zcu_id].get("recent_messages", [])
        if node_routing
        else NODE_INSTANCES[zcu_id]._message_history
    )
    original = zcu_messages[0]
    relay = _encode_zcu_relay(zcu_id, copy.deepcopy(original), 0, socket_secret())
    packet = bytearray.fromhex(relay["someip"]["packet_hex"])
    malformed_service_id = secrets.randbelow(0x10000)
    while malformed_service_id == NODE_INSTANCES[zcu_id].SOMEIP_SERVICE_ID:
        malformed_service_id = secrets.randbelow(0x10000)
    packet[0:2] = malformed_service_id.to_bytes(2, "big")
    relay["someip"]["packet_hex"] = packet.hex().upper()
    _seal_node_message(zcu_id, relay, socket_secret())
    if node_routing:
        hpc_id = next(
            (
                node_id
                for node_id in NODES[zcu_id]["connected_to"]
                if NODES[node_id]["role"] == "hpc"
            ),
            None,
        )
        if hpc_id is None:
            raise RuntimeError(f"ZCU {zcu_id} has no connected HPC for SOME/IP probe")
        response = _send_internal_socket(
            ZCU_HPC_TCP_SOCKET_PORT,
            {
                "action": "zcu_relay",
                "source_zcu_id": zcu_id,
                "messages": [relay],
            },
            f"{os.getenv('VEHICLE_NODE_HOST_PREFIX', 'vehicle-node-')}{hpc_id}",
        )
        if response is None:
            raise RuntimeError("simulated SOME/IP header probe received no socket response")
        rejected = int(response.get("status") == "error")
        _record_socket_activity(
            "zcu-hpc-tcp",
            zcu_id,
            hpc_id,
            "dropped" if rejected else "accepted",
            relay,
            "Bounded malformed SOME/IP header probe",
        )
    else:
        response = _send_internal_socket(
            HPC_INGRESS_PORT,
            {
                "action": "zcu_messages",
                "source_node_id": zcu_id,
                "messages": [relay],
            },
        )
        if response is None or "dropped_messages" not in response:
            raise RuntimeError("simulated SOME/IP header probe did not receive a valid response")
        rejected = int(response["dropped_messages"])
    if rejected:
        _raise_security_event(
            zcu_id,
            "hpc-vehicle",
            "someip_header_mismatch",
            "Simulator rejected a bounded malformed SOME/IP service identifier.",
            relay,
        )
    return {
        "attempted": 1,
        "rejected": rejected,
        "target_node_count": 1,
        "category_counts": {"someip_header_mismatch": rejected} if rejected else {},
    }


def _run_doip_header_probe() -> Dict[str, int]:
    zcu_id = next(
        (
            node_id
            for node_id, spec in NODES.items()
            if spec["role"] == "zone_controller"
            and spec["connected_to"]
        ),
        None,
    )
    if zcu_id is None:
        raise RuntimeError("no simulated ZCU route is available for DoIP probe")
    source_id = NODES[zcu_id]["connected_to"][0]
    source = NODE_INSTANCES[source_id]
    target = NODE_INSTANCES[zcu_id]
    packet = struct.pack(
        "!BBHIHH",
        0x01,
        0xFE,
        0x8001,
        4,
        source.DOIP_LOGICAL_ADDRESS,
        target.DOIP_LOGICAL_ADDRESS,
    )
    doip_payload = {
            "action": "doip_diagnostic",
            "source_hpc_id": source_id,
            "target_zcu_id": zcu_id,
            "target_component_id": zcu_id,
            "doip_packet_hex": packet.hex().upper(),
        }
    if os.getenv("VEHICLE_NODE_SOCKET_ROUTING") == "1":
        response = _send_internal_socket(
            ZCU_HPC_TCP_SOCKET_PORT,
            doip_payload,
            f"{os.getenv('VEHICLE_NODE_HOST_PREFIX', 'vehicle-node-')}{zcu_id}",
        )
    else:
        response = _send_internal_socket(DOIP_SOCKET_PORT, doip_payload)
    if response is None or response.get("status") != "error":
        raise RuntimeError("simulated DoIP header probe was not rejected")
    _raise_security_event(
        zcu_id,
        source_id,
        "doip_header_mismatch",
        "Simulator rejected a bounded malformed DoIP protocol-version header.",
        {"message_name": "malformed_doip_header"},
    )
    return {
        "attempted": 1,
        "rejected": 1,
        "target_node_count": 1,
        "category_counts": {"doip_header_mismatch": 1},
    }


def run_simulated_protocol_probe_suite() -> Dict[str, Any]:
    probes = {
        "can": _run_can_protocol_probes(),
        "uds": _run_uds_protocol_probes(),
        "someip": _run_someip_header_probe(),
        "doip": _run_doip_header_probe(),
    }
    categories: Dict[str, int] = {}
    for probe in probes.values():
        for category, count in probe["category_counts"].items():
            categories[category] = categories.get(category, 0) + count
    return {
        "suite": "bounded_simulator_protocol_probes_v1",
        "status": "completed",
        "attempted_count": sum(item["attempted"] for item in probes.values()),
        "rejected_count": sum(item["rejected"] for item in probes.values()),
        "target_node_count": sum(
            item["target_node_count"] for item in probes.values()
        ),
        "category_counts": dict(sorted(categories.items())),
        "protocols": {
            protocol: {
                "attempted_count": result["attempted"],
                "rejected_count": result["rejected"],
                "target_node_count": result["target_node_count"],
            }
            for protocol, result in probes.items()
        },
    }


def _attack_can_route(target_id: str) -> tuple[str, str]:
    target = NODES[target_id]
    role = target["role"]
    if role == "ecu":
        parent_id = target["connected_to"]
        if isinstance(parent_id, str):
            return target_id, parent_id
    elif role == "zone_controller":
        source_id = next(
            (
                node_id
                for node_id, spec in NODES.items()
                if spec["role"] == "ecu"
                and spec["zone"] == target["zone"]
                and not spec["safety_critical"]
                and spec["protocol"] in {"CAN", "CAN-FD"}
            ),
            None,
        )
        if source_id:
            return source_id, target_id
    elif role == "hpc":
        source_id = next(
            (
                node_id
                for node_id, spec in NODES.items()
                if spec["role"] == "ecu"
                and spec["connected_to"] == target_id
                and spec["safety_critical"]
                and spec["protocol"] in {"CAN", "CAN-FD"}
            ),
            None,
        )
        if source_id:
            return source_id, target_id
        zcu_id = next(
            (
                node_id
                for node_id, spec in NODES.items()
                if spec["role"] == "zone_controller"
                and target_id in spec["connected_to"]
            ),
            None,
        )
        if zcu_id:
            source_id = next(
                (
                    node_id
                    for node_id, spec in NODES.items()
                    if spec["role"] == "ecu"
                    and spec["connected_to"] == zcu_id
                    and not spec["safety_critical"]
                    and spec["protocol"] in {"CAN", "CAN-FD"}
                ),
                None,
            )
            if source_id:
                return source_id, zcu_id
    raise ValueError(f"no simulated CAN route is available for attack target {target_id}")


def _attack_base_can_message(source_id: str, receiver_id: str) -> Dict[str, Any]:
    if os.getenv("VEHICLE_NODE_SOCKET_ROUTING") == "1":
        history = REMOTE_NODE_SNAPSHOTS.get(source_id, {}).get("recent_messages", [])
    else:
        source = NODE_INSTANCES.get(source_id)
        history = getattr(source, "_message_history", []) if source else []
    message = next(
        (
            item
            for item in reversed(history)
            if isinstance(item, dict)
            and isinstance(item.get("can_frame"), dict)
            and isinstance(item.get("recipient_node_ids"), list)
            and receiver_id in item["recipient_node_ids"]
        ),
        None,
    )
    if message is None:
        poll_node_messages()
        if os.getenv("VEHICLE_NODE_SOCKET_ROUTING") == "1":
            history = REMOTE_NODE_SNAPSHOTS.get(source_id, {}).get(
                "recent_messages", []
            )
        else:
            source = NODE_INSTANCES.get(source_id)
            history = getattr(source, "_message_history", []) if source else []
        message = next(
            (
                item
                for item in reversed(history)
                if isinstance(item, dict)
                and isinstance(item.get("can_frame"), dict)
                and isinstance(item.get("recipient_node_ids"), list)
                and receiver_id in item["recipient_node_ids"]
            ),
            None,
        )
    if message is None:
        raise RuntimeError(
            f"no live CAN message is available from {source_id} to {receiver_id}"
        )
    return copy.deepcopy(message)


def _attack_base_zcu_message(source_id: str, receiver_id: str) -> Dict[str, Any]:
    if os.getenv("VEHICLE_NODE_SOCKET_ROUTING") == "1":
        history = REMOTE_NODE_SNAPSHOTS.get(source_id, {}).get(
            "recent_messages", []
        )
    else:
        source = NODE_INSTANCES.get(source_id)
        history = getattr(source, "_message_history", []) if source else []
    message = next(
        (
            item
            for item in reversed(history)
            if isinstance(item, dict) and isinstance(item.get("someip"), dict)
        ),
        None,
    )
    if message is None and source_id in NODE_INSTANCES:
        source = NODE_INSTANCES[source_id]
        now_ms = (time.monotonic() - STARTED_AT) * 1000
        originals = source.emit_due_messages(now_ms + 100_000, socket_secret())
        message = next(
            (
                _encode_wire_message(source_id, item, index, socket_secret())
                for index, item in enumerate(originals)
                if index < len(NODES[source_id]["message_catalog"])
            ),
            None,
        )
    if not isinstance(message, dict) or not isinstance(
        message.get("someip"), dict
    ):
        raise RuntimeError(
            f"no live SOME/IP message is available from {source_id} to {receiver_id}"
        )
    message = copy.deepcopy(message)
    message["source_node_id"] = source_id
    message["recipient_node_ids"] = [receiver_id]
    message["phase"] = "attack"
    message["attack_generated"] = True
    _seal_node_message(source_id, message, socket_secret())
    return message


def _submit_attack_zcu_message(
    source_id: str, receiver_id: str, message: Dict[str, Any]
) -> Dict[str, int]:
    if os.getenv("VEHICLE_NODE_SOCKET_ROUTING") == "1":
        host = (
            f"{os.getenv('VEHICLE_NODE_HOST_PREFIX', 'vehicle-node-')}"
            f"{receiver_id}"
        )
        response = _send_internal_socket(
            ZCU_HPC_TCP_SOCKET_PORT,
            {
                "action": "receive_message",
                "source_hpc_id": source_id,
                "source_node_id": source_id,
                "message": message,
            },
            host,
        )
        if response is None or response.get("status") != "ok":
            reason = (response or {}).get(
                "message", "HPC-ZCU SOME/IP attack was not delivered"
            )
            _raise_security_event(
                source_id,
                receiver_id,
                "invalid_route" if "authorization" in reason else "invalid_authentication",
                reason,
                message,
            )
            _record_socket_activity(
                "zcu-hpc-tcp",
                source_id,
                receiver_id,
                "dropped",
                message,
                reason,
            )
            return {"accepted": 0, "dropped": 1}
        return {
            "accepted": int(
                isinstance(response.get("data"), dict)
                and response["data"].get("accepted") is True
            ),
            "dropped": 0,
        }

    reason = _validate_message(source_id, message, "someip", receiver_id)
    if reason:
        category = _validation_failure_category(reason)
        _raise_security_event(source_id, receiver_id, category, reason, message)
        _record_socket_activity(
            "zcu-hpc-tcp",
            source_id,
            receiver_id,
            "dropped",
            message,
            reason,
        )
        return {"accepted": 0, "dropped": 1}
    received = copy.deepcopy(message)
    received.update(
        {
            "direction": "rx",
            "received_by_node_id": receiver_id,
            "received_at_monotonic_ms": round(time.monotonic() * 1000, 3),
        }
    )
    _store_received_messages(receiver_id, [received])
    _record_socket_activity(
        "zcu-hpc-tcp",
        source_id,
        receiver_id,
        "accepted",
        received,
        "Authenticated SOME/IP attack frame accepted by simulator receiver",
    )
    return {"accepted": 1, "dropped": 0}


def _send_attack_can_batch(
    source_id: str,
    receiver_id: str,
    messages: list[Dict[str, Any]],
    cross_zone: bool = False,
) -> Dict[str, int]:
    if os.getenv("VEHICLE_NODE_SOCKET_ROUTING") == "1":
        if cross_zone:
            accepted = dropped = 0
            for message in messages:
                try:
                    _send_node_socket(
                        receiver_id,
                        {
                            "action": "receive_message",
                            "source_node_id": source_id,
                            "message": message,
                        },
                    )
                    accepted += 1
                except RuntimeError as exc:
                    _raise_security_event(
                        source_id,
                        receiver_id,
                        "invalid_route",
                        str(exc),
                        message,
                        action="dropped",
                    )
                    _record_socket_activity(
                        _socket_id_for_node(receiver_id),
                        source_id,
                        receiver_id,
                        "dropped",
                        message,
                        str(exc),
                    )
                    dropped += 1
            return {"accepted": accepted, "dropped": dropped}
        response = _send_controller_can_socket(
            receiver_id,
            {
                "action": "can_frames",
                "source_node_id": source_id,
                "frames": messages,
            },
        )
    else:
        response = _send_internal_socket(
            CAN_SOCKET_PORT,
            {
                "action": "can_frames",
                "source_node_id": source_id,
                "frames": messages,
            },
        )
        if response is None or "dropped_frames" not in response:
            raise RuntimeError("simulated attack did not receive a CAN socket response")
    return {
        "accepted": int(response.get("accepted_frames", 0)),
        "dropped": int(response.get("dropped_frames", 0)),
    }


def _create_attack_messages(
    attack_type: str,
    severity: str,
    source_id: str,
    receiver_id: str,
    baseline: Dict[str, Any],
    requested_count: int,
) -> tuple[list[Dict[str, Any]], str]:
    secret = socket_secret()
    attack_receiver_id = receiver_id
    is_flood = attack_type in {"flooding", "dos"}
    count = min(512, max(1, requested_count)) if is_flood else 1
    last_sequence = max(
        (
            message.get("sequence", 0)
            for message in (
                REMOTE_NODE_SNAPSHOTS.get(source_id, {}).get("recent_messages", [])
                if os.getenv("VEHICLE_NODE_SOCKET_ROUTING") == "1"
                else getattr(NODE_INSTANCES.get(source_id), "_message_history", [])
            )
            if isinstance(message, dict) and type(message.get("sequence")) is int
        ),
        default=baseline.get("sequence", 1),
    )
    messages = []
    for index in range(count):
        message = copy.deepcopy(baseline)
        message["phase"] = "attack"
        message["attack_generated"] = True
        message["attack_type"] = attack_type
        if is_flood:
            message["sequence"] = last_sequence + index + 1
            message["sampled_at_monotonic_ms"] = round(
                (time.monotonic() - STARTED_AT) * 1000 + index, 3
            )
            message["sent_at_unix_ms"] = int(time.time() * 1000)
            _seal_node_message(source_id, message, secret)
        elif attack_type == "replay_attack":
            message["sent_at_unix_ms"] = int(time.time() * 1000)
            _seal_node_message(source_id, message, secret)
        elif attack_type == "tampering":
            layout = message.get("signal_layout")
            if isinstance(layout, dict) and type(layout.get("maximum")) is int:
                invalid_value = layout["maximum"] + 1
                layout["encoded_value"] = invalid_value
                message["signal_payload_hex"] = invalid_value.to_bytes(
                    8, "big", signed=invalid_value < 0
                ).hex().upper()
                can_frame = message.get("can_frame")
                if isinstance(can_frame, dict):
                    can_frame["data_hex"] = message["signal_payload_hex"]
                signals = message.get("signals")
                if isinstance(signals, dict):
                    signals[layout["name"]] = invalid_value
                message["sent_at_unix_ms"] = int(time.time() * 1000)
        elif attack_type in {"repudiation", "ids_auditability_regression"}:
            message["sent_at_unix_ms"] = int(time.time() * 1000)
            message["auth_tag"] = "0" * 64
        elif attack_type == "spoofing":
            message["source_node_id"] = "ecu-unregistered"
            message["sent_at_unix_ms"] = int(time.time() * 1000)
        elif attack_type == "cross_zone_access":
            wrong_receiver = next(
                (
                    node_id
                    for node_id, spec in NODES.items()
                    if spec["role"] == "zone_controller"
                    and spec["zone"] != NODES[receiver_id]["zone"]
                ),
                None,
            )
            if wrong_receiver is None:
                raise ValueError("no cross-zone CAN destination is available")
            attack_receiver_id = wrong_receiver
            message["recipient_node_ids"] = [wrong_receiver]
            message["sent_at_unix_ms"] = int(time.time() * 1000)
            _seal_node_message(source_id, message, secret)
        messages.append(message)
    return messages, attack_receiver_id


def _attack_diagnostic_request(
    target_id: str, request_count: int = 1
) -> Dict[str, Any]:
    if type(request_count) is not int or not 1 <= request_count <= 512:
        raise ValueError("diagnostic attack batch must contain 1 to 512 requests")
    request_bytes = [0x34, 0x00, 0x00, 0x00]
    target_spec = NODES[target_id]
    role = target_spec["role"]
    if role == "ecu":
        parent_id = target_spec.get("connected_to")
        parent_role = NODES.get(parent_id, {}).get("role")
        if parent_role == "hpc":
            if os.getenv("VEHICLE_NODE_SOCKET_ROUTING") == "1":
                response = _send_controller_can_socket(
                    parent_id,
                    {
                        "action": "hpc_uds",
                        "source_hpc_id": parent_id,
                        "target_node_id": target_id,
                        "request_bytes": request_bytes,
                    },
                )
                return _diagnostic_attack_counts(response.get("uds_result", {}))
            response = _send_internal_socket(
                CAN_SOCKET_PORT,
                {
                    "action": "uds_request",
                    "source_node_id": parent_id,
                    "target_node_id": target_id,
                    "request_bytes": request_bytes,
                },
            )
            if response is None or response.get("status") != "ok":
                raise RuntimeError("unauthorized UDS request was not delivered over CAN")
            return _diagnostic_attack_counts(response["uds_result"])
        if parent_role == "zone_controller":
            source_hpc_id = next(
                (
                    node_id
                    for node_id in NODES[parent_id]["connected_to"]
                    if NODES.get(node_id, {}).get("role") == "hpc"
                ),
                None,
            )
            zcu_id = parent_id
        else:
            source_hpc_id = None
            zcu_id = None
    elif role == "zone_controller":
        source_hpc_id = next(
            (
                node_id
                for node_id in target_spec["connected_to"]
                if NODES.get(node_id, {}).get("role") == "hpc"
            ),
            None,
        )
        zcu_id = target_id
    elif role == "hpc":
        if os.getenv("VEHICLE_NODE_SOCKET_ROUTING") == "1":
            response = _send_node_socket(
                target_id,
                {
                    "action": "uds_request",
                    "node_id": target_id,
                    "request_bytes": request_bytes,
                },
            )
            return _diagnostic_attack_counts(response.get("uds_result", {}))
        result = NODE_INSTANCES[target_id].handle_uds_request(request_bytes)
        _record_uds_security_result(target_id, "central-compute", result)
        _record_socket_activity(
            "cloud-hpc-tcp",
            "central-compute",
            target_id,
            "rejected" if not result.get("positive_response") else "accepted",
            {
                "message_name": "Unauthorized RequestDownload",
                "service_id": "0x34",
                "transport_type": "UDS",
                "message_length_bytes": len(request_bytes),
            },
        )
        return _diagnostic_attack_counts(result)
    else:
        source_hpc_id = None
        zcu_id = None

    if not isinstance(source_hpc_id, str) or not isinstance(zcu_id, str):
        raise ValueError(f"no diagnostic route is available for {target_id}")
    if os.getenv("VEHICLE_NODE_SOCKET_ROUTING") == "1":
        source_address = getattr(
            NODE_REGISTRY.get(source_hpc_id), "DOIP_LOGICAL_ADDRESS", None
        )
        target_address = getattr(
            NODE_REGISTRY.get(target_id), "DOIP_LOGICAL_ADDRESS", None
        )
    else:
        source_address = getattr(
            type(NODE_INSTANCES[source_hpc_id]), "DOIP_LOGICAL_ADDRESS", None
        )
        target_address = getattr(
            type(NODE_INSTANCES[target_id]), "DOIP_LOGICAL_ADDRESS", None
        )
    if source_address is None or target_address is None:
        raise ValueError("DoIP logical address is unavailable for diagnostic attack")
    packet = struct.pack(
        "!BBHIHH",
        0x02,
        0xFD,
        0x8001,
        len(request_bytes) + 4,
        source_address,
        target_address,
    ) + bytes(request_bytes)
    packets = [packet.hex().upper()] * request_count
    batched = request_count > 1
    payload = {
        "action": "doip_diagnostic_batch" if batched else "doip_diagnostic",
        "source_hpc_id": source_hpc_id,
        "target_zcu_id": zcu_id,
        "target_component_id": target_id,
        **(
            {"doip_packet_hexes": packets}
            if batched
            else {"doip_packet_hex": packets[0]}
        ),
        "phase": "attack",
    }
    if os.getenv("VEHICLE_NODE_SOCKET_ROUTING") == "1":
        response = _send_internal_socket(
            ZCU_HPC_TCP_SOCKET_PORT,
            payload,
            f"{os.getenv('VEHICLE_NODE_HOST_PREFIX', 'vehicle-node-')}{zcu_id}",
        )
    else:
        response = _send_internal_socket(DOIP_SOCKET_PORT, payload)
    if response is None or response.get("status") != "ok":
        raise RuntimeError(
            (response or {}).get(
                "message", "unauthorized UDS request was not delivered over DoIP"
            )
        )
    response_data = (
        response.get("data")
        if isinstance(response.get("data"), dict)
        else response
    )
    uds_results = response_data.get("uds_results")
    if not isinstance(uds_results, list):
        single_result = response_data.get("uds_result")
        uds_results = [single_result] if isinstance(single_result, dict) else []
    if len(uds_results) != request_count:
        raise RuntimeError("DoIP diagnostic attack returned an incomplete response batch")
    accepted = sum(item.get("positive_response") is True for item in uds_results)
    return {
        "positive_response": accepted == request_count,
        "attempted_count": len(uds_results),
        "accepted_count": accepted,
        "dropped_count": len(uds_results) - accepted,
    }


def _diagnostic_attack_counts(result: Dict[str, Any]) -> Dict[str, Any]:
    accepted = int(result.get("positive_response") is True)
    return {
        **result,
        "attempted_count": 1,
        "accepted_count": accepted,
        "dropped_count": 1 - accepted,
    }


def _invalid_firmware_package(target_id: str) -> Dict[str, Any]:
    target = NODES[target_id]
    parent_id = target.get("connected_to")
    if target["role"] == "hpc":
        source_id = next(iter(target.get("trusted_sources", ())), None)
        zcu_id = None
    elif target["role"] == "zone_controller":
        source_id = next(
            (
                node_id
                for node_id in target["connected_to"]
                if NODES.get(node_id, {}).get("role") == "hpc"
            ),
            None,
        )
        zcu_id = None
    elif isinstance(parent_id, str) and NODES[parent_id]["role"] == "zone_controller":
        source_id = next(
            (
                node_id
                for node_id in NODES[parent_id]["connected_to"]
                if NODES.get(node_id, {}).get("role") == "hpc"
            ),
            None,
        )
        zcu_id = parent_id
    else:
        source_id = parent_id if isinstance(parent_id, str) else None
        zcu_id = None
    if not isinstance(source_id, str):
        raise ValueError(f"no trusted OTA source is available for {target_id}")
    image = b"invalid-ota-test"
    manifest = {
        "ecu_id": target_id,
        "version": "SIM-ATTACK-INVALID",
        "image_size": len(image),
        "sha256": hashlib.sha256(image).hexdigest(),
        "signature": "0" * 64,
    }
    return {
        "source_hpc_id": source_id,
        "zcu_id": zcu_id,
        "target_ecu_id": target_id,
        "attack_generated": True,
        "image_hex": image.hex(),
        "manifest": manifest,
    }


def _sandboxed_invalid_firmware_probe(
    target_id: str, package: Dict[str, Any]
) -> Dict[str, Any]:
    if os.getenv("VEHICLE_NODE_SOCKET_ROUTING") == "1":
        return _send_node_socket(
            target_id,
            {"action": "sandboxed_ota_probe", "package": package},
        )

    target_node = NODE_INSTANCES[target_id]
    had_uds_state = hasattr(target_node, "_uds_state")
    previous_state = copy.deepcopy(getattr(target_node, "_uds_state", {}))
    had_software_profile = hasattr(target_node, "_software_profile")
    previous_profile = copy.deepcopy(getattr(target_node, "_software_profile", {}))
    previous_partitions = copy.deepcopy(
        getattr(target_node, "_firmware_partitions", None)
    )
    previous_partition = getattr(target_node, "_active_partition", None)
    if NODES[target_id]["role"] == "hpc":
        _record_hpc_ota_socket_activity(target_id, package, "received")
    try:
        result = target_node.perform_ota(
            package,
            node_instances=NODE_INSTANCES,
            network_transport={"send_socket": _send_transport_frame},
        )
        if isinstance(result, dict):
            _record_uds_security_result(
                target_id,
                package["source_hpc_id"],
                {
                    "service_name": "SecureFlashProbe",
                    "security_bypasses": result.get("security_bypasses", []),
                    "firmware": result.get("firmware", {}),
                },
            )
        if NODES[target_id]["role"] == "hpc":
            _record_hpc_ota_socket_activity(
                target_id,
                package,
                "rejected" if result.get("status") != "completed" else "accepted",
                result,
            )
        return result
    except (PermissionError, ValueError) as exc:
        _raise_security_event(
            package["source_hpc_id"],
            target_id,
            "secure_flash_failure",
            str(exc),
            {"message_name": "Invalid firmware signature"},
        )
        return {"status": "rejected", "reason": str(exc)}
    finally:
        if had_uds_state:
            target_node._uds_state = previous_state
        elif hasattr(target_node, "_uds_state"):
            delattr(target_node, "_uds_state")
        if had_software_profile:
            target_node._software_profile = previous_profile
        elif hasattr(target_node, "_software_profile"):
            delattr(target_node, "_software_profile")
        if previous_partitions is not None:
            target_node._firmware_partitions = previous_partitions
        elif hasattr(target_node, "_firmware_partitions"):
            delattr(target_node, "_firmware_partitions")
        if previous_partition is not None:
            target_node._active_partition = previous_partition


def run_authorized_attack_test(payload: Dict[str, Any]) -> Dict[str, Any]:
    global ACTIVE_ATTACK_RUNNING
    with ACTIVE_ATTACK_LOCK:
        if ACTIVE_ATTACK_RUNNING:
            raise ValueError("another simulated attack is already active")
        ACTIVE_ATTACK_RUNNING = True
        ACTIVE_ATTACK_STOP_EVENT.clear()
    try:
        return _execute_authorized_attack_test(payload)
    finally:
        with ACTIVE_ATTACK_LOCK:
            ACTIVE_ATTACK_RUNNING = False


def _execute_authorized_attack_test(payload: Dict[str, Any]) -> Dict[str, Any]:
    if payload.get("authorized_simulation") is not True:
        raise PermissionError("authorized simulation test flag is required")
    attack_type = payload.get("attack_type")
    severity = payload.get("severity")
    duration_seconds = payload.get("duration_seconds")
    if not isinstance(attack_type, str) or attack_type not in AUTHORIZED_TEST_SCENARIOS:
        raise ValueError("unsupported authorized simulation scenario")
    if not isinstance(severity, str) or severity not in {"low", "medium", "high", "critical"}:
        raise ValueError("unsupported authorized simulation severity")
    if type(duration_seconds) is not int or not 1 <= duration_seconds <= 60:
        raise ValueError("duration_seconds must be an integer between 1 and 60")
    requested_targets = payload.get("target_node_ids")
    if requested_targets is None:
        target_ids = [
            node_id
            for node_id in NODES
            if _scenario_matches_node(node_id, AUTHORIZED_TEST_SCENARIOS[attack_type])
        ]
    elif (
        not isinstance(requested_targets, list)
        or not requested_targets
        or any(
            not isinstance(node_id, str) or node_id not in NODES
            for node_id in requested_targets
        )
        or len(requested_targets) != len(set(requested_targets))
    ):
        raise ValueError("target_node_ids must be a non-empty list of registered node IDs")
    else:
        target_ids = requested_targets

    with SERVICE_STATE_LOCK:
        if VEHICLE_SERVICE_STATE != "in_service":
            raise PermissionError("authorized attack tests require the vehicle to be in service")

    attack_frames = payload.get("attack_frames")
    if (
        not isinstance(attack_frames, list)
        or len(attack_frames) != len(target_ids)
        or any(
            not isinstance(frame, dict)
            or frame.get("target_ecu_id") not in target_ids
            or frame.get("attack_type") != attack_type
            or frame.get("severity") != severity
            for frame in attack_frames
        )
        or {frame["target_ecu_id"] for frame in attack_frames} != set(target_ids)
    ):
        raise ValueError(
            "Central Compute must provide one matching attack plan per selected simulator node"
        )

    run_protocol_probes = payload.get("run_protocol_probes", True)
    if type(run_protocol_probes) is not bool:
        raise ValueError("run_protocol_probes must be a boolean")
    probe_summary = (
        run_simulated_protocol_probe_suite()
        if run_protocol_probes
        else {"status": "skipped", "reason": "fast_assessment_requested"}
    )
    set_scan_activity_phase("attack")
    started_at = time.monotonic()
    started_at_utc = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    if not target_ids:
        raise ValueError("authorized simulation scenario has no matching nodes")

    role_counts = Counter(NODES[node_id]["role"] for node_id in target_ids)
    with SECURITY_PROFILE_LOCK:
        security_level_counts = Counter(
            NODE_SECURITY_PROFILES[node_id]["security_level"]
            for node_id in target_ids
        )
    counters_before = {
        key: sum(stats[key] for stats in NODE_TRAFFIC_STATS.values())
        for key in ("tx_generated", "tx_delivered")
    }
    deadline = started_at + duration_seconds
    security_events_before = len(ACTIVE_SECURITY_EVENTS)
    attempted_count = accepted_count = dropped_count = 0
    attack_sockets = set()
    stopped_early = False
    for plan in attack_frames:
        if ACTIVE_ATTACK_STOP_EVENT.is_set():
            stopped_early = True
            break
        with SERVICE_STATE_LOCK:
            if VEHICLE_SERVICE_STATE != "in_service":
                stopped_early = True
                break
        target_id = plan["target_ecu_id"]
        if attack_type == "unauthorized_diagnostics" or (
            attack_type in {"flooding", "dos"}
            and (
                NODES[target_id]["role"] == "zone_controller"
                or NODES[target_id]["protocol"] not in {"CAN", "CAN-FD"}
            )
        ):
            request_count = (
                int(plan.get("message_count", 1))
                if attack_type in {"flooding", "dos"}
                else 1
            )
            result = _attack_diagnostic_request(target_id, request_count)
            attempted_count += result.get("attempted_count", 1)
            accepted_count += result.get("accepted_count", 0)
            dropped_count += result.get("dropped_count", 0)
            target_spec = NODES[target_id]
            parent_id = target_spec.get("connected_to")
            attack_sockets.add(
                "cloud-hpc-tcp"
                if target_spec["role"] == "hpc"
                else "zcu-hpc-tcp"
                if target_spec["role"] == "zone_controller"
                or NODES.get(parent_id, {}).get("role") == "zone_controller"
                else _socket_id_for_node(target_id)
            )
        elif attack_type == "invalid_firmware":
            security_event_count_before = len(ACTIVE_SECURITY_EVENTS)
            package = _invalid_firmware_package(target_id)
            result = _sandboxed_invalid_firmware_probe(target_id, package)
            attempted_count += 1
            dropped_count += int(result.get("status") != "completed")
            accepted_count += int(result.get("status") == "completed")
            target_spec = NODES[target_id]
            parent_id = target_spec.get("connected_to")
            socket_id = (
                "cloud-hpc-tcp"
                if target_spec["role"] == "hpc"
                else "zcu-hpc-tcp"
                if target_spec["role"] == "zone_controller"
                or NODES.get(parent_id, {}).get("role") == "zone_controller"
                else _socket_id_for_node(target_id)
            )
            attack_sockets.add(socket_id)
            if result.get("status") != "completed" and len(ACTIVE_SECURITY_EVENTS) == security_event_count_before:
                _raise_security_event(
                    target_id,
                    target_id,
                    "secure_flash_failure",
                    str(result.get("reason", "Node rejected invalid firmware.")),
                    {"message_name": "Invalid firmware signature probe"},
                )
            _record_socket_activity(
                socket_id,
                package["source_hpc_id"],
                target_id,
                "accepted" if result.get("status") == "completed" else "dropped",
                {
                    "phase": "attack",
                    "attack_generated": True,
                    "attack_type": attack_type,
                    "message_name": "Invalid firmware signature probe",
                    "message_length_bytes": package["manifest"]["image_size"],
                    "transport_type": (
                        "UDS over CAN/CAN-FD"
                        if socket_id in {"zcu-can", "hpc-can"}
                        else "DoIP over authenticated TCP"
                        if socket_id == "zcu-hpc-tcp"
                        else "Authenticated TCP / JSON Lines"
                    ),
                },
                str(result.get("reason", result.get("status", "unknown"))),
            )
        elif NODES[target_id]["role"] == "zone_controller":
            source_id = next(
                (
                    node_id
                    for node_id in NODES[target_id]["connected_to"]
                    if NODES.get(node_id, {}).get("role") == "hpc"
                ),
                None,
            )
            if not isinstance(source_id, str):
                raise ValueError(f"no connected HPC is available for {target_id}")
            baseline = _attack_base_zcu_message(source_id, target_id)
            messages, attack_receiver_id = _create_attack_messages(
                attack_type,
                severity,
                source_id,
                target_id,
                baseline,
                int(plan.get("message_count", 1)),
            )
            result = {"accepted": 0, "dropped": 0}
            for message in messages:
                message_result = _submit_attack_zcu_message(
                    source_id, attack_receiver_id, message
                )
                result["accepted"] += message_result["accepted"]
                result["dropped"] += message_result["dropped"]
            attempted_count += len(messages)
            accepted_count += result["accepted"]
            dropped_count += result["dropped"]
            attack_sockets.add("zcu-hpc-tcp")
        else:
            source_id, receiver_id = _attack_can_route(target_id)
            baseline = _attack_base_can_message(source_id, receiver_id)
            messages, attack_receiver_id = _create_attack_messages(
                attack_type,
                severity,
                source_id,
                receiver_id,
                baseline,
                int(plan.get("message_count", 1)),
            )
            result = {"accepted": 0, "dropped": 0}
            for offset in range(0, len(messages), 256):
                batch_result = _send_attack_can_batch(
                    source_id,
                    attack_receiver_id,
                    messages[offset : offset + 256],
                    cross_zone=attack_type == "cross_zone_access",
                )
                result["accepted"] += batch_result["accepted"]
                result["dropped"] += batch_result["dropped"]
            attempted_count += len(messages)
            accepted_count += result["accepted"]
            dropped_count += result["dropped"]
            attack_sockets.add(
                "zcu-hpc-tcp"
                if NODES[receiver_id]["role"] == "zone_controller"
                and NODES[target_id]["role"] == "hpc"
                else _socket_id_for_node(receiver_id)
            )

    if not stopped_early:
        while not ACTIVE_ATTACK_STOP_EVENT.is_set() and time.monotonic() < deadline:
            with SERVICE_STATE_LOCK:
                if VEHICLE_SERVICE_STATE != "in_service":
                    stopped_early = True
                    break
            time.sleep(min(0.1, max(0.0, deadline - time.monotonic())))
    stopped_early = stopped_early or ACTIVE_ATTACK_STOP_EVENT.is_set()

    ended_at_utc = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    elapsed_seconds = max(time.monotonic() - started_at, 0.001)
    counters_after = {
        key: sum(stats[key] for stats in NODE_TRAFFIC_STATS.values())
        for key in ("tx_generated", "tx_delivered")
    }
    during_generated = max(
        0, counters_after["tx_generated"] - counters_before["tx_generated"]
    )
    during_delivered = max(
        0, counters_after["tx_delivered"] - counters_before["tx_delivered"]
    )
    event_count = max(0, len(ACTIVE_SECURITY_EVENTS) - security_events_before)
    affected_protocols = sorted({NODES[node_id]["protocol"] for node_id in target_ids})
    affected_sockets = sorted(attack_sockets)
    return {
        "status": "stopped" if stopped_early else "completed",
        "execution_mode": "bounded_simulator_socket_traffic",
        "attack_type": attack_type,
        "severity": severity,
        "started_at": started_at_utc,
        "ended_at": ended_at_utc,
        "requested_duration_seconds": duration_seconds,
        "elapsed_seconds": round(elapsed_seconds, 2),
        "event_count": event_count,
        "attack_frame_count": attempted_count,
        "accepted_frame_count": accepted_count,
        "dropped_frame_count": dropped_count,
        "affected_node_count": len(target_ids),
        "target_role_counts": dict(sorted(role_counts.items())),
        "target_security_level_counts": dict(sorted(security_level_counts.items())),
        "targeting_mode": "operator_selected" if requested_targets is not None else "scenario_default",
        "affected_interfaces": affected_protocols,
        "affected_sockets": affected_sockets,
        "probe_summary": probe_summary,
        "during_metrics": {
            "sample_window_seconds": round(elapsed_seconds, 2),
            "message_count": during_generated,
            "message_rate_per_second": round(
                during_generated / elapsed_seconds, 3
            ),
            "message_loss_percentage": round(
                max(0, during_generated - during_delivered)
                * 100.0
                / max(during_generated, 1),
                3,
            ),
            "security_event_count": event_count,
            "attack_frame_count": attempted_count,
            "accepted_frame_count": accepted_count,
            "dropped_frame_count": dropped_count,
        },
    }


def run_network_diagnostics() -> Dict[str, Any]:
    started = time.perf_counter()
    successful_count = 0
    failed_count = 0
    active_dtc_count = 0
    response_categories = {
        "positive": 0,
        "negative": 0,
        "timeout": 0,
        "transport_error": 0,
    }
    latencies_ms = []
    for component_id in NODE_INSTANCES:
        request_started = time.perf_counter()
        try:
            result = _dispatch_sovd_request(
                {
                    "component_id": component_id,
                    "operation": "readDTCInformation",
                    "vehicle_id": "simulated-vehicle",
                }
            )
            latencies_ms.append((time.perf_counter() - request_started) * 1000)
            uds_result = result.get("result", {})
            if SCAN_ACTIVITY_PHASE in {"before_attack", "after_attack"}:
                response_bytes = uds_result.get("response_bytes", [])
                response_service_id = (
                    f"0x{response_bytes[0]:02X}"
                    if isinstance(response_bytes, list)
                    and response_bytes
                    and type(response_bytes[0]) is int
                    else None
                )
                target = NODE_INSTANCES[component_id]
                routing = result.get("routing", {})
                route_transports = (
                    routing.get("transports", [])
                    if isinstance(routing, dict)
                    else []
                )
                route_transport = (
                    route_transports[-1]
                    if isinstance(route_transports, list)
                    and route_transports
                    and isinstance(route_transports[-1], str)
                    else None
                )
                logical_address = getattr(
                    type(target), "DOIP_LOGICAL_ADDRESS", None
                )
                transport = (
                    route_transport
                    or (
                        target.PROTOCOL
                        if getattr(target, "ROLE", "") == "ecu"
                        and getattr(target, "SAFETY_CRITICAL", False)
                        else "DoIP over Automotive Ethernet"
                        if getattr(target, "ROLE", "") != "hpc"
                        else "Local UDS"
                    )
                )
                transport_chain = " -> ".join(route_transports)
                if transport_chain:
                    transport = transport_chain
                if getattr(target, "ROLE", "") == "ecu" and getattr(
                    target, "SAFETY_CRITICAL", False
                ):
                    message_id = getattr(target, "MESSAGE_ID", None)
                elif "DoIP" in transport:
                    message_id = (
                        f"0x{logical_address:04X}"
                        if type(logical_address) is int
                        else None
                    )
                else:
                    message_id = getattr(
                        type(target), "SOMEIP_SERVICE_ID", None
                    )
                    if type(message_id) is int:
                        message_id = f"0x{message_id:04X}"
                socket_id = _socket_id_for_node(component_id)
                with DIAGNOSTIC_ACTIVITY_LOCK:
                    DIAGNOSTIC_ACTIVITY.append(
                        {
                            "event_type": "diagnostic",
                            "timestamp": time.time(),
                            "phase": SCAN_ACTIVITY_PHASE,
                            "source_node_id": "hpc-vehicle",
                            "target_node_id": component_id,
                            "transport_type": transport,
                            "socket_id": socket_id,
                            "direction": "request / response",
                            "message_id": message_id,
                            "service_id": "0x19",
                            "response_service_id": response_service_id,
                            "status": (
                                "positive"
                                if uds_result.get("positive_response")
                                else "negative"
                            ),
                            "nrc": uds_result.get("nrc"),
                            "latency_ms": round(
                                (time.perf_counter() - request_started) * 1000,
                                3,
                            ),
                        }
                    )
                    del DIAGNOSTIC_ACTIVITY[:-1000]
            if uds_result.get("positive_response"):
                successful_count += 1
                response_categories["positive"] += 1
                active_dtc_count += sum(
                    1 for dtc in uds_result.get("dtcs", []) if dtc.get("active")
                )
            else:
                failed_count += 1
                response_categories["negative"] += 1
        except (TimeoutError, socket.timeout):
            failed_count += 1
            response_categories["timeout"] += 1
            if SCAN_ACTIVITY_PHASE in {"before_attack", "after_attack"}:
                record_diagnostic_failure(component_id, "timeout")
        except (OSError, RuntimeError, ValueError):
            failed_count += 1
            response_categories["transport_error"] += 1
            if SCAN_ACTIVITY_PHASE in {"before_attack", "after_attack"}:
                record_diagnostic_failure(component_id, "transport_error")
    component_count = len(NODE_INSTANCES)
    return {
        "component_count": component_count,
        "successful_count": successful_count,
        "failed_count": failed_count,
        "active_dtc_count": active_dtc_count,
        "response_categories": response_categories,
        "timeout_count": response_categories["timeout"],
        "timeout_rate_percent": round(
            response_categories["timeout"] * 100 / max(component_count, 1), 3
        ),
        "ecu_availability_percent": round(
            successful_count * 100 / max(component_count, 1), 3
        ),
        "diagnostic_latency_mean_ms": round(
            sum(latencies_ms) / max(len(latencies_ms), 1), 3
        ),
        "diagnostic_latency_max_ms": round(max(latencies_ms, default=0.0), 3),
        "diagnostic_elapsed_ms": round((time.perf_counter() - started) * 1000, 3),
        "sample_precision": "milliseconds",
    }


def record_diagnostic_failure(component_id: str, status: str) -> None:
    target = NODE_INSTANCES[component_id]
    is_can = (
        getattr(target, "ROLE", "") == "ecu"
        and getattr(target, "SAFETY_CRITICAL", False)
    )
    transport = (
        target.PROTOCOL
        if is_can
        else "DoIP over Automotive Ethernet"
        if getattr(target, "ROLE", "") != "hpc"
        else "Local UDS"
    )
    with DIAGNOSTIC_ACTIVITY_LOCK:
        DIAGNOSTIC_ACTIVITY.append(
            {
                "event_type": "diagnostic",
                "timestamp": time.time(),
                "phase": SCAN_ACTIVITY_PHASE,
                "source_node_id": "hpc-vehicle",
                "target_node_id": component_id,
                "transport_type": transport,
                "socket_id": _socket_id_for_node(component_id),
                "direction": "request / response",
                "message_id": getattr(target, "MESSAGE_ID", None),
                "service_id": "0x19",
                "response_service_id": None,
                "status": status,
                "nrc": None,
                "latency_ms": None,
            }
        )
        del DIAGNOSTIC_ACTIVITY[:-1000]


def _request_signal_over_someip(target_node_id, signal_name, requester_node_id="hpc-vehicle"):
    if target_node_id not in NODE_INSTANCES or NODES[target_node_id]["role"] not in {"zone_controller", "hpc"}:
        raise ValueError("target_node_id must identify a ZCU or HPC service")
    if not isinstance(signal_name, str) or not signal_name.strip():
        raise ValueError("signal_name must be a non-empty string")
    if requester_node_id not in NODE_INSTANCES or NODES[requester_node_id]["role"] != "hpc":
        raise ValueError("requester_node_id must identify an HPC")
    poll_node_messages()
    target = NODE_INSTANCES[target_node_id]
    requester = NODE_INSTANCES[requester_node_id]
    request_packet_hex = requester.build_someip_signal_request(target, signal_name)
    if os.getenv("VEHICLE_NODE_SOCKET_ROUTING") == "1":
        response = _send_node_socket(
            target_node_id,
            {
                "action": "someip_request",
                "requester_node_id": requester_node_id,
                "target_node_id": target_node_id,
                "someip_request_packet_hex": request_packet_hex,
            },
        )
    else:
        response = _send_internal_socket(
            HPC_INGRESS_PORT,
            {
                "action": "someip_request",
                "requester_node_id": requester_node_id,
                "target_node_id": target_node_id,
                "someip_request_packet_hex": request_packet_hex,
            },
        )
    if not response or response.get("status") != "ok":
        raise RuntimeError((response or {}).get("message", "SOME/IP service did not respond"))
    service_response = response.get("service_response")
    if not isinstance(service_response, dict):
        raise RuntimeError("SOME/IP service returned an invalid response")
    response_packet_hex = service_response.get("someip_response_packet_hex")
    if not isinstance(response_packet_hex, str):
        raise RuntimeError("SOME/IP service response packet is missing")
    service_name = signal_name[:80]
    _record_someip_socket_activity(
        requester_node_id,
        target_node_id,
        request_packet_hex,
        "sent",
        f"SOME/IP signal request: {service_name}",
    )
    _record_someip_socket_activity(
        target_node_id,
        requester_node_id,
        response_packet_hex,
        "received",
        f"SOME/IP signal response: {'found' if service_response.get('found') else 'not found'}",
    )
    return service_response


@app.post("/signals/read")
def read_signal_service():
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"status": "error", "message": "Request body must be a JSON object"}), 400
    try:
        result = _request_signal_over_someip(
            payload.get("target_node_id"),
            payload.get("signal_name"),
            payload.get("requester_node_id", "hpc-vehicle"),
        )
    except PermissionError as exc:
        return jsonify({"status": "error", "message": str(exc)}), 403
    except ValueError as exc:
        return jsonify({"status": "error", "message": str(exc)}), 400
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 503
    if not result.get("found"):
        return jsonify(result), 404
    return jsonify(result)


def _hpc_sovd_transport() -> Dict[str, Any]:
    def can_uds(source_hpc_id, target_ecu_id, request_bytes, context=None):
        response = _send_internal_socket(CAN_SOCKET_PORT, {"action": "uds_request", "source_node_id": source_hpc_id, "target_node_id": target_ecu_id, "request_bytes": request_bytes, "context": context})
        if not response or response.get("status") != "ok":
            raise RuntimeError((response or {}).get("message", "HPC CAN UDS transport failed"))
        return response

    def doip(source_hpc_id, target_zcu_id, target_component_id, request_bytes, context=None):
        source = NODE_INSTANCES[source_hpc_id]
        target = NODE_INSTANCES[target_component_id]
        source_address = getattr(type(source), "DOIP_LOGICAL_ADDRESS", None)
        target_address = getattr(type(target), "DOIP_LOGICAL_ADDRESS", None)
        if source_address is None or target_address is None:
            raise ValueError("DoIP logical address is missing from an HPC or target node")
        packet = struct.pack("!BBHIHH", 0x02, 0xFD, 0x8001, len(request_bytes) + 4, source_address, target_address) + bytes(request_bytes)
        response = _send_internal_socket(DOIP_SOCKET_PORT, {"action": "doip_diagnostic", "source_hpc_id": source_hpc_id, "target_zcu_id": target_zcu_id, "target_component_id": target_component_id, "context": context, "doip_packet_hex": packet.hex().upper()})
        if not response or response.get("status") != "ok":
            raise RuntimeError((response or {}).get("message", "DoIP diagnostic transport failed"))
        return response

    def peer_sovd(source_hpc_id, target_hpc_id, sovd_request):
        source = NODE_INSTANCES[source_hpc_id]
        target = NODE_INSTANCES[target_hpc_id]
        packet_hex = source.build_someip_sovd_request(target, sovd_request)
        response = _send_internal_socket(HPC_INGRESS_PORT, {"action": "hpc_sovd_request", "source_hpc_id": source_hpc_id, "target_hpc_id": target_hpc_id, "someip_packet_hex": packet_hex, "sovd_request": sovd_request})
        if not response or response.get("status") != "ok":
            raise RuntimeError((response or {}).get("message", "peer HPC SOME/IP request failed"))
        return response["sovd_response"]

    return {"can_uds": can_uds, "doip": doip, "peer_sovd": peer_sovd}


def _dispatch_sovd_request(payload: Dict[str, Any]) -> Dict[str, Any]:
    gateway_id = payload.get("gateway_hpc_id", "hpc-vehicle")
    if os.getenv("VEHICLE_NODE_SOCKET_ROUTING") == "1":
        return _send_node_socket(
            gateway_id, {"action": "sovd_request", **payload}
        )
    gateway = NODE_INSTANCES.get(gateway_id)
    if gateway is None or getattr(gateway, "ROLE", "") != "hpc":
        raise ValueError("gateway_hpc_id must identify a registered HPC")
    return gateway.handle_sovd_request(payload, NODE_INSTANCES, _hpc_sovd_transport())


class NetworkSocketHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        while True:
            frame = self.rfile.readline(MAX_FRAME_BYTES + 1)
            if not frame:
                return
            if len(frame) > MAX_FRAME_BYTES or not frame.endswith(b"\n"):
                return
            request_id = None
            try:
                payload = json.loads(frame)
                if not isinstance(payload, dict):
                    raise ValueError("frame must contain a JSON object")
                request_id = payload.get("request_id")
                if not verify_request(payload):
                    response = {"request_id": request_id, "timestamp": int(time.time()), "status": "error", "message": "socket authentication failed"}
                else:
                    listening_port = self.server.server_address[1]
                    if listening_port == ZCU_HPC_TCP_SOCKET_PORT:
                        node_role = getattr(
                            NODE_INSTANCES.get(VEHICLE_NODE_ID), "ROLE", ""
                        )
                        source_id = (
                            payload.get("source_zcu_id")
                            if payload.get("action") == "zcu_relay"
                            else payload.get("source_hpc_id")
                        )
                        source_role = NODES.get(source_id, {}).get("role")
                        allowed_link_action = (
                            node_role == "hpc"
                            and payload.get("action") == "zcu_relay"
                            and source_role == "zone_controller"
                            and VEHICLE_NODE_ID in NODES[source_id]["connected_to"]
                        ) or (
                            node_role == "zone_controller"
                            and payload.get("action")
                            in {"doip_diagnostic", "doip_diagnostic_batch"}
                            and source_role == "hpc"
                        ) or (
                            node_role == "zone_controller"
                            and payload.get("action") == "receive_message"
                            and source_role == "hpc"
                            and source_id in NODES[VEHICLE_NODE_ID]["connected_to"]
                        )
                        if not allowed_link_action:
                            raise PermissionError(
                                "HPC-ZCU socket accepts authorized ZCU/HPC link traffic only"
                            )
                    if listening_port == CLOUD_HPC_SOCKET_PORT and (
                        getattr(NODE_INSTANCES.get(VEHICLE_NODE_ID), "ROLE", "")
                        != "hpc"
                        or payload.get("action")
                        in {"zcu_relay", "hpc_peer_messages"}
                    ):
                        raise PermissionError(
                            "Cloud-HPC socket does not accept peer relay traffic"
                        )
                    response = {"request_id": request_id, "timestamp": int(time.time()), "status": "ok", "data": socket_action(payload)}
            except Exception as exc:
                response = {"request_id": request_id, "timestamp": int(time.time()), "status": "error", "message": str(exc)}
            try:
                encoded = json.dumps(sign_payload(response)).encode("utf-8") + b"\n"
            except RuntimeError:
                encoded = b'{"status":"error","message":"socket authentication is not configured"}\n'
            if len(encoded) > MAX_FRAME_BYTES:
                encoded = json.dumps(sign_payload({"request_id": request_id, "timestamp": int(time.time()), "status": "error", "message": "response too large"})).encode("utf-8") + b"\n"
            self.wfile.write(encoded)
            self.wfile.flush()


class NodeCanSocketHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        while True:
            frame = self.rfile.readline(MAX_FRAME_BYTES + 1)
            if not frame:
                return
            if len(frame) > MAX_FRAME_BYTES or not frame.endswith(b"\n"):
                return
            request_id = None
            try:
                payload = json.loads(frame)
                if not isinstance(payload, dict):
                    raise ValueError("CAN socket frame must contain a JSON object")
                request_id = payload.get("request_id")
                if not verify_request(payload):
                    raise PermissionError("CAN socket authentication failed")
                if payload.get("action") not in {
                    "can_frames",
                    "can_uds",
                    "can_uds_batch",
                    "hpc_uds",
                    "hpc_uds_batch",
                }:
                    raise ValueError(
                        "node CAN socket accepts CAN frames and routed UDS only"
                    )
                response = {
                    "request_id": request_id,
                    "timestamp": int(time.time()),
                    "status": "ok",
                    "data": socket_action(payload),
                }
            except Exception as exc:
                response = {
                    "request_id": request_id,
                    "timestamp": int(time.time()),
                    "status": "error",
                    "message": str(exc),
                }
            encoded = json.dumps(sign_payload(response)).encode("utf-8") + b"\n"
            if len(encoded) > MAX_FRAME_BYTES:
                return
            self.wfile.write(encoded)
            self.wfile.flush()


class HpcIngressSocketHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        while True:
            frame = self.rfile.readline(MAX_FRAME_BYTES + 1)
            if not frame:
                return
            if len(frame) > MAX_FRAME_BYTES or not frame.endswith(b"\n"):
                return
            request_id = None
            try:
                payload = json.loads(frame)
                if not isinstance(payload, dict) or payload.get("action") not in {"zcu_messages", "hpc_peer_messages"}:
                    if isinstance(payload, dict) and payload.get("action") in {"someip_request", "hpc_sovd_request"}:
                        request_id = payload.get("request_id")
                        if verify_request(payload):
                            if payload["action"] == "someip_request":
                                target = NODE_INSTANCES.get(payload.get("target_node_id"))
                                if target is None:
                                    raise ValueError("unknown SOME/IP service target")
                                response = target.handle_someip_signal_request(
                                    payload, NODE_INSTANCES
                                )
                            else:
                                target = NODE_INSTANCES.get(payload.get("target_hpc_id"))
                                if target is None:
                                    raise ValueError("unknown HPC SOVD target")
                                response = target.handle_someip_sovd_request(
                                    payload, NODE_INSTANCES, _hpc_sovd_transport()
                                )
                        else:
                            response = {"request_id": request_id, "timestamp": int(time.time()), "status": "error", "message": "SOME/IP request authentication failed"}
                        encoded = json.dumps(sign_payload(response)).encode("utf-8") + b"\n"
                        self.wfile.write(encoded)
                        self.wfile.flush()
                        continue
                    raise ValueError("invalid HPC ingress frame")
                request_id = payload.get("request_id")
                if not verify_request(payload):
                    raise PermissionError("HPC ingress authentication failed")
                action = payload["action"]
                source_id = payload.get("source_node_id") if action == "zcu_messages" else payload.get("source_hpc_id")
                messages = payload.get("messages")
                if not isinstance(messages, list) or not messages or len(messages) > 512:
                    raise ValueError("messages must be a non-empty bounded array")
                accepted = []
                dropped = 0
                if action == "hpc_peer_messages":
                    hpc_receiver = NODE_INSTANCES["hpc-vehicle"]
                    for relay in messages:
                        reason, origin_id, origin = hpc_receiver.validate_service_relay(
                            relay, NODE_INSTANCES, socket_secret(), "hpc"
                        )
                        if reason is None and relay.get("relayed_by_hpc_id") != source_id:
                            reason = "HPC relay source does not match socket source"
                        if reason is None:
                            reason = _validate_message(origin_id, origin, "can", source_id, check_periodicity=False, sequence_scope=f"hpc-peer-relay:{source_id}")
                        if reason:
                            category = "invalid_authentication" if "auth" in reason or "source" in reason or "authorization" in reason else "someip_header_mismatch"
                            _raise_security_event(origin_id or source_id, hpc_receiver.NODE_ID, category, reason, relay)
                            dropped += 1
                            continue
                        accepted.append({**origin, "relayed_by_hpc_id": source_id, "received_by_hpc_id": "hpc-vehicle", "rx_transport": "SOME/IP over TCP"})
                    if accepted:
                        NODE_INSTANCES["hpc-vehicle"].receive_hpc_peer_messages(source_id, accepted)
                        NODE_TRAFFIC_STATS[source_id]["tx_delivered"] += len(accepted)
                    outgoing = []
                else:
                    hpc_receiver = NODE_INSTANCES["hpc-vehicle"]
                    for relay in messages:
                        reason, origin_id, origin = hpc_receiver.validate_service_relay(
                            relay, NODE_INSTANCES, socket_secret(), "zcu"
                        )
                        if reason is None and relay.get("relayed_by_zcu_id") != source_id:
                            reason = "ZCU relay source does not match socket source"
                        if reason:
                            category = "invalid_authentication" if "auth" in reason or "source" in reason or "authorization" in reason else "someip_header_mismatch"
                            _raise_security_event(source_id, hpc_receiver.NODE_ID, category, reason, relay)
                            dropped += 1
                            continue
                        reason = _validate_message(source_id, origin, "someip", "hpc-vehicle") if origin_id == source_id else _validate_message(origin_id, origin, "can", source_id, check_periodicity=False, sequence_scope=f"zcu-relay:{source_id}")
                        if reason:
                            category = "periodicity_violation" if "periodicity" in reason or "periodic" in reason else "signal_out_of_range" if "signal" in reason or "threshold" in reason else "can_id_mismatch" if "identifier" in reason else "invalid_authentication" if "authentication" in reason else "someip_header_mismatch"
                            _raise_security_event(origin_id or source_id, "hpc-vehicle", category, reason, origin)
                            dropped += 1
                            continue
                        accepted.append({**origin, "relayed_by_zcu_id": source_id, "received_by_hpc_id": "hpc-vehicle", "rx_transport": "SOME/IP over TCP"})
                    if accepted:
                        NODE_INSTANCES["hpc-vehicle"].receive_zcu_messages(source_id, accepted)
                        NODE_TRAFFIC_STATS[source_id]["tx_delivered"] += len(accepted)
                    connected_hpcs = set(NODES[source_id]["connected_to"] or [])
                    outgoing = [message for hpc_id in connected_hpcs if hpc_id in PENDING_HPC_MESSAGES for message in PENDING_HPC_MESSAGES[hpc_id]]
                response = {"request_id": request_id, "timestamp": int(time.time()), "status": "ok", "accepted_messages": len(accepted), "dropped_messages": dropped, "hpc_messages": outgoing}
            except Exception as exc:
                response = {"request_id": request_id, "timestamp": int(time.time()), "status": "error", "message": str(exc)}
            try:
                encoded = json.dumps(sign_payload(response)).encode("utf-8") + b"\n"
            except RuntimeError:
                encoded = b'{"status":"error","message":"socket authentication is not configured"}\n'
            if len(encoded) > MAX_FRAME_BYTES:
                return
            self.wfile.write(encoded)
            self.wfile.flush()


class DoIPSocketHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        while True:
            frame = self.rfile.readline(MAX_FRAME_BYTES + 1)
            if not frame:
                return
            if len(frame) > MAX_FRAME_BYTES or not frame.endswith(b"\n"):
                return
            request_id = None
            try:
                payload = json.loads(frame)
                action = payload.get("action") if isinstance(payload, dict) else None
                if action not in {"doip_diagnostic", "doip_diagnostic_batch"}:
                    raise ValueError("invalid DoIP diagnostic envelope")
                request_id = payload.get("request_id")
                if not verify_request(payload):
                    raise PermissionError("DoIP socket authentication failed")
                source_hpc_id = payload.get("source_hpc_id")
                zcu_id = payload.get("target_zcu_id")
                component_id = payload.get("target_component_id")
                if source_hpc_id not in NODES or NODES[source_hpc_id]["role"] != "hpc" or zcu_id not in NODES or NODES[zcu_id]["role"] != "zone_controller":
                    raise ValueError("DoIP source or ZCU is not registered")
                if source_hpc_id not in NODES[zcu_id]["connected_to"]:
                    raise PermissionError("HPC is not connected to target ZCU")
                source_node = NODE_INSTANCES[source_hpc_id]
                packet_hexes = (
                    payload.get("doip_packet_hexes")
                    if action == "doip_diagnostic_batch"
                    else [payload.get("doip_packet_hex", "")]
                )
                if not isinstance(packet_hexes, list) or not 1 <= len(packet_hexes) <= 512:
                    raise ValueError("DoIP packet batch must contain 1 to 512 packets")

                def send_can_uds(zcu_source, ecu_target, uds_request, context=None):
                    can_response = _send_internal_socket(CAN_SOCKET_PORT, {"action": "uds_request", "source_node_id": zcu_source, "target_node_id": ecu_target, "request_bytes": uds_request, "context": context})
                    if not can_response or can_response.get("status") != "ok":
                        raise RuntimeError((can_response or {}).get("message", "ZCU CAN UDS request failed"))
                    return can_response

                uds_results = []
                doip_response_hexes = []
                for packet_hex in packet_hexes:
                    packet = bytes.fromhex(packet_hex)
                    if len(packet) < 12:
                        raise ValueError("DoIP packet is truncated")
                    version, inverse, payload_type, payload_length = struct.unpack("!BBHI", packet[:8])
                    source_address, target_address = struct.unpack("!HH", packet[8:12])
                    addressed_node = next((node for node in NODE_INSTANCES.values() if getattr(type(node), "DOIP_LOGICAL_ADDRESS", None) == target_address), None)
                    if version != 0x02 or inverse != 0xFD or payload_type != 0x8001 or payload_length != len(packet) - 8:
                        raise ValueError("DoIP protocol version, payload type, or payload length is invalid")
                    if source_address != source_node.DOIP_LOGICAL_ADDRESS or addressed_node is None or addressed_node.NODE_ID != component_id:
                        raise ValueError("DoIP source or target logical address does not match the route")
                    context = payload.get("context")
                    _record_doip_socket_activity(
                        source_hpc_id,
                        zcu_id,
                        component_id,
                        packet_hex,
                        "sent",
                        context if isinstance(context, dict) else None,
                        phase=payload.get("phase"),
                    )
                    routed = NODE_INSTANCES[zcu_id].handle_doip_request(
                        packet,
                        NODE_INSTANCES,
                        send_can_uds,
                        context,
                    )
                    uds_result = routed["uds_result"]
                    uds_results.append(uds_result)
                    uds_response = bytes(uds_result.get("response_bytes", []))
                    doip_response = struct.pack(
                        "!BBHIHH",
                        0x02,
                        0xFD,
                        0x8001,
                        len(uds_response) + 4,
                        addressed_node.DOIP_LOGICAL_ADDRESS,
                        source_node.DOIP_LOGICAL_ADDRESS,
                    ) + uds_response
                    response_hex = doip_response.hex().upper()
                    doip_response_hexes.append(response_hex)
                    _record_doip_socket_activity(
                        zcu_id,
                        source_hpc_id,
                        component_id,
                        response_hex,
                        "received",
                        context if isinstance(context, dict) else None,
                        f"DoIP UDS response: {uds_result.get('service_name', 'UDS')}; "
                        f"{'positive' if uds_result.get('positive_response') else 'negative'}",
                        payload.get("phase"),
                    )
                if action == "doip_diagnostic_batch":
                    response = {"request_id": request_id, "timestamp": int(time.time()), "status": "ok", "uds_results": uds_results, "doip_response_packet_hexes": doip_response_hexes, "route": [source_hpc_id, zcu_id, component_id]}
                else:
                    response = {"request_id": request_id, "timestamp": int(time.time()), "status": "ok", "uds_result": uds_results[0], "doip_request_packet_hex": packet_hexes[0], "doip_response_packet_hex": doip_response_hexes[0], "route": [source_hpc_id, zcu_id, component_id]}
            except Exception as exc:
                response = {"request_id": request_id, "timestamp": int(time.time()), "status": "error", "message": str(exc)}
            encoded = json.dumps(sign_payload(response)).encode("utf-8") + b"\n"
            if len(encoded) > MAX_FRAME_BYTES:
                return
            self.wfile.write(encoded)
            self.wfile.flush()


class CanBusSocketHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        while True:
            frame = self.rfile.readline(MAX_FRAME_BYTES + 1)
            if not frame:
                return
            if len(frame) > MAX_FRAME_BYTES or not frame.endswith(b"\n"):
                return
            request_id = None
            try:
                payload = json.loads(frame)
                if not isinstance(payload, dict):
                    raise ValueError("CAN socket frame must be a JSON object")
                request_id = payload.get("request_id")
                if not verify_request(payload):
                    raise PermissionError("CAN bus authentication failed")
                if payload.get("action") in {"uds_request", "uds_security_probe", "uds_batch"}:
                    source_id = payload.get("source_node_id")
                    target_id = payload.get("target_node_id")
                    request_bytes = payload.get("request_bytes")
                    source = NODE_INSTANCES.get(source_id)
                    target = NODE_INSTANCES.get(target_id)
                    if target is None:
                        raise PermissionError("UDS-over-CAN target is not registered")
                    route_authorized = target.authorize_uds_route(source)
                    if route_authorized:
                        _record_uds_security_result(
                            target_id,
                            source_id if isinstance(source_id, str) else None,
                            {
                                "service_name": "UDSRoute",
                                "security_bypasses": list(
                                    getattr(target, "_accepted_profile_bypasses", ())
                                ),
                            },
                        )
                    if not route_authorized:
                        raise PermissionError("UDS-over-CAN route violates ECU safety/zonal hierarchy")
                    if payload.get("action") == "uds_batch":
                        requests = payload.get("requests")
                        uds_results = target.handle_uds_batch(requests)
                        for uds_result in uds_results:
                            _record_uds_security_result(
                                target_id,
                                source_id
                                if isinstance(source_id, str)
                                else None,
                                uds_result,
                            )
                        response = {
                            "request_id": request_id,
                            "timestamp": int(time.time()),
                            "status": "ok",
                            "uds_results": uds_results,
                            "source_node_id": source_id,
                            "target_node_id": target_id,
                        }
                        self.wfile.write(
                            json.dumps(sign_payload(response)).encode("utf-8")
                            + b"\n"
                        )
                        self.wfile.flush()
                        continue
                    if payload.get("action") == "uds_security_probe":
                        if payload.get("sandboxed_uds_probe") is not True:
                            raise PermissionError(
                                "SecurityAccess simulation probes must use isolated ECU state"
                            )
                        probe = target.sandboxed_security_access_probe()
                        response = {
                            "request_id": request_id,
                            "timestamp": int(time.time()),
                            "status": "ok",
                            **probe,
                            "source_node_id": source_id,
                            "target_node_id": target_id,
                        }
                        self.wfile.write(
                            json.dumps(sign_payload(response)).encode("utf-8")
                            + b"\n"
                        )
                        self.wfile.flush()
                        continue
                    if payload.get("sandboxed_uds_probe") is True:
                        uds_result = target.sandboxed_uds_request(
                            request_bytes
                        )
                    else:
                        uds_result = target.handle_uds_request(
                            request_bytes, payload.get("context")
                        )
                    _record_uds_security_result(
                        target_id,
                        source_id if isinstance(source_id, str) else None,
                        uds_result,
                    )
                    response = {"request_id": request_id, "timestamp": int(time.time()), "status": "ok", "uds_result": uds_result, "source_node_id": source_id, "target_node_id": target_id}
                    self.wfile.write(json.dumps(sign_payload(response)).encode("utf-8") + b"\n")
                    self.wfile.flush()
                    continue
                if payload.get("action") != "can_frames":
                    raise ValueError("invalid CAN bus frame envelope")
                source_id = payload.get("source_node_id")
                frames = payload.get("frames")
                if source_id not in NODES or not isinstance(frames, list) or len(frames) > 2048:
                    raise ValueError("CAN frame source or batch is invalid")
                delivered: Dict[str, list[Dict[str, Any]]] = {}
                accepted_count = 0
                dropped_count = 0
                for message in frames:
                    NODE_TRAFFIC_STATS[source_id]["tx_generated"] += 1
                    recipients = message.get("recipient_node_ids", []) if isinstance(message, dict) else []
                    if not isinstance(recipients, list) or not recipients:
                        _raise_security_event(source_id, source_id, "invalid_route", "CAN message has no receiver", message)
                        _record_socket_activity(
                            _socket_id_for_node(source_id),
                            source_id,
                            source_id,
                            "dropped",
                            message if isinstance(message, dict) else None,
                            "CAN message has no receiver",
                        )
                        dropped_count += 1
                        continue
                    for receiver_id in recipients:
                        reason = _validate_message(source_id, message, "can", receiver_id)
                        socket_id = (
                            "zcu-can"
                            if NODES.get(receiver_id, {}).get("role")
                            == "zone_controller"
                            else "hpc-can"
                            if NODES.get(receiver_id, {}).get("role") == "hpc"
                            else _socket_id_for_node(source_id)
                        )
                        if reason:
                            category = "replay_detected" if "replay" in reason or "out-of-order" in reason else "periodicity_violation" if "periodicity" in reason or "periodic" in reason else "signal_out_of_range" if "signal" in reason or "threshold" in reason else "can_id_mismatch" if "identifier" in reason else "invalid_authentication" if "authentication" in reason else "invalid_route"
                            _raise_security_event(source_id, receiver_id, category, reason, message)
                            _record_socket_activity(
                                socket_id,
                                source_id,
                                receiver_id,
                                "dropped",
                                message,
                                reason,
                            )
                            dropped_count += 1
                            continue
                        received = dict(message)
                        received["direction"] = "rx"
                        received["received_by_node_id"] = receiver_id
                        received["received_at_monotonic_ms"] = round(time.monotonic() * 1000, 3)
                        delivered.setdefault(receiver_id, []).append(received)
                        _record_socket_activity(
                            socket_id,
                            source_id,
                            receiver_id,
                            "accepted",
                            received,
                            "CAN frame accepted by simulator receiver",
                        )
                        accepted_count += 1
                for receiver_id, received_messages in delivered.items():
                    _store_received_messages(receiver_id, received_messages)
                    NODE_TRAFFIC_STATS[source_id]["tx_delivered"] += len(received_messages)
                    if receiver_id == "hpc-vehicle":
                        NODE_INSTANCES[receiver_id].receive_direct_can_messages(received_messages)
                    elif NODES[receiver_id]["role"] == "hpc":
                        forwarded = []
                        for index, received_message in enumerate(received_messages):
                            tx_message = {key: value for key, value in received_message.items() if key not in {"direction", "received_by_node_id", "received_at_monotonic_ms"}}
                            tx_message["direction"] = "tx"
                            forwarded.append(_encode_service_relay(receiver_id, tx_message, index, socket_secret(), "hpc"))
                        _send_internal_socket(HPC_INGRESS_PORT, {"action": "hpc_peer_messages", "source_hpc_id": receiver_id, "messages": forwarded})
                response = {"request_id": request_id, "timestamp": int(time.time()), "status": "ok", "accepted_frames": accepted_count, "dropped_frames": dropped_count, "delivered": [{"node_id": node_id, "messages": messages} for node_id, messages in delivered.items()]}
            except Exception as exc:
                response = {"request_id": request_id, "timestamp": int(time.time()), "status": "error", "message": str(exc)}
            try:
                encoded = json.dumps(sign_payload(response)).encode("utf-8") + b"\n"
            except RuntimeError:
                encoded = b'{"status":"error","message":"socket authentication is not configured"}\n'
            if len(encoded) > MAX_FRAME_BYTES:
                return
            self.wfile.write(encoded)
            self.wfile.flush()


class NetworkTCPServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


@app.get("/")
def root():
    return jsonify({"service": "vehicle-network", "status": "ok", "transport": "authenticated_read_only_socket"})


@app.get("/health")
def health():
    if VEHICLE_NODE_ID is not None:
        return jsonify(
            {
                "service": "vehicle-node",
                "node_id": VEHICLE_NODE_ID,
                "status": "ok",
                "socket_status": SOCKET_STATUS,
                "socket_port": SOCKET_PORT,
            }
        )
    topology = build_topology()
    return jsonify(
        {
            "service": "vehicle-network",
            "status": "ok",
            "node_count": len(topology["nodes"]),
            "zone_count": len(topology["zones"]),
            "socket_status": SOCKET_STATUS,
            "socket_port": SOCKET_PORT,
            "hpc_ingress_status": HPC_INGRESS_STATUS,
            "hpc_ingress_host": HPC_INGRESS_HOST,
            "hpc_ingress_port": HPC_INGRESS_PORT,
            "can_socket_status": CAN_SOCKET_STATUS,
            "can_socket_host": CAN_SOCKET_HOST,
            "can_socket_port": CAN_SOCKET_PORT,
            "doip_socket_status": DOIP_SOCKET_STATUS,
            "doip_socket_host": DOIP_SOCKET_HOST,
            "doip_socket_port": DOIP_SOCKET_PORT,
            "socket_auth_configured": len(os.getenv("VEHICLE_SOCKET_SECRET", "")) >= 32,
            "hpc_aggregate_nodes": topology["hpc_vehicle_data"]["node_count"],
            "scheduler_running": bool(SCHEDULER_THREAD and SCHEDULER_THREAD.is_alive()),
        }
    )


@app.get("/network/topology")
def get_topology():
    return jsonify(build_topology())


if __name__ == "__main__":
    if VEHICLE_NODE_ID is not None:
        node_server = NetworkTCPServer(("0.0.0.0", SOCKET_PORT), NetworkSocketHandler)
        SOCKET_STATUS = "listening"
        threading.Thread(
            target=node_server.serve_forever,
            name=f"{VEHICLE_NODE_ID}-socket",
            daemon=True,
        ).start()
        node_role = getattr(NODE_INSTANCES[VEHICLE_NODE_ID], "ROLE", "")
        if node_role in {"zone_controller", "hpc"}:
            can_server = NetworkTCPServer(
                ("0.0.0.0", ZCU_CAN_SOCKET_PORT), NodeCanSocketHandler
            )
            CAN_SOCKET_STATUS = "listening"
            threading.Thread(
                target=can_server.serve_forever,
                name=f"{VEHICLE_NODE_ID}-can-socket",
                daemon=True,
            ).start()
            zcu_hpc_server = NetworkTCPServer(
                ("0.0.0.0", ZCU_HPC_TCP_SOCKET_PORT), NetworkSocketHandler
            )
            ZCU_HPC_TCP_SOCKET_STATUS = "listening"
            threading.Thread(
                target=zcu_hpc_server.serve_forever,
                name=f"{VEHICLE_NODE_ID}-zcu-hpc-socket",
                daemon=True,
            ).start()
        if node_role == "hpc":
            cloud_hpc_server = NetworkTCPServer(
                ("0.0.0.0", CLOUD_HPC_SOCKET_PORT), NetworkSocketHandler
            )
            CLOUD_HPC_SOCKET_STATUS = "listening"
            threading.Thread(
                target=cloud_hpc_server.serve_forever,
                name=f"{VEHICLE_NODE_ID}-cloud-hpc-socket",
                daemon=True,
            ).start()
        SCHEDULER_THREAD = threading.Thread(
            target=schedule_single_node_messages,
            name=f"{VEHICLE_NODE_ID}-scheduler",
            daemon=True,
        )
        SCHEDULER_THREAD.start()
        try:
            node_server.serve_forever()
        finally:
            SCHEDULER_STOP.set()
        raise SystemExit(0)

    def schedule_messages() -> None:
        while not SCHEDULER_STOP.is_set():
            poll_node_messages()
            time.sleep(0.005)

    if os.getenv("VEHICLE_NODE_SOCKET_ROUTING") != "1":
        SCHEDULER_THREAD = threading.Thread(target=schedule_messages, name="vehicle-node-scheduler", daemon=True)
        SCHEDULER_THREAD.start()
    server = NetworkTCPServer(("0.0.0.0", SOCKET_PORT), NetworkSocketHandler)
    SOCKET_STATUS = "listening"
    threading.Thread(target=server.serve_forever, daemon=True).start()
    if os.getenv("VEHICLE_NODE_SOCKET_ROUTING") != "1":
        ingress_server = NetworkTCPServer(("0.0.0.0", HPC_INGRESS_PORT), HpcIngressSocketHandler)
        HPC_INGRESS_STATUS = "listening"
        threading.Thread(target=ingress_server.serve_forever, daemon=True).start()
        can_server = NetworkTCPServer(("0.0.0.0", CAN_SOCKET_PORT), CanBusSocketHandler)
        CAN_SOCKET_STATUS = "listening"
        threading.Thread(target=can_server.serve_forever, daemon=True).start()
        doip_server = NetworkTCPServer(("0.0.0.0", DOIP_SOCKET_PORT), DoIPSocketHandler)
        DOIP_SOCKET_STATUS = "listening"
        threading.Thread(target=doip_server.serve_forever, daemon=True).start()
    app.run(host="0.0.0.0", port=PORT, debug=os.getenv("FLASK_DEBUG", "0") == "1")
