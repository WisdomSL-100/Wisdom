import base64
import hashlib
import hmac
import json
import os
import ssl
import time

from behavior_analysis.analyzer import MODEL_STATUS
from flask import Flask, jsonify, request
from ota_client.client import flash_firmware
from scanner.diagnostics_client import request_signal, request_sovd_diagnostics
from scanner.service import (
    ATTACK_TYPES,
    MAX_ATTACK_DURATION_SECONDS,
    MIN_ATTACK_DURATION_SECONDS,
    SCAN_MODES,
    SEVERITIES,
    run_scan,
)
from scanner.vehicle_network_client import (
    VEHICLE_NETWORK_SOCKET_HOST,
    VEHICLE_NETWORK_SOCKET_PORT,
    vehicle_network_request,
)

app = Flask(__name__)
PORT = int(os.getenv("PORT", "5002"))
TLS_SERVER_CERT = os.getenv("CENTRAL_TLS_SERVER_CERT", "/run/tls/central-server.crt")
TLS_SERVER_KEY = os.getenv("CENTRAL_TLS_SERVER_KEY", "/run/tls/central-server.key")
TLS_CLIENT_CA = os.getenv("CENTRAL_TLS_CLIENT_CA", "/run/tls/ca.crt")
TLS_ALLOWED_CLIENT_CN = os.getenv("CENTRAL_TLS_ALLOWED_CLIENT_CN", "cloud-app")
JWT_ISSUER = "cloud-app"
JWT_AUDIENCE = "vehicle-central-compute"
JWT_MAX_LIFETIME_SECONDS = 60


def _jwt_secret() -> bytes:
    secret = os.getenv("CENTRAL_SERVICE_JWT_SECRET", "")
    if len(secret.encode("utf-8")) < 32:
        raise RuntimeError(
            "CENTRAL_SERVICE_JWT_SECRET must contain at least 32 bytes"
        )
    return secret.encode("utf-8")


def _decode_base64url(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _valid_cloud_jwt(token: str) -> bool:
    if len(token) > 4096:
        return False
    parts = token.split(".")
    if len(parts) != 3:
        return False
    encoded_header, encoded_claims, encoded_signature = parts
    signing_input = f"{encoded_header}.{encoded_claims}".encode("ascii")
    expected_signature = hmac.new(
        _jwt_secret(), signing_input, hashlib.sha256
    ).digest()
    try:
        supplied_signature = _decode_base64url(encoded_signature)
        header = json.loads(_decode_base64url(encoded_header))
        claims = json.loads(_decode_base64url(encoded_claims))
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
        return False
    if not isinstance(header, dict) or header != {"alg": "HS256", "typ": "JWT"}:
        return False
    if not hmac.compare_digest(expected_signature, supplied_signature):
        return False
    if not isinstance(claims, dict):
        return False
    now = int(time.time())
    issued_at = claims.get("iat")
    expires_at = claims.get("exp")
    return (
        claims.get("iss") == JWT_ISSUER
        and claims.get("sub") == JWT_ISSUER
        and claims.get("aud") == JWT_AUDIENCE
        and isinstance(claims.get("jti"), str)
        and bool(claims["jti"])
        and type(issued_at) is int
        and type(expires_at) is int
        and issued_at <= now + 5
        and expires_at > now
        and expires_at > issued_at
        and expires_at - issued_at <= JWT_MAX_LIFETIME_SECONDS
    )


def mutual_tls_context() -> ssl.SSLContext:
    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(TLS_SERVER_CERT, TLS_SERVER_KEY)
    context.load_verify_locations(cafile=TLS_CLIENT_CA)
    context.verify_mode = ssl.CERT_REQUIRED
    return context


@app.before_request
def require_cloud_service_identity():
    peer_socket = request.environ.get("werkzeug.socket")
    if peer_socket is not None:
        get_peer_certificate = getattr(peer_socket, "getpeercert", None)
        certificate = get_peer_certificate() if callable(get_peer_certificate) else None
        common_names = [
            value
            for rdn in (certificate or {}).get("subject", ())
            for key, value in rdn
            if key == "commonName"
        ]
        if TLS_ALLOWED_CLIENT_CN not in common_names:
            return jsonify({"status": "error", "message": "cloud client certificate identity is required"}), 403
    if request.endpoint == "health":
        return None
    authorization = request.headers.get("Authorization", "")
    scheme, separator, token = authorization.partition(" ")
    if scheme.lower() != "bearer" or not separator or not token:
        return jsonify({"status": "error", "message": "cloud service JWT is required"}), 401
    try:
        valid_token = _valid_cloud_jwt(token)
    except RuntimeError as exc:
        return jsonify({"status": "error", "message": str(exc)}), 503
    if not valid_token:
        return jsonify({"status": "error", "message": "cloud service JWT is invalid or expired"}), 401
    return None


@app.get("/")
def root():
    return jsonify({"service": "vehicle-central-compute", "status": "ok"})


@app.get("/health")
def health():
    return jsonify(
        {
            "status": "ok",
            "service": "vehicle-central-compute",
            "models": MODEL_STATUS,
            "vehicle_network_transport": "tcp_json_lines",
            "vehicle_network_socket": f"{VEHICLE_NETWORK_SOCKET_HOST}:{VEHICLE_NETWORK_SOCKET_PORT}",
        }
    )


@app.get("/architecture")
def architecture():
    node_socket_routing = os.getenv("VEHICLE_NODE_SOCKET_ROUTING", "0") == "1"
    return jsonify(
        {
            "central_compute": {
                "container": "vehicle-central-compute",
                "modules": [
                    {
                        "folder": "scanner/",
                        "responsibility": "Scan orchestration and diagnostic service clients",
                        "entrypoints": [
                            "/scan/start",
                            "/security/profiles",
                            "/sovd/v1/diagnostics",
                            "/signals/read",
                            "/uds/diagnostics",
                            "/uds/<ecu_id>",
                        ],
                    },
                    {
                        "folder": "behavior_analysis/",
                        "responsibility": "Telemetry analysis and risk classification",
                        "entrypoints": ["/scan/start"],
                    },
                    {
                        "folder": "ota_client/",
                        "responsibility": "Simulated firmware update client",
                        "entrypoints": ["/ota/flash"],
                    },
                    {
                        "file": "scanner/hpc_vehicle_model.py",
                        "responsibility": "Standalone companion model; not the active simulator node",
                    },
                ],
            },
            "connections": [
                {
                    "source": "cloud-app / HTTP",
                    "target": "vehicle-central-compute / Flask REST",
                    "transport": "HTTPS/JSON with mutual TLS",
                    "port": PORT,
                },
                {
                    "source": "vehicle-central-compute / scanner/vehicle_network_client.py",
                    "target": "vehicle-network_Simulator / aggregate socket",
                    "transport": "authenticated newline-framed JSON over TCP",
                    "port": VEHICLE_NETWORK_SOCKET_PORT,
                },
                {
                    "source": "vehicle-central-compute / scanner, behavior_analysis, ota_client",
                    "target": "vehicle-node-{node_id} / owning ECU, ZCU, or HPC socket",
                    "transport": "authenticated newline-framed JSON over TCP",
                    "port": int(os.getenv("VEHICLE_NODE_SOCKET_PORT", "6001")),
                    "enabled": node_socket_routing,
                    "routing": (
                        "Target-specific UDS, OTA, SOME/IP, and SOVD requests connect directly to the responsible node container"
                        if node_socket_routing
                        else "Direct node socket routing is disabled; local simulator mode is active"
                    ),
                },
            ],
            "scan_workflow": [
                "Check vehicle service state",
                "Collect full-network diagnostics and behavior baseline",
                "Run bounded simulator-only CAN/CAN-FD, SOME/IP, DoIP, and per-node UDS probes",
                "Run a bounded authorized attack simulation against configured selected nodes",
                "Repeat full-network diagnostics and behavior analysis",
                "Return aggregate analytics and probe counts only",
            ],
            "maximum_attack_duration_seconds": MAX_ATTACK_DURATION_SECONDS,
            "simulation_only": True,
        }
    )


@app.get("/scan/types")
def list_attack_types():
    return jsonify({"attack_types": sorted(ATTACK_TYPES)})


@app.get("/network/snapshot")
def get_vehicle_network_snapshot():
    try:
        return jsonify(vehicle_network_request("snapshot"))
    except Exception as exc:
        print(f"scan failed: {type(exc).__name__}: {exc}", flush=True)
        return jsonify({"status": "error", "message": f"Vehicle network socket unavailable: {exc}"}), 503


@app.get("/signals/catalog")
def get_signal_catalog():
    target_node_id = request.args.get("target_node_id", "")
    if not target_node_id:
        return jsonify(
            {"status": "error", "message": "target_node_id is required"}
        ), 400
    try:
        snapshot = vehicle_network_request("snapshot")
        topology = snapshot.get("network_snapshot", {})
        nodes = topology.get("nodes", []) if isinstance(topology, dict) else []
        node = next(
            (
                item
                for item in nodes
                if isinstance(item, dict)
                and item.get("id") == target_node_id
            ),
            None,
        )
        if node is None:
            return jsonify(
                {"status": "error", "message": "Unknown signal service node"}
            ), 404
        if not node.get("someip_service_id"):
            return jsonify(
                {
                    "status": "error",
                    "message": "Selected node does not provide a SOME/IP signal service",
                }
            ), 400
        signals = node.get("signals", {})
        if not isinstance(signals, dict):
            raise ValueError("Simulator returned an invalid signal catalog")
        return jsonify(
            {
                "status": "ok",
                "target_node_id": target_node_id,
                "signals": sorted(
                    name
                    for name in signals
                    if isinstance(name, str) and name
                ),
            }
        )
    except Exception as exc:
        print(f"signal catalog failed: {type(exc).__name__}: {exc}", flush=True)
        return jsonify(
            {"status": "error", "message": f"SOME/IP signal catalog unavailable: {exc}"}
        ), 503


@app.get("/network/observability")
def get_network_observability():
    try:
        return jsonify(vehicle_network_request("network_observability"))
    except Exception as exc:
        return jsonify(
            {
                "status": "error",
                "message": f"Vehicle network observability unavailable: {exc}",
            }
        ), 503


@app.get("/network/activity")
def get_network_activity():
    try:
        limit = request.args.get("limit", "100")
        if not limit.isdigit() or not 1 <= int(limit) <= 200:
            return jsonify(
                {
                    "status": "error",
                    "message": "limit must be an integer between 1 and 200",
                }
            ), 400
        return jsonify(
            vehicle_network_request(
                "network_activity",
                limit=int(limit),
            )
        )
    except Exception as exc:
        return jsonify(
            {
                "status": "error",
                "message": f"Vehicle network activity unavailable: {exc}",
            }
        ), 503


@app.get("/vehicle/service-state")
def get_vehicle_service_state():
    try:
        return jsonify(vehicle_network_request("vehicle_service_state"))
    except Exception as exc:
        print(f"scan failed: {type(exc).__name__}: {exc}", flush=True)
        return jsonify({"status": "error", "message": f"Vehicle network socket unavailable: {exc}"}), 503


@app.post("/vehicle/service-state")
def set_vehicle_service_state():
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"status": "error", "message": "Request body must be a JSON object"}), 400
    service_state = payload.get("service_state")
    if not isinstance(service_state, str) or service_state not in {"in_service", "out_of_service"}:
        return jsonify(
            {
                "status": "error",
                "message": "service_state must be in_service or out_of_service",
            }
        ), 400
    try:
        return jsonify(
            vehicle_network_request(
                "set_vehicle_service_state", service_state=service_state
            )
        )
    except Exception as exc:
        print(f"scan failed: {type(exc).__name__}: {exc}", flush=True)
        return jsonify({"status": "error", "message": f"Vehicle network socket unavailable: {exc}"}), 503


@app.get("/security/profiles")
def get_security_profiles():
    try:
        return jsonify(vehicle_network_request("security_profiles"))
    except Exception as exc:
        return jsonify({"status": "error", "message": f"Vehicle security profiles unavailable: {exc}"}), 503


@app.post("/security/profiles")
def update_security_profile():
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"status": "error", "message": "Request body must be a JSON object"}), 400
    try:
        profiles = vehicle_network_request(
            "configure_security_profile",
            node_id=payload.get("node_id"),
            security_level=payload.get("security_level"),
            susceptible_attacks=payload.get("susceptible_attacks"),
        )
    except ValueError as exc:
        return jsonify({"status": "error", "message": str(exc)}), 400
    except Exception as exc:
        return jsonify({"status": "error", "message": f"Vehicle security profile update failed: {exc}"}), 503
    return jsonify(profiles)


@app.get("/vehicle/messages")
def get_vehicle_messages():
    try:
        return jsonify(vehicle_network_request("vehicle_messages"))
    except Exception as exc:
        print(f"scan failed: {type(exc).__name__}: {exc}", flush=True)
        return jsonify({"status": "error", "message": f"Vehicle network socket unavailable: {exc}"}), 503


@app.get("/uds/diagnostics")
def get_uds_diagnostics():
    try:
        return jsonify(vehicle_network_request("uds_diagnostics"))
    except Exception as exc:
        return jsonify({"status": "error", "message": f"Vehicle network UDS unavailable: {exc}"}), 503


@app.post("/uds/<ecu_id>")
def send_uds_request(ecu_id: str):
    payload = request.get_json(silent=True) or {}
    if not isinstance(payload, dict):
        return jsonify({"status": "error", "message": "Request body must be a JSON object"}), 400
    try:
        result = vehicle_network_request(
            "uds_request", node_id=ecu_id, request_bytes=payload.get("request_bytes"), context=payload.get("context")
        )
    except ValueError as exc:
        return jsonify({"status": "error", "message": str(exc)}), 400
    except Exception as exc:
        return jsonify({"status": "error", "message": f"Vehicle network UDS unavailable: {exc}"}), 503
    return jsonify(result.get("uds_result", result))


@app.post("/signals/read")
def read_vehicle_signal():
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"status": "error", "message": "Request body must be a JSON object"}), 400
    try:
        result = request_signal(vehicle_network_request, payload)
    except PermissionError as exc:
        return jsonify({"status": "error", "message": str(exc)}), 403
    except ValueError as exc:
        return jsonify({"status": "error", "message": str(exc)}), 400
    except Exception as exc:
        return jsonify({"status": "error", "message": f"SOME/IP signal service unavailable: {exc}"}), 503
    service_response = result.get("service_response")
    if isinstance(service_response, dict):
        result = service_response
    if not result.get("found"):
        return jsonify(result), 404
    return jsonify(result)


@app.post("/sovd/v1/diagnostics")
def sovd_diagnostics_request():
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"status": "error", "message": "Request body must be a JSON object"}), 400
    if not payload.get("component_id"):
        return jsonify({"status": "error", "message": "component_id is required"}), 400
    try:
        result = request_sovd_diagnostics(vehicle_network_request, payload)
    except PermissionError as exc:
        return jsonify({"status": "error", "message": str(exc)}), 403
    except ValueError as exc:
        return jsonify({"status": "error", "message": str(exc)}), 400
    except Exception as exc:
        return jsonify({"status": "error", "message": f"SOVD diagnostic service unavailable: {exc}"}), 503
    status_code = 200 if result.get("status") == "completed" else 422
    return jsonify(result), status_code


@app.post("/ota/flash")
def relay_firmware_update():
    payload = request.get_json(silent=True) or {}
    if not isinstance(payload, dict):
        return jsonify({"status": "error", "message": "Request body must be a JSON object"}), 400
    try:
        result = flash_firmware(vehicle_network_request, payload)
    except PermissionError as exc:
        return jsonify({"status": "rejected", "message": str(exc)}), 403
    except ValueError as exc:
        return jsonify({"status": "rejected", "message": str(exc)}), 400
    except Exception as exc:
        return jsonify({"status": "error", "message": f"Vehicle network OTA relay unavailable: {exc}"}), 503
    status_code = 200 if result.get("status") == "completed" else 422
    return jsonify(result), status_code


@app.post("/scan/start")
def start_scan():
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"status": "error", "message": "Request body must be a JSON object"}), 400
    attack_type = payload.get("attack_type")
    severity = payload.get("severity")
    duration_seconds = payload.get("duration_seconds", 10)
    target_node_ids = payload.get("target_node_ids")
    scan_mode = payload.get("scan_mode", "oem_validation")
    run_baseline_checks = payload.get("run_baseline_checks", True)

    if not isinstance(attack_type, str) or attack_type not in ATTACK_TYPES:
        return jsonify({"status": "error", "message": f"Unsupported attack type: {attack_type}"}), 400
    if not isinstance(severity, str) or severity not in SEVERITIES:
        return jsonify({"status": "error", "message": f"Unsupported severity: {severity}"}), 400
    if not isinstance(scan_mode, str) or scan_mode not in SCAN_MODES:
        return jsonify({"status": "error", "message": f"Unsupported scan_mode: {scan_mode}"}), 400
    if type(run_baseline_checks) is not bool:
        return jsonify({"status": "error", "message": "run_baseline_checks must be a boolean"}), 400
    if type(duration_seconds) is not int or not (
        MIN_ATTACK_DURATION_SECONDS
        <= duration_seconds
        <= MAX_ATTACK_DURATION_SECONDS
    ):
        return jsonify(
            {
                "status": "error",
                "message": (
                    "duration_seconds must be an integer between "
                    f"{MIN_ATTACK_DURATION_SECONDS} and "
                    f"{MAX_ATTACK_DURATION_SECONDS}"
                ),
            }
        ), 400

    if target_node_ids is not None and (
        not isinstance(target_node_ids, list)
        or not target_node_ids
        or len(target_node_ids) > 64
        or any(not isinstance(node_id, str) for node_id in target_node_ids)
        or len(target_node_ids) != len(set(target_node_ids))
    ):
        return jsonify(
            {
                "status": "error",
                "message": "target_node_ids must be a non-empty list of unique node IDs",
            }
        ), 400

    try:
        result = run_scan(
            vehicle_network_request,
            attack_type,
            severity,
            MODEL_STATUS,
            duration_seconds,
            target_node_ids,
            scan_mode,
            run_baseline_checks,
        )
    except PermissionError as exc:
        return jsonify({"status": "rejected", "message": str(exc)}), 409
    except ValueError as exc:
        return jsonify({"status": "error", "message": str(exc)}), 400
    except Exception as exc:
        print(f"scan failed: {type(exc).__name__}: {exc}", flush=True)
        return jsonify({"status": "error", "message": f"Vehicle network socket unavailable: {exc}"}), 503
    return jsonify(result)


@app.post("/scan/stop")
def stop_scan():
    try:
        result = vehicle_network_request("authorized_attack_stop")
    except Exception as exc:
        return jsonify(
            {"status": "error", "message": f"Vehicle network stop request failed: {exc}"}
        ), 503
    status_code = 202 if result.get("status") == "stop_requested" else 409
    return jsonify(result), status_code


if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=PORT,
        debug=os.getenv("FLASK_DEBUG", "0") == "1",
        ssl_context=mutual_tls_context(),
    )
