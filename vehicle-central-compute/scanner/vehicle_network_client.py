import hashlib
import hmac
import json
import os
import socket
import time
from typing import Any, Dict
from uuid import uuid4


VEHICLE_NETWORK_SOCKET_HOST = os.getenv(
    "VEHICLE_NETWORK_SOCKET_HOST", "vehicle-network"
)
VEHICLE_NETWORK_SOCKET_PORT = int(os.getenv("VEHICLE_NETWORK_SOCKET_PORT", "6001"))
MAX_SOCKET_FRAME_BYTES = 8_388_608


def vehicle_network_request(action: str, **parameters: Any) -> Dict[str, Any]:
    host = os.getenv(
        "VEHICLE_NETWORK_SOCKET_HOST", VEHICLE_NETWORK_SOCKET_HOST
    )
    port = int(
        os.getenv(
            "VEHICLE_NETWORK_SOCKET_PORT",
            str(VEHICLE_NETWORK_SOCKET_PORT),
        )
    )
    node_id = None
    if action == "uds_request":
        node_id = parameters.get("node_id")
    elif action == "ota_flash":
        package = parameters.get("package")
        node_id = package.get("target_ecu_id") if isinstance(package, dict) else None
    elif action == "someip_request":
        node_id = parameters.get("target_node_id")
    elif action == "sovd_request":
        node_id = parameters.get("gateway_hpc_id", "hpc-vehicle")
    if (
        os.getenv("VEHICLE_NODE_SOCKET_ROUTING", "0") == "1"
        and isinstance(node_id, str)
    ):
        host = f"{os.getenv('VEHICLE_NODE_HOST_PREFIX', 'vehicle-node-')}{node_id}"
        port = int(os.getenv("VEHICLE_NODE_SOCKET_PORT", "6001"))

    payload = {
        "request_id": uuid4().hex,
        "timestamp": int(time.time()),
        "action": action,
        **parameters,
    }
    secret = os.getenv("VEHICLE_SOCKET_SECRET", "").encode("utf-8")
    if len(secret) < 32:
        raise RuntimeError("VEHICLE_SOCKET_SECRET must contain at least 32 bytes")
    payload["auth"] = hmac.new(
        secret,
        json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    frame = json.dumps(payload).encode("utf-8") + b"\n"
    if len(frame) > MAX_SOCKET_FRAME_BYTES:
        raise ValueError("Vehicle network request exceeds maximum frame size")

    socket_timeout = 10
    requested_duration = parameters.get("duration_seconds")
    if (
        action == "authorized_attack_test"
        and type(requested_duration) is int
        and 1 <= requested_duration <= 60
    ):
        socket_timeout += requested_duration + 30
    elif action in ("network_diagnostics", "snapshot"):
        socket_timeout = 60
    elif action == "ota_flash":
        socket_timeout = 180

    with socket.create_connection(
        (host, port), timeout=socket_timeout
    ) as connection:
        connection.settimeout(socket_timeout)
        with connection.makefile("rwb") as stream:
            stream.write(frame)
            stream.flush()
            response_frame = stream.readline(MAX_SOCKET_FRAME_BYTES + 1)

    if (
        not response_frame
        or len(response_frame) > MAX_SOCKET_FRAME_BYTES
        or not response_frame.endswith(b"\n")
    ):
        raise RuntimeError(
            "Vehicle network returned an invalid or oversized socket frame"
        )
    response = json.loads(response_frame)
    response_auth = response.get("auth")
    unsigned_response = {
        key: value for key, value in response.items() if key != "auth"
    }
    expected_auth = hmac.new(
        secret,
        json.dumps(
            unsigned_response, sort_keys=True, separators=(",", ":")
        ).encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()
    if not isinstance(response_auth, str) or not hmac.compare_digest(
        response_auth, expected_auth
    ):
        raise RuntimeError("Vehicle network socket response authentication failed")
    if response.get("request_id") != payload["request_id"]:
        raise RuntimeError("Vehicle network response request ID did not match")
    if (
        not isinstance(response.get("timestamp"), int)
        or abs(int(time.time()) - response["timestamp"]) > 30
    ):
        raise RuntimeError("Vehicle network socket response is stale")
    if response.get("status") != "ok":
        raise RuntimeError(
            response.get("message", "Vehicle network socket request failed")
        )
    data = response.get("data")
    if not isinstance(data, dict):
        raise RuntimeError("Vehicle network returned an invalid data payload")
    return data
