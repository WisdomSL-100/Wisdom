import copy
import importlib.util
import base64
import hashlib
import hmac
import json
import os
import pathlib
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from uuid import uuid4

PROJECT_ROOT = pathlib.Path(__file__).resolve().parents[1]
NETWORK_DIR = PROJECT_ROOT / "vehicle-network_Simulator"
CENTRAL_DIR = PROJECT_ROOT / "vehicle-central-compute"
sys.path.insert(0, str(NETWORK_DIR))
sys.path.insert(0, str(CENTRAL_DIR))



def security_key_for_seed(node_id, seed):
    return hmac.new(("node-security:" + node_id).encode(), seed, hashlib.sha256).digest()[:8]


def cloud_service_token(secret):
    encode = lambda value: base64.urlsafe_b64encode(
        json.dumps(value, separators=(",", ":"), sort_keys=True).encode()
    ).rstrip(b"=").decode()
    issued_at = int(time.time())
    header = encode({"alg": "HS256", "typ": "JWT"})
    claims = encode(
        {
            "iss": "cloud-app",
            "sub": "cloud-app",
            "aud": "vehicle-central-compute",
            "iat": issued_at,
            "exp": issued_at + 60,
            "jti": uuid4().hex,
        }
    )
    signing_input = f"{header}.{claims}".encode("ascii")
    signature = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
    encoded_signature = base64.urlsafe_b64encode(signature).rstrip(b"=").decode()
    return f"{header}.{claims}.{encoded_signature}"


def create_simulated_ota_package(
    source_hpc_id, zcu_id, target_ecu_id, image, version, software_profile=None
):
    manifest = {
        "ecu_id": target_ecu_id,
        "version": version,
        "image_size": len(image),
        "sha256": hashlib.sha256(image).hexdigest(),
    }
    if software_profile is not None:
        manifest["software_profile"] = software_profile
    signed_manifest = json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    manifest["signature"] = hmac.new(
        ("firmware-signature:" + target_ecu_id).encode(),
        signed_manifest,
        hashlib.sha256,
    ).hexdigest()
    return {
        "source_hpc_id": source_hpc_id,
        "zcu_id": zcu_id,
        "target_ecu_id": target_ecu_id,
        "image_hex": image.hex(),
        "manifest": manifest,
    }


def load_module(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"Unable to load module: {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class VehicleNetworkSocketTests(unittest.TestCase):
    def setUp(self):
        self.previous_secret = os.environ.get("VEHICLE_SOCKET_SECRET")
        self.previous_host = os.environ.get("VEHICLE_NETWORK_SOCKET_HOST")
        self.previous_port = os.environ.get("VEHICLE_NETWORK_SOCKET_PORT")
        self.previous_can_port = os.environ.get("CAN_SOCKET_PORT")
        self.previous_doip_port = os.environ.get("DOIP_SOCKET_PORT")
        self.previous_ingress_port = os.environ.get("HPC_INGRESS_PORT")
        self.previous_node_id = os.environ.get("VEHICLE_NODE_ID")
        self.previous_transport_host = os.environ.get("VEHICLE_NETWORK_TRANSPORT_HOST")
        self.previous_service_state = os.environ.get("VEHICLE_SERVICE_STATE")
        self.previous_jwt_secret = os.environ.get("CENTRAL_SERVICE_JWT_SECRET")
        self.previous_node_socket_routing = os.environ.get(
            "VEHICLE_NODE_SOCKET_ROUTING"
        )
        os.environ["VEHICLE_SOCKET_SECRET"] = "test-only-vehicle-socket-secret-32-bytes-minimum"
        os.environ["CENTRAL_SERVICE_JWT_SECRET"] = (
            "test-central-service-jwt-secret-at-least-32-bytes"
        )
        os.environ["VEHICLE_SERVICE_STATE"] = "out_of_service"

        self.network = load_module(f"network_service_test_{uuid4().hex}", NETWORK_DIR / "network_service.py")
        self.server = self.network.NetworkTCPServer(("127.0.0.1", 0), self.network.NetworkSocketHandler)
        self.ingress_server = self.network.NetworkTCPServer(("127.0.0.1", 0), self.network.HpcIngressSocketHandler)
        self.can_server = self.network.NetworkTCPServer(("127.0.0.1", 0), self.network.CanBusSocketHandler)
        self.doip_server = self.network.NetworkTCPServer(("127.0.0.1", 0), self.network.DoIPSocketHandler)
        self.network.HPC_INGRESS_HOST = "127.0.0.1"
        self.network.HPC_INGRESS_PORT = self.ingress_server.server_address[1]
        self.network.SOCKET_PORT = self.server.server_address[1]
        self.network.HPC_INGRESS_STATUS = "listening"
        self.network.CAN_SOCKET_PORT = self.can_server.server_address[1]
        self.network.CAN_SOCKET_STATUS = "listening"
        self.network.DOIP_SOCKET_PORT = self.doip_server.server_address[1]
        self.network.DOIP_SOCKET_STATUS = "listening"
        os.environ["CAN_SOCKET_PORT"] = str(self.can_server.server_address[1])
        os.environ["DOIP_SOCKET_PORT"] = str(self.doip_server.server_address[1])
        os.environ["HPC_INGRESS_PORT"] = str(self.ingress_server.server_address[1])
        os.environ["VEHICLE_NETWORK_TRANSPORT_HOST"] = "127.0.0.1"
        os.environ["VEHICLE_NETWORK_SOCKET_HOST"] = "127.0.0.1"
        os.environ["VEHICLE_NETWORK_SOCKET_PORT"] = str(self.server.server_address[1])
        self.server_thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.ingress_thread = threading.Thread(target=self.ingress_server.serve_forever, daemon=True)
        self.can_thread = threading.Thread(target=self.can_server.serve_forever, daemon=True)
        self.doip_thread = threading.Thread(target=self.doip_server.serve_forever, daemon=True)
        self.server_thread.start()
        self.ingress_thread.start()
        self.can_thread.start()
        self.doip_thread.start()

        self.central = load_module(
            f"central_service_test_{uuid4().hex}",
            CENTRAL_DIR / "scanner" / "api.py",
        )
        self.client = self.central.app.test_client()
        self.client.environ_base["HTTP_AUTHORIZATION"] = (
            f"Bearer {cloud_service_token(os.environ['CENTRAL_SERVICE_JWT_SECRET'])}"
        )

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.server_thread.join(timeout=2)
        self.ingress_server.shutdown()
        self.ingress_server.server_close()
        self.ingress_thread.join(timeout=2)
        self.can_server.shutdown()
        self.can_server.server_close()
        self.can_thread.join(timeout=2)
        self.doip_server.shutdown()
        self.doip_server.server_close()
        self.doip_thread.join(timeout=2)
        for name, previous in (
            ("VEHICLE_SOCKET_SECRET", self.previous_secret),
            ("VEHICLE_NETWORK_SOCKET_HOST", self.previous_host),
            ("VEHICLE_NETWORK_SOCKET_PORT", self.previous_port),
            ("CAN_SOCKET_PORT", self.previous_can_port),
            ("DOIP_SOCKET_PORT", self.previous_doip_port),
            ("HPC_INGRESS_PORT", self.previous_ingress_port),
            ("VEHICLE_NODE_ID", self.previous_node_id),
            ("VEHICLE_NETWORK_TRANSPORT_HOST", self.previous_transport_host),
            ("VEHICLE_SERVICE_STATE", self.previous_service_state),
            ("CENTRAL_SERVICE_JWT_SECRET", self.previous_jwt_secret),
            ("VEHICLE_NODE_SOCKET_ROUTING", self.previous_node_socket_routing),
        ):
            if previous is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = previous

    def test_single_node_socket_owns_and_routes_its_uds_service(self):
        os.environ["VEHICLE_NODE_ID"] = "ecu-powertrain"
        node_network = load_module(
            f"powertrain_node_service_{uuid4().hex}",
            NETWORK_DIR / "network_service.py",
        )
        self.assertEqual(set(node_network.NODE_INSTANCES), {"ecu-powertrain"})
        self.assertEqual(len(node_network.NODES), 15)

        server = node_network.NetworkTCPServer(
            ("127.0.0.1", 0), node_network.NetworkSocketHandler
        )
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            snapshot = node_network._send_internal_socket(
                port, {"action": "node_snapshot"}
            )
            self.assertEqual(snapshot["status"], "ok")
            self.assertEqual(snapshot["data"]["node_id"], "ecu-powertrain")

            uds_response = node_network._send_internal_socket(
                port,
                {
                    "action": "uds_request",
                    "node_id": "ecu-powertrain",
                    "source_node_id": "hpc-vehicle",
                    "request_bytes": [0x22, 0xF1, 0xB0],
                },
            )
            self.assertEqual(uds_response["status"], "ok")
            self.assertTrue(uds_response["data"]["uds_result"]["positive_response"])

            def send_to_local_node(node_id, payload):
                if node_id == "hpc-vehicle" and payload.get("action") == "hpc_uds":
                    self.assertEqual(
                        payload.get("target_node_id"), "ecu-powertrain"
                    )
                    return node_network.node_socket_action(
                        {
                            "action": "uds_request",
                            "source_node_id": "hpc-vehicle",
                            "request_bytes": payload.get("request_bytes"),
                            "context": payload.get("context"),
                        }
                    )
                if node_id == "hpc-vehicle" and payload.get("action") == "hpc_uds_batch":
                    self.assertEqual(
                        payload.get("target_node_id"), "ecu-powertrain"
                    )
                    return node_network.node_socket_action(
                        {
                            "action": "uds_batch",
                            "source_node_id": "hpc-vehicle",
                            "requests": payload.get("requests"),
                        }
                    )
                self.assertEqual(node_id, "ecu-powertrain")
                response = node_network._send_internal_socket(port, payload)
                if response is None or response.get("status") != "ok":
                    raise RuntimeError(
                        (response or {}).get(
                            "message",
                            f"{node_id} {payload.get('action')} socket request failed",
                        )
                    )
                return response["data"]

            with patch.object(
                node_network,
                "_send_node_socket",
                side_effect=send_to_local_node,
            ), patch.object(
                node_network,
                "_send_controller_can_socket",
                side_effect=send_to_local_node,
            ):
                ota_response = node_network._send_internal_socket(
                    port,
                    {
                        "action": "ota_flash",
                        "package": create_simulated_ota_package(
                            "hpc-vehicle",
                            None,
                            "ecu-powertrain",
                            b"node-owned-firmware",
                            "SIM-2.0",
                        ),
                    },
                )
            self.assertEqual(ota_response["status"], "ok", ota_response)
            self.assertEqual(ota_response["data"]["status"], "completed")
            self.assertEqual(
                [
                    frame["service"]
                    for frame in ota_response["data"]["uds_trace"]
                ],
                ["0x10", "0x27", "0x27", "0x34", "0x36", "0x37"],
            )

            wrong_target = node_network._send_internal_socket(
                port,
                {
                    "action": "uds_request",
                    "node_id": "ecu-battery",
                    "request_bytes": [0x22, 0xF1, 0xB0],
                },
            )
            self.assertEqual(wrong_target["status"], "error")
            self.assertIn("does not match", wrong_target["message"])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
            if self.previous_node_id is None:
                os.environ.pop("VEHICLE_NODE_ID", None)
            else:
                os.environ["VEHICLE_NODE_ID"] = self.previous_node_id

    def test_hpc_sovd_routes_over_zcu_socket_to_owning_ecu_socket(self):
        node_services = {}
        servers = []
        threads = []
        can_servers = []
        can_threads = []
        previous_node_id = os.environ.get("VEHICLE_NODE_ID")
        try:
            for node_id in (
                "hpc-vehicle",
                "zcu-front-right",
                "ecu-body-front",
                "ecu-powertrain",
            ):
                os.environ["VEHICLE_NODE_ID"] = node_id
                service = load_module(
                    f"node_service_{node_id.replace('-', '_')}_{uuid4().hex}",
                    NETWORK_DIR / "network_service.py",
                )
                server = service.NetworkTCPServer(
                    ("127.0.0.1", 0), service.NetworkSocketHandler
                )
                service.SOCKET_PORT = server.server_address[1]
                thread = threading.Thread(
                    target=server.serve_forever, daemon=True
                )
                thread.start()
                node_services[node_id] = service
                servers.append(server)
                threads.append(thread)
                if node_id.startswith(("hpc-", "zcu-")):
                    can_server = service.NetworkTCPServer(
                        ("127.0.0.1", 0), service.NodeCanSocketHandler
                    )
                    service.ZCU_CAN_SOCKET_PORT = can_server.server_address[1]
                    can_thread = threading.Thread(
                        target=can_server.serve_forever, daemon=True
                    )
                    can_thread.start()
                    can_servers.append(can_server)
                    can_threads.append(can_thread)

            def send_to_node(node_id, payload):
                service = node_services[node_id]
                response = service._send_internal_socket(
                    service.SOCKET_PORT, payload
                )
                if response is None or response.get("status") != "ok":
                    raise RuntimeError(
                        (response or {}).get("message", "node request failed")
                    )
                return response["data"]

            def send_to_controller_can(controller_id, payload):
                service = node_services[controller_id]
                response = service._send_internal_socket(
                    service.ZCU_CAN_SOCKET_PORT, payload
                )
                if response is None or response.get("status") != "ok":
                    raise RuntimeError(
                        (response or {}).get(
                            "message", "controller CAN socket request failed"
                        )
                    )
                return response["data"]

            patches = [
                patch.object(
                    service,
                    "_send_node_socket",
                    side_effect=send_to_node,
                )
                for service in node_services.values()
            ] + [
                patch.object(
                    service,
                    "_send_controller_can_socket",
                    side_effect=send_to_controller_can,
                )
                for service in node_services.values()
            ]
            for patcher in patches:
                patcher.start()
            try:
                hpc = node_services["hpc-vehicle"]
                response = hpc._send_internal_socket(
                    hpc.SOCKET_PORT,
                    {
                        "action": "sovd_request",
                        "gateway_hpc_id": "hpc-vehicle",
                        "component_id": "ecu-body-front",
                        "operation": "readDTCInformation",
                    },
                )
                self.assertEqual(response["status"], "ok", response)
                result = response["data"]
                self.assertEqual(result["status"], "completed", result)
                self.assertEqual(
                    result["routing"]["path"],
                    ["hpc-vehicle", "zcu-front-right", "ecu-body-front"],
                )
                powertrain = node_services["ecu-powertrain"]
                uds_response = powertrain._send_internal_socket(
                    powertrain.SOCKET_PORT,
                    {
                        "action": "uds_request",
                        "node_id": "ecu-powertrain",
                        "request_bytes": [0x22, 0xF1, 0xB0],
                    },
                )
                self.assertEqual(uds_response["status"], "ok", uds_response)
                self.assertTrue(
                    uds_response["data"]["uds_result"]["positive_response"]
                )
                ota_response = powertrain._send_internal_socket(
                    powertrain.SOCKET_PORT,
                    {
                        "action": "ota_flash",
                        "package": create_simulated_ota_package(
                            "hpc-vehicle",
                            None,
                            "ecu-powertrain",
                            b"zonal-socket-firmware",
                            "SIM-2.0",
                        ),
                    },
                )
                self.assertEqual(ota_response["status"], "ok", ota_response)
                self.assertEqual(
                    ota_response["data"]["status"], "completed"
                )
                self.assertEqual(
                    [
                        frame["service"]
                        for frame in ota_response["data"]["uds_trace"]
                    ],
                    ["0x10", "0x27", "0x27", "0x34", "0x36", "0x37"],
                )
                body_controller = node_services["ecu-body-front"]
                zonal_ota = body_controller._send_internal_socket(
                    body_controller.SOCKET_PORT,
                    {
                        "action": "ota_flash",
                        "package": create_simulated_ota_package(
                            "hpc-vehicle",
                            "zcu-front-right",
                            "ecu-body-front",
                            b"zcu-routed-firmware",
                            "SIM-2.1",
                        ),
                    },
                )
                self.assertEqual(zonal_ota["status"], "ok", zonal_ota)
                self.assertEqual(zonal_ota["data"]["status"], "completed")
                self.assertEqual(
                    [
                        frame["service"]
                        for frame in zonal_ota["data"]["uds_trace"]
                    ],
                    ["0x10", "0x27", "0x27", "0x34", "0x36", "0x37"],
                )
                zcu = node_services["zcu-front-right"]
                zcu_ota = zcu._send_internal_socket(
                    zcu.SOCKET_PORT,
                    {
                        "action": "ota_flash",
                        "package": create_simulated_ota_package(
                            "hpc-vehicle",
                            "zcu-front-right",
                            "zcu-front-right",
                            b"zcu-own-doip-firmware",
                            "SIM-2.1",
                        ),
                    },
                )
                self.assertEqual(zcu_ota["status"], "ok", zcu_ota)
                self.assertEqual(zcu_ota["data"]["status"], "completed")
                zcu_ota_events = [
                    event
                    for event in zcu.SOCKET_ACTIVITY_EVENTS
                    if event["socket_id"] == "zcu-hpc-tcp"
                    and event["phase"] == "ota"
                ]
                self.assertTrue(
                    any(
                        event["message_id"] == "TransferData"
                        and event["action"] == "received"
                        for event in zcu_ota_events
                    )
                )
                self.assertTrue(
                    any(
                        event["message_id"] == "TransferData"
                        and event["action"] == "sent"
                        for event in zcu_ota_events
                    )
                )
                someip_response = zcu._send_internal_socket(
                    zcu.SOCKET_PORT,
                    {
                        "action": "someip_request",
                        "target_node_id": "zcu-front-right",
                        "requester_node_id": "hpc-vehicle",
                        "signal_name": "gateway_state",
                    },
                )
                self.assertEqual(someip_response["status"], "ok", someip_response)
                service_response = someip_response["data"]["service_response"]
                self.assertTrue(service_response["found"], service_response)
                self.assertIn("someip_response_packet_hex", service_response)
            finally:
                for patcher in reversed(patches):
                    patcher.stop()
        finally:
            for server in can_servers:
                server.shutdown()
                server.server_close()
            for thread in can_threads:
                thread.join(timeout=2)
            for server in servers:
                server.shutdown()
                server.server_close()
            for thread in threads:
                thread.join(timeout=2)
            if previous_node_id is None:
                os.environ.pop("VEHICLE_NODE_ID", None)
            else:
                os.environ["VEHICLE_NODE_ID"] = previous_node_id

    def test_zcu_can_socket_records_can_frames_and_routed_uds(self):
        previous_node_id = self.network.VEHICLE_NODE_ID
        previous_phase = self.network.SCAN_ACTIVITY_PHASE
        self.network.VEHICLE_NODE_ID = "zcu-front-right"
        self.network.SCAN_ACTIVITY_PHASE = "protocol_probes"
        self.network.SOCKET_ACTIVITY_EVENTS.clear()
        server = self.network.NetworkTCPServer(
            ("127.0.0.1", 0), self.network.NodeCanSocketHandler
        )
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        source_id = "ecu-body-front"
        try:
            source = self.network.NODE_INSTANCES[source_id]
            message = source.emit_due_messages(
                (time.monotonic() - self.network.STARTED_AT) * 1000,
                self.network.socket_secret(),
            )[0]
            encoded = self.network._encode_wire_message(
                source_id, message, 0, self.network.socket_secret()
            )
            with patch.object(
                self.network,
                "_send_node_socket",
                return_value={"accepted_count": 1},
            ):
                response = self.network._send_internal_socket(
                    server.server_address[1],
                    {
                        "action": "can_frames",
                        "source_node_id": source_id,
                        "frames": [encoded],
                    },
                )
            self.assertEqual(response["status"], "ok")
            self.assertEqual(response["data"]["accepted_frames"], 1)
            can_event = next(
                event
                for event in self.network.SOCKET_ACTIVITY_EVENTS
                if event["socket_id"] == "zcu-can"
                and event["action"] == "accepted"
            )
            self.assertEqual(can_event["socket_id"], "zcu-can")
            self.assertEqual(can_event["can_id_hex"], encoded["can_frame"]["can_id_hex"])
            self.assertEqual(can_event["dlc"], 8)
            self.assertEqual(can_event["data_hex"], encoded["can_frame"]["data_hex"])

            invalid_id = copy.deepcopy(encoded)
            invalid_id["sequence"] += 1
            invalid_id["can_frame"]["can_id"] = 0x7FF
            invalid_id["can_frame"]["can_id_hex"] = "0x7FF"
            invalid_id["message_id"] = "0x7FF"
            self.network._seal_node_message(
                source_id, invalid_id, self.network.socket_secret()
            )
            invalid_response = self.network._send_internal_socket(
                server.server_address[1],
                {
                    "action": "can_frames",
                    "source_node_id": source_id,
                    "frames": [invalid_id],
                },
            )
            self.assertEqual(invalid_response["data"]["dropped_frames"], 1)
            dropped_event = next(
                event
                for event in reversed(self.network.SOCKET_ACTIVITY_EVENTS)
                if event["socket_id"] == "zcu-can"
                and event["action"] == "dropped"
            )
            self.assertEqual(dropped_event["phase"], "protocol_probes")
            self.assertEqual(dropped_event["can_id_hex"], "0x7FF")

            uds_request = [0x22, 0xF1, 0x80]
            with patch.object(
                self.network,
                "_send_node_socket",
                return_value={"uds_result": {"response_bytes": [0x62, 0xF1, 0x80]}},
            ):
                uds_response = self.network._send_internal_socket(
                    server.server_address[1],
                    {
                        "action": "can_uds",
                        "source_zcu_id": "zcu-front-right",
                        "target_node_id": source_id,
                        "request_bytes": uds_request,
                    },
                )
            self.assertEqual(uds_response["status"], "ok")
            uds_events = [
                event
                for event in self.network.SOCKET_ACTIVITY_EVENTS
                if event["message_name"].startswith("UDS")
            ]
            self.assertEqual(len(uds_events), 2)
            self.assertEqual(uds_events[0]["can_id_hex"], "0x7E5")
            self.assertEqual(uds_events[0]["message_length_bytes"], len(uds_request))
            self.assertEqual(uds_events[0]["dlc"], 8)
            with patch.object(self.network, "poll_node_messages"):
                activity = self.network.network_activity(200)
            visible_can_event = next(
                event
                for event in activity["socket_events"]
                if event["socket_id"] == "zcu-can"
                and event["action"] == "accepted"
            )
            self.assertEqual(
                visible_can_event["data_hex"], encoded["can_frame"]["data_hex"]
            )
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
            self.network.VEHICLE_NODE_ID = previous_node_id
            self.network.SCAN_ACTIVITY_PHASE = previous_phase

    def test_central_api_requires_a_valid_cloud_service_jwt(self):
        response = self.client.get(
            "/network/snapshot", headers={"Authorization": "Bearer invalid"}
        )
        self.assertEqual(response.status_code, 401)
        self.assertEqual(
            response.get_json()["message"],
            "cloud service JWT is invalid or expired",
        )

    def test_central_scan_stop_endpoint_forwards_to_authorized_simulator_action(self):
        with patch.object(
            self.central,
            "vehicle_network_request",
            return_value={
                "status": "stop_requested",
                "message": "Stop requested; post-attack diagnostics will still run.",
            },
        ) as network_request:
            response = self.client.post("/scan/stop")

        self.assertEqual(response.status_code, 202)
        self.assertEqual(response.get_json()["status"], "stop_requested")
        network_request.assert_called_once_with("authorized_attack_stop")

    def test_central_container_reads_all_hpc_vehicle_data_over_authenticated_socket(self):
        response = self.client.get("/network/snapshot")
        self.assertEqual(response.status_code, 200, response.get_json())
        payload = response.get_json()
        self.assertEqual(payload["network_snapshot"]["node_count"], 15)
        self.assertEqual(payload["hpc_vehicle_data"]["aggregator_id"], "hpc-vehicle")
        self.assertEqual(payload["hpc_vehicle_data"]["node_count"], 12)
        self.assertGreaterEqual(len(payload["hpc_vehicle_data"]["messages"]), 120)
        self.assertEqual(len(payload["diagnostics"]), 15)
        self.assertIn("ecu-powertrain", payload["hpc_vehicle_data"]["direct_safety_ecu_ids"])

    def test_central_signal_catalog_lists_signals_for_selected_someip_node(self):
        snapshot = {
            "network_snapshot": {
                "nodes": [
                    {
                        "id": "hpc-vehicle",
                        "someip_service_id": "0x1234",
                        "signals": {
                            "vehicle_speed_kph": 64,
                            "battery_state_of_charge_pct": 82.5,
                        },
                    },
                    {
                        "id": "ecu-powertrain",
                        "someip_service_id": None,
                        "signals": {"engine_rpm": 1200},
                    },
                ]
            }
        }
        with patch.object(
            self.central,
            "vehicle_network_request",
            return_value=snapshot,
        ) as network_request:
            response = self.client.get(
                "/signals/catalog?target_node_id=hpc-vehicle"
            )

        self.assertEqual(response.status_code, 200, response.get_json())
        self.assertEqual(
            response.get_json()["signals"],
            ["battery_state_of_charge_pct", "vehicle_speed_kph"],
        )
        network_request.assert_called_once_with("snapshot")

    def test_central_signal_read_unwraps_routed_node_service_response(self):
        service_response = {
            "found": True,
            "signal_name": "compute_state",
            "value": "online",
            "source_node_id": "hpc-adas",
            "transport": "authenticated SOME/IP over TCP",
        }
        with patch.object(
            self.central,
            "vehicle_network_request",
            return_value={
                "status": "ok",
                "request_id": "simulator-request-id",
                "service_response": service_response,
            },
        ):
            response = self.client.post(
                "/signals/read",
                json={
                    "target_node_id": "hpc-adas",
                    "signal_name": "compute_state",
                },
            )

        self.assertEqual(response.status_code, 200, response.get_json())
        self.assertEqual(response.get_json(), service_response)

    def test_network_observability_reports_all_sockets_and_aggregate_uds_outcomes(self):
        response = self.client.get("/network/observability")

        self.assertEqual(response.status_code, 200, response.get_json())
        data = response.get_json()
        self.assertEqual(data["network"], {"node_count": 15, "zone_count": 4})
        self.assertEqual(len(data["sockets"]), 4)
        sockets = {endpoint["socket_id"]: endpoint for endpoint in data["sockets"]}
        self.assertEqual(
            set(sockets),
            {"zcu-can", "hpc-can", "zcu-hpc-tcp", "cloud-hpc-tcp"},
        )
        self.assertEqual(sockets["zcu-can"]["port"], 6003)
        self.assertEqual(sockets["hpc-can"]["port"], 6003)
        self.assertEqual(sockets["zcu-hpc-tcp"]["port"], 6004)
        self.assertEqual(sockets["cloud-hpc-tcp"]["port"], 6005)
        self.assertEqual(data["uds"]["component_count"], 15)
        self.assertEqual(data["uds"]["successful_count"], 15)
        self.assertEqual(data["uds"]["response_categories"]["positive"], 15)
        self.assertIn("CAN", data["traffic_by_protocol"])
        self.assertIn("CAN-FD", data["traffic_by_protocol"])
        self.assertIn("Automotive Ethernet SOME/IP", data["traffic_by_protocol"])
        self.assertNotIn("diagnostics", data)
        self.assertNotIn("vehicle_messages", data)

    def test_node_socket_routes_zcu_hpc_and_cloud_hpc_to_separate_ports(self):
        self.network.VEHICLE_NODE_ID = None
        os.environ["VEHICLE_NODE_SOCKET_ROUTING"] = "1"
        with patch.object(
            self.network,
            "_send_internal_socket",
            return_value={"status": "ok", "data": {"accepted_count": 1}},
        ) as send:
            self.network._send_node_socket(
                "hpc-vehicle", {"action": "someip_request"}
            )
            self.assertEqual(send.call_args.args[0], 6005)
            self.network.VEHICLE_NODE_ID = "zcu-front-right"
            self.network._send_node_socket(
                "hpc-vehicle",
                {"action": "zcu_relay", "source_zcu_id": "zcu-front-right"},
            )
            self.assertEqual(send.call_args.args[0], 6004)
            self.network.VEHICLE_NODE_ID = "hpc-vehicle"
            self.network._send_node_socket(
                "zcu-front-right",
                {
                    "action": "doip_diagnostic",
                    "source_hpc_id": "hpc-vehicle",
                },
            )
            self.assertEqual(send.call_args.args[0], 6004)
        self.assertIn(
            "cloud-hpc-tcp",
            {event["socket_id"] for event in self.network.SOCKET_ACTIVITY_EVENTS},
        )
        self.assertEqual(
            {
                self.network._socket_id_for_node("ecu-body-front"),
                self.network._socket_id_for_node("ecu-powertrain"),
                self.network._socket_id_for_node("zcu-front-right"),
                self.network._socket_id_for_node("hpc-vehicle"),
            },
            {"zcu-can", "hpc-can", "zcu-hpc-tcp", "cloud-hpc-tcp"},
        )

    def test_remote_snapshot_poll_reuses_a_recent_refresh(self):
        self.network.VEHICLE_NODE_ID = None
        os.environ["VEHICLE_NODE_SOCKET_ROUTING"] = "1"
        self.network.REMOTE_NODE_SNAPSHOTS.clear()
        self.network.REMOTE_SNAPSHOT_REFRESHED_AT = 0.0

        def node_snapshot(node_id, _request):
            return {
                "node_id": node_id,
                "diagnostics": {},
                "uds_diagnostics": {},
                "traffic": {},
                "security_events": [],
            }

        with patch.object(
            self.network, "_send_node_socket", side_effect=node_snapshot
        ) as send_node_socket:
            self.network._refresh_remote_node_snapshots()
            self.network._refresh_remote_node_snapshots()

        self.assertEqual(send_node_socket.call_count, len(self.network.NODES))

    def test_network_activity_returns_without_waiting_for_snapshot_refresh(self):
        previous_snapshots = self.network.REMOTE_NODE_SNAPSHOTS
        previous_refreshed_at = self.network.REMOTE_SNAPSHOT_REFRESHED_AT
        self.network.VEHICLE_NODE_ID = None
        self.network.REMOTE_NODE_SNAPSHOTS = {}
        self.network.REMOTE_SNAPSHOT_REFRESHED_AT = 0.0
        refresh_started = threading.Event()
        release_refresh = threading.Event()
        refresh_finished = threading.Event()

        def slow_refresh():
            refresh_started.set()
            release_refresh.wait(timeout=2)
            refresh_finished.set()

        try:
            with patch.dict(os.environ, {"VEHICLE_NODE_SOCKET_ROUTING": "1"}):
                with patch.object(
                    self.network,
                    "_refresh_remote_node_snapshots",
                    side_effect=slow_refresh,
                ):
                    started_at = time.monotonic()
                    activity = self.network.network_activity(20)
                    elapsed = time.monotonic() - started_at
                    self.assertEqual(activity["messages"], [])
                    self.assertTrue(refresh_started.wait(timeout=1))
                    self.assertLess(elapsed, 0.1)
                    self.assertFalse(refresh_finished.is_set())
                    release_refresh.set()
                    self.assertTrue(refresh_finished.wait(timeout=1))
                    deadline = time.monotonic() + 1
                    while self.network.REMOTE_SNAPSHOT_SCHEDULE_LOCK.locked():
                        if time.monotonic() >= deadline:
                            self.fail("background snapshot refresh did not release its lock")
                        time.sleep(0.01)
        finally:
            release_refresh.set()
            self.network.REMOTE_NODE_SNAPSHOTS = previous_snapshots
            self.network.REMOTE_SNAPSHOT_REFRESHED_AT = previous_refreshed_at

    def test_remote_snapshot_refresh_fetches_nodes_concurrently(self):
        previous_snapshots = self.network.REMOTE_NODE_SNAPSHOTS
        previous_refreshed_at = self.network.REMOTE_SNAPSHOT_REFRESHED_AT
        self.network.VEHICLE_NODE_ID = None
        self.network.REMOTE_NODE_SNAPSHOTS = {}
        self.network.REMOTE_SNAPSHOT_REFRESHED_AT = 0.0
        active_requests = 0
        maximum_active_requests = 0
        request_lock = threading.Lock()

        def node_snapshot(node_id, _request):
            nonlocal active_requests, maximum_active_requests
            with request_lock:
                active_requests += 1
                maximum_active_requests = max(
                    maximum_active_requests, active_requests
                )
            time.sleep(0.05)
            with request_lock:
                active_requests -= 1
            return {
                "node_id": node_id,
                "diagnostics": {},
                "uds_diagnostics": {},
                "traffic": {},
                "security_events": [],
            }

        try:
            with patch.dict(os.environ, {"VEHICLE_NODE_SOCKET_ROUTING": "1"}):
                with patch.object(
                    self.network, "_send_node_socket", side_effect=node_snapshot
                ):
                    self.network._refresh_remote_node_snapshots()

            self.assertGreater(maximum_active_requests, 1)
            self.assertEqual(
                set(self.network.REMOTE_NODE_SNAPSHOTS), set(self.network.NODES)
            )
        finally:
            self.network.REMOTE_NODE_SNAPSHOTS = previous_snapshots
            self.network.REMOTE_SNAPSHOT_REFRESHED_AT = previous_refreshed_at

    def test_network_activity_exposes_decoded_traffic_and_event_metadata_without_frames(self):
        self.network.poll_node_messages()
        node_id = "ecu-powertrain"
        self.network.NODE_INSTANCES[node_id]._message_history.append(
            {
                "sampled_at_monotonic_ms": 1_000_000,
                "source_node_id": node_id,
                "direction": "tx",
                "message_name": "SpeedStatus",
                "message_id": "0x123",
                "transport_type": "CAN",
                "signals": {"vehicle_speed_kph": 42, "latitude": 37.5},
                "signal_payload_hex": "SECRET-FRAME",
            }
        )
        self.network.NODE_INSTANCES["hpc-vehicle"]._message_history.append(
            {
                "sampled_at_monotonic_ms": 1_000_002,
                "source_node_id": "hpc-vehicle",
                "direction": "tx",
                "message_name": "VehicleStatus",
                "message_id": "0x1001:0001",
                "transport_type": "Automotive Ethernet SOME/IP",
                "someip": {
                    "service_id": "0x1001",
                    "method_or_event_id": "0x0001",
                    "packet_hex": "SECRET-PACKET",
                },
                "signals": {"vehicle_speed_kph": 42},
            }
        )
        self.network.NODE_INSTANCES[node_id]._message_history.append(
            {
                "sampled_at_monotonic_ms": 1_000_001,
                "source_node_id": node_id,
                "direction": "tx",
                "message_name": "GNSSPosition",
                "message_id": "0x124",
                "transport_type": "CAN-FD",
                "signals": {"longitude": -122.1},
            }
        )
        event = self.network._raise_security_event(
            node_id,
            "zcu-front-left",
            "signal_out_of_range",
            "Simulator rejected an out-of-range signal value.",
            {"message_name": "speed_status"},
        )

        with patch.object(self.network, "poll_node_messages"):
            response = self.client.get("/network/activity?limit=25")

        self.assertEqual(response.status_code, 200, response.get_json())
        data = response.get_json()
        self.assertIn(
            "vehicle_speed_kph",
            repr(data["messages"]),
        )
        self.assertNotIn("latitude", repr(data["messages"]))
        self.assertNotIn("GNSSPosition", repr(data["messages"]))
        self.assertNotIn("longitude", repr(data["messages"]))
        someip_message = next(
            item for item in data["messages"] if item["message_name"] == "VehicleStatus"
        )
        self.assertEqual(someip_message["service_id"], "0x1001")
        self.assertEqual(someip_message["method_id"], "0x0001")
        self.assertEqual(someip_message["socket_id"], "cloud-hpc-tcp")
        self.assertNotIn("packet_hex", repr(data))
        matching_event = next(
            item
            for item in data["security_events"]
            if item["event_id"] == event["event_id"]
        )
        self.assertEqual(matching_event["category"], "signal_out_of_range")
        self.assertEqual(matching_event["socket_id"], "hpc-can")
        self.assertNotIn("signal_payload_hex", repr(data))
        self.assertNotIn("auth_tag", repr(data))

    def test_scan_diagnostics_are_logged_with_phase_protocol_and_uds_service_ids(self):
        self.network.set_scan_activity_phase("before_attack")
        result = self.network.run_network_diagnostics()
        activity = self.network.network_activity(200)
        self.assertEqual(activity["scan_phase"], "before_attack")
        self.assertGreater(activity["scan_phase_updated_at"], 0)
        diagnostics = [
            item
            for item in activity["diagnostics"]
            if item["event_type"] == "diagnostic"
        ]
        self.network.set_scan_activity_phase("idle")
        idle_activity = self.network.network_activity(200)
        self.assertEqual(idle_activity["scan_phase"], "idle")
        self.assertGreaterEqual(
            idle_activity["scan_phase_updated_at"],
            activity["scan_phase_updated_at"],
        )

        self.assertEqual(result["component_count"], 15)
        self.assertEqual(len(diagnostics), 15)
        self.assertTrue(all(item["phase"] == "before_attack" for item in diagnostics))
        self.assertTrue(all(item["service_id"] == "0x19" for item in diagnostics))
        self.assertIn("0x59", {item["response_service_id"] for item in diagnostics})
        diagnostic_sockets = {item["socket_id"] for item in diagnostics}
        self.assertIn("hpc-can", diagnostic_sockets)
        self.assertIn("zcu-can", diagnostic_sockets)
        self.assertIn("zcu-hpc-tcp", diagnostic_sockets)
        self.assertIn("cloud-hpc-tcp", diagnostic_sockets)
        self.assertTrue(
            all(item["event_type"] == "diagnostic" for item in diagnostics)
        )

    def test_authorized_attack_stop_sets_only_the_active_simulation_stop_signal(self):
        self.assertEqual(
            self.network.request_attack_stop()["status"],
            "inactive",
        )
        with self.network.ACTIVE_ATTACK_LOCK:
            self.network.ACTIVE_ATTACK_RUNNING = True
        try:
            result = self.network.request_attack_stop()
            self.assertEqual(result["status"], "stop_requested")
            self.assertTrue(self.network.ACTIVE_ATTACK_STOP_EVENT.is_set())
        finally:
            self.network.ACTIVE_ATTACK_STOP_EVENT.clear()
            with self.network.ACTIVE_ATTACK_LOCK:
                self.network.ACTIVE_ATTACK_RUNNING = False

    def test_stop_request_ends_timed_simulation_without_skipping_result_status(self):
        previous_state = self.network.VEHICLE_SERVICE_STATE
        with self.network.SERVICE_STATE_LOCK:
            self.network.VEHICLE_SERVICE_STATE = "in_service"
        result_holder = {}

        def run_test():
            result_holder["result"] = self.network.run_authorized_attack_test(
                {
                    "authorized_simulation": True,
                    "attack_type": "flooding",
                    "severity": "low",
                    "duration_seconds": 60,
                    "target_node_ids": ["zcu-front-left"],
                    "attack_frames": [
                        {
                            "target_ecu_id": "zcu-front-left",
                            "attack_type": "flooding",
                            "severity": "low",
                            "message_count": 512,
                        }
                    ],
                }
            )

        try:
            with patch.object(
                self.network,
                "run_simulated_protocol_probe_suite",
                return_value={"suite": "test", "status": "completed"},
            ):
                worker = threading.Thread(target=run_test)
                worker.start()
                deadline = time.monotonic() + 5
                while (
                    time.monotonic() < deadline
                    and not self.network.ACTIVE_ATTACK_RUNNING
                ):
                    time.sleep(0.01)
                self.assertTrue(self.network.ACTIVE_ATTACK_RUNNING)
                self.network.request_attack_stop()
                worker.join(timeout=5)

            self.assertFalse(worker.is_alive())
            self.assertEqual(result_holder["result"]["status"], "stopped")
            self.assertLess(result_holder["result"]["elapsed_seconds"], 5)
        finally:
            with self.network.SERVICE_STATE_LOCK:
                self.network.VEHICLE_SERVICE_STATE = previous_state

    def test_bounded_protocol_probe_suite_exercises_all_registered_nodes(self):
        summary = self.network.run_simulated_protocol_probe_suite()
        self.assertEqual(summary["status"], "completed")
        self.assertEqual(summary["protocols"]["uds"]["target_node_count"], 15)
        self.assertGreater(summary["attempted_count"], 0)
        self.assertGreater(summary["rejected_count"], 0)
        received = self.network.NODE_INSTANCES["hpc-vehicle"].aggregated_zcu_messages()
        expected_sources = {
            node_id
            for node_id, spec in self.network.NODES.items()
            if spec["role"] in {"ecu", "zone_controller"}
        }
        self.assertEqual(
            {message["source_node_id"] for message in received},
            expected_sources,
        )
        target_id = "hpc-vehicle"
        node = self.network.NODE_INSTANCES[target_id]
        initial_uds_state = copy.deepcopy(node._uds_state)
        response = self.network._send_internal_socket(
            int(os.environ["VEHICLE_NETWORK_SOCKET_PORT"]),
            {
                "action": "uds_security_probe",
                "node_id": target_id,
                "sandboxed_uds_probe": True,
            },
        )
        self.assertEqual(
            response["data"]["uds_result"]["nrc"],
            "0x35",
        )
        self.assertEqual(node._uds_state, initial_uds_state)

    def test_security_profiles_do_not_gate_authorized_attack_selection(self):
        node_id = "hpc-vehicle"
        original = copy.deepcopy(self.network.NODE_SECURITY_PROFILES[node_id])
        self.network.SECURITY_PROFILE_PATH = ""
        try:
            self.network.configure_node_security_profile(
                {
                    "node_id": node_id,
                    "security_level": "hardened",
                    "susceptible_attacks": ["dos"],
                }
            )
            with self.assertRaisesRegex(PermissionError, "vehicle.*in service"):
                self.network.run_authorized_attack_test(
                    {
                        "authorized_simulation": True,
                        "attack_type": "dos",
                        "severity": "high",
                        "duration_seconds": 1,
                        "target_node_ids": [node_id],
                    }
                )
            with self.assertRaisesRegex(PermissionError, "vehicle.*in service"):
                self.network.run_authorized_attack_test(
                    {
                        "authorized_simulation": True,
                        "attack_type": "tampering",
                        "severity": "medium",
                        "duration_seconds": 1,
                        "target_node_ids": [node_id],
                    }
                )
        finally:
            self.network.NODE_SECURITY_PROFILES[node_id] = original

    def test_security_profile_configuration_persists_and_reloads(self):
        node_id = "hpc-vehicle"
        original = copy.deepcopy(self.network.NODE_SECURITY_PROFILES[node_id])
        previous_path = self.network.SECURITY_PROFILE_PATH
        with tempfile.TemporaryDirectory() as directory:
            self.network.SECURITY_PROFILE_PATH = str(
                pathlib.Path(directory) / "security_profiles.json"
            )
            try:
                self.network.configure_node_security_profile(
                    {
                        "node_id": node_id,
                        "security_level": "hardened",
                        "susceptible_attacks": ["dos"],
                    }
                )
                self.network.NODE_SECURITY_PROFILES[node_id] = copy.deepcopy(original)
                self.network._load_node_security_profiles()
                self.assertEqual(
                    self.network.NODE_SECURITY_PROFILES[node_id],
                    {
                        "security_level": "hardened",
                        "susceptible_attacks": ["dos"],
                    },
                )
            finally:
                self.network.SECURITY_PROFILE_PATH = previous_path
                self.network.NODE_SECURITY_PROFILES[node_id] = original

    def test_operator_selected_targets_are_the_only_attack_targets(self):
        target_node_id = "zcu-front-left"
        self.network.VEHICLE_SERVICE_STATE = "in_service"

        result = self.network.run_authorized_attack_test(
            {
                "authorized_simulation": True,
                "attack_type": "flooding",
                "severity": "low",
                "duration_seconds": 1,
                "target_node_ids": [target_node_id],
                "attack_frames": [
                    {
                        "target_ecu_id": target_node_id,
                        "attack_type": "flooding",
                        "severity": "low",
                        "message_count": 512,
                    }
                ],
            }
        )

        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["targeting_mode"], "operator_selected")
        self.assertEqual(result["affected_node_count"], 1)
        self.assertEqual(result["target_role_counts"], {"zone_controller": 1})
        self.assertEqual(result["execution_mode"], "bounded_simulator_socket_traffic")
        self.assertEqual(result["attack_frame_count"], 512)
        self.assertGreater(result["dropped_frame_count"], 0)
        self.assertIn("zcu-hpc-tcp", result["affected_sockets"])

    def test_attack_phase_traffic_does_not_evict_attack_activity(self):
        attack_event = self.network._record_socket_activity(
            "hpc-can",
            "hpc-vehicle",
            "ecu-powertrain",
            "dropped",
            {
                "phase": "attack",
                "attack_generated": True,
                "attack_type": "invalid_firmware",
            },
            "Simulated attack event",
        )
        for _ in range(1000):
            self.network._record_socket_activity(
                "hpc-can",
                "hpc-vehicle",
                "ecu-powertrain",
                "accepted",
                {"phase": "attack", "attack_generated": False},
                "Ordinary simulator traffic during attack phase",
            )

        recent_events = self.network._recent_socket_activity(20)

        self.assertIn(
            attack_event["event_id"],
            {event["event_id"] for event in recent_events},
        )

    def test_zcu_attack_traffic_uses_the_hpc_zcu_someip_socket(self):
        previous_state = self.network.VEHICLE_SERVICE_STATE
        with self.network.SERVICE_STATE_LOCK:
            self.network.VEHICLE_SERVICE_STATE = "in_service"
        try:
            result = self.network.run_authorized_attack_test(
                {
                    "authorized_simulation": True,
                    "attack_type": "ids_auditability_regression",
                    "severity": "low",
                    "duration_seconds": 1,
                    "target_node_ids": ["zcu-front-left"],
                    "attack_frames": [
                        {
                            "target_ecu_id": "zcu-front-left",
                            "attack_type": "ids_auditability_regression",
                            "severity": "low",
                            "message_count": 1,
                        }
                    ],
                }
            )
        finally:
            with self.network.SERVICE_STATE_LOCK:
                self.network.VEHICLE_SERVICE_STATE = previous_state

        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["attack_frame_count"], 1)
        self.assertEqual(result["dropped_frame_count"], 1)
        self.assertIn("zcu-hpc-tcp", result["affected_sockets"])
        activity = self.network.network_activity(200)
        attack_events = [
            event
            for event in activity["socket_events"]
            if event["phase"] == "attack"
            and event["socket_id"] == "zcu-hpc-tcp"
            and event["target_node_id"] == "zcu-front-left"
        ]
        self.assertTrue(attack_events)
        self.assertEqual(
            result["target_security_level_counts"], {"elevated": 1}
        )

    def test_invalid_firmware_probe_is_rejected_and_restores_target_state(self):
        target_node_id = "ecu-powertrain"
        target = self.network.NODE_INSTANCES[target_node_id]
        previous_state = copy.deepcopy(target._uds_state)
        had_software_profile = hasattr(target, "_software_profile")
        previous_profile = copy.deepcopy(
            getattr(target, "_software_profile", None)
        )
        previous_vehicle_state = self.network.VEHICLE_SERVICE_STATE
        with self.network.SERVICE_STATE_LOCK:
            self.network.VEHICLE_SERVICE_STATE = "in_service"
        try:
            result = self.network.run_authorized_attack_test(
                {
                    "authorized_simulation": True,
                    "attack_type": "invalid_firmware",
                    "severity": "low",
                    "duration_seconds": 1,
                    "target_node_ids": [target_node_id],
                    "attack_frames": [
                        {
                            "target_ecu_id": target_node_id,
                            "attack_type": "invalid_firmware",
                            "severity": "low",
                            "message_count": 1,
                        }
                    ],
                }
            )
        finally:
            with self.network.SERVICE_STATE_LOCK:
                self.network.VEHICLE_SERVICE_STATE = previous_vehicle_state

        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["attack_frame_count"], 1)
        self.assertEqual(result["dropped_frame_count"], 1)
        self.assertEqual(target._uds_state, previous_state)
        self.assertEqual(
            hasattr(target, "_software_profile"), had_software_profile
        )
        if had_software_profile:
            self.assertEqual(target._software_profile, previous_profile)
        self.assertGreater(result["event_count"], 0)
        self.assertTrue(
            any(
                event.get("attack_generated") is True
                and event.get("attack_type") == "invalid_firmware"
                and event.get("target_node_id") == target_node_id
                and event.get("socket_id") == "hpc-can"
                and event.get("action") == "dropped"
                for event in self.network.network_activity(200)["socket_events"]
            )
        )

    def test_bounded_attack_workflow_requires_service_and_returns_aggregate_analytics(self):
        rejected = self.client.post(
            "/scan/start",
            json={
                "attack_type": "flooding",
                "severity": "low",
                "duration_seconds": 1,
            },
        )
        self.assertEqual(rejected.status_code, 409)

        state_response = self.client.post(
            "/vehicle/service-state", json={"service_state": "in_service"}
        )
        self.assertEqual(state_response.status_code, 200, state_response.get_json())
        self.assertEqual(state_response.get_json()["service_state"], "in_service")
        initial_security_failures = {
            node_id: node._uds_state.get("security_failures", 0)
            for node_id, node in self.network.NODE_INSTANCES.items()
        }

        response = self.client.post(
            "/scan/start",
            json={
                "attack_type": "flooding",
                "severity": "low",
                "duration_seconds": 1,
            },
        )
        self.assertEqual(response.status_code, 200, response.get_json())
        result = response.get_json()
        self.assertEqual(result["before_attack"]["network_node_count"], 15)
        self.assertEqual(result["before_attack"]["uds_tested_node_count"], 15)
        self.assertEqual(result["after_attack"]["uds_tested_node_count"], 15)
        self.assertEqual(result["attack_summary"]["status"], "completed", result)
        self.assertGreater(result["attack_summary"]["event_count"], 0)
        probes = result["probe_summary"]
        self.assertEqual(probes["suite"], "bounded_simulator_protocol_probes_v1")
        self.assertEqual(probes["status"], "completed")
        self.assertGreater(probes["attempted_count"], 0)
        self.assertGreater(probes["rejected_count"], 0)
        self.assertTrue(
            {
                "can_id_mismatch",
                "signal_out_of_range",
                "replay_detected",
                "periodicity_violation",
                "invalid_authentication",
                "uds_unsupported_did",
                "uds_unsupported_rid",
                "uds_malformed_length",
                "uds_security_access",
                "someip_header_mismatch",
                "doip_header_mismatch",
            }.issubset(probes["category_counts"]),
            probes["category_counts"],
        )
        self.assertEqual(
            {
                node_id: node._uds_state.get("security_failures", 0)
                for node_id, node in self.network.NODE_INSTANCES.items()
            },
            initial_security_failures,
        )
        self.assertTrue(
            all(
                node._uds_state.get("unlocked", False) is False
                for node in self.network.NODE_INSTANCES.values()
            )
        )
        self.assertNotIn("network_snapshot", result)
        self.assertNotIn("uds_diagnostics", result)
        self.assertNotIn("vehicle_messages", result)
        self.assertNotIn("ecu-powertrain", response.get_data(as_text=True))

    def test_architecture_endpoint_exposes_companion_model_and_simulator_link(self):
        response = self.client.get("/architecture")
        self.assertEqual(response.status_code, 200)
        architecture = response.get_json()
        modules = architecture["central_compute"]["modules"]
        self.assertEqual(
            {module["folder"] for module in modules if "folder" in module},
            {"scanner/", "behavior_analysis/", "ota_client/"},
        )
        self.assertIn(
            "scanner/hpc_vehicle_model.py",
            {module["file"] for module in modules if "file" in module},
        )
        simulator_link = next(
            link
            for link in architecture["connections"]
            if link["source"] == "vehicle-central-compute / scanner/vehicle_network_client.py"
        )
        self.assertEqual(simulator_link["port"], self.server.server_address[1])
        node_links = [
            link
            for link in architecture["connections"]
            if link["target"].startswith("vehicle-node-{node_id}")
        ]
        self.assertEqual(len(node_links), 1)
        self.assertEqual(node_links[0]["port"], 6001)
        self.assertIsInstance(node_links[0]["enabled"], bool)

    def test_central_container_reads_uds_and_dtc_catalogs_for_every_node(self):
        response = self.client.get("/uds/diagnostics")
        self.assertEqual(response.status_code, 200, response.get_json())
        nodes = response.get_json()["uds_diagnostics"]
        self.assertEqual(len(nodes), 15)
        self.assertTrue(all("0x19" in node["supported_services"] for node in nodes))
        self.assertTrue(all("0x31" in node["supported_services"] for node in nodes))
        self.assertTrue(all(node["dtc_catalog"] for node in nodes))
        self.assertTrue(all(node["dids"] and node["rids"] for node in nodes))
        self.assertEqual(len({tuple(sorted(node["dids"].items())) for node in nodes}), 15)

    def test_per_node_did_and_routine_control_are_served_by_uds(self):
        topology = self.client.get("/network/snapshot").get_json()["network_snapshot"]
        for node in topology["nodes"]:
            with self.subTest(node=node["id"]):
                did = next(iter(node["uds_dids"]))
                request_bytes = [0x22, int(did[2:4], 16), int(did[4:6], 16)]
                did_response = self.client.post(f"/uds/{node['id']}", json={"request_bytes": request_bytes})
                self.assertEqual(did_response.status_code, 200)
                self.assertTrue(did_response.get_json()["positive_response"])

                rid = next(iter(node["uds_rids"]))
                self.client.post(f"/uds/{node['id']}", json={"request_bytes": [0x10, 0x03]})
                seed = self.client.post(f"/uds/{node['id']}", json={"request_bytes": [0x27, 0x01]}).get_json()
                key = security_key_for_seed(node["id"], bytes(seed["response_bytes"][2:]))
                unlock = self.client.post(f"/uds/{node['id']}", json={"request_bytes": [0x27, 0x02, *key]})
                self.assertTrue(unlock.get_json()["positive_response"])
                routine = self.client.post(f"/uds/{node['id']}", json={"request_bytes": [0x31, 0x01, int(rid[2:4], 16), int(rid[4:6], 16)]})
                self.assertTrue(routine.get_json()["positive_response"])
                self.assertEqual(routine.get_json()["routine_name"], node["uds_rids"][rid])

    def test_rest_signal_reads_use_someip_for_hpc_and_zcu_services(self):
        vehicle_response = self.client.post(
            "/signals/read",
            json={"target_node_id": "hpc-vehicle", "signal_name": "vehicle_speed_kph"},
        )
        self.assertEqual(vehicle_response.status_code, 200, vehicle_response.get_json())
        vehicle_data = vehicle_response.get_json()
        self.assertEqual(vehicle_data["value"], 64)
        self.assertEqual(vehicle_data["source_node_id"], "ecu-powertrain")
        self.assertEqual(vehicle_data["transport"], "authenticated SOME/IP over TCP")
        self.assertEqual(vehicle_data["minimum"], 0)
        self.assertEqual(vehicle_data["maximum"], 350)

        adas_response = self.client.post(
            "/signals/read",
            json={"target_node_id": "hpc-adas", "signal_name": "nearest_object_distance_m"},
        )
        self.assertEqual(adas_response.status_code, 200, adas_response.get_json())
        self.assertEqual(adas_response.get_json()["value"], 28.4, adas_response.get_json())
        self.assertEqual(adas_response.get_json()["source_node_id"], "ecu-adas-radar")

        zcu_response = self.client.post(
            "/signals/read",
            json={"target_node_id": "zcu-front-right", "signal_name": "window_position_pct"},
        )
        self.assertEqual(zcu_response.status_code, 200, zcu_response.get_json())
        zcu_data = zcu_response.get_json()
        self.assertEqual(zcu_data["value"], 0)
        self.assertEqual(zcu_data["source_node_id"], "ecu-body-front")
        self.assertTrue(zcu_data["someip_request_packet_hex"])
        self.assertTrue(zcu_data["someip_response_packet_hex"])
        zcu_signal_events = [
            event
            for event in self.network.SOCKET_ACTIVITY_EVENTS
            if event["socket_id"] == "zcu-hpc-tcp"
            and event["message_name"] == "SOME/IP signal service"
        ]
        self.assertEqual(
            [event["action"] for event in zcu_signal_events[-2:]],
            ["sent", "received"],
        )
        self.assertTrue(
            all(event["someip_service_id"] and event["someip_method_id"] for event in zcu_signal_events[-2:])
        )

    def test_someip_services_authenticate_callers_on_target_nodes(self):
        service_nodes = [
            node
            for node in self.network.NODE_INSTANCES.values()
            if getattr(node, "ROLE", "") in {"hpc", "zone_controller"}
        ]
        self.assertTrue(
            all(callable(node.handle_someip_signal_request) for node in service_nodes)
        )
        self.assertTrue(
            all(
                callable(node.handle_someip_sovd_request)
                for node in service_nodes
                if getattr(node, "ROLE", "") == "hpc"
            )
        )

        adas_hpc = self.network.NODE_INSTANCES["hpc-adas"]
        front_right_zcu = self.network.NODE_INSTANCES["zcu-front-right"]
        signal_packet = adas_hpc.build_someip_signal_request(
            front_right_zcu, "window_position_pct"
        )
        with self.assertRaises(PermissionError):
            front_right_zcu.handle_someip_signal_request(
                {
                    "requester_node_id": "hpc-vehicle",
                    "someip_request_packet_hex": signal_packet,
                },
                self.network.NODE_INSTANCES,
            )

        vehicle_hpc = self.network.NODE_INSTANCES["hpc-vehicle"]
        sovd_request = {
            "operation": "testerPresent",
            "component_id": "hpc-adas",
        }
        sovd_packet = vehicle_hpc.build_someip_sovd_request(
            adas_hpc, sovd_request
        )
        with self.assertRaises(PermissionError):
            adas_hpc.handle_someip_sovd_request(
                {
                    "source_hpc_id": "ecu-powertrain",
                    "someip_packet_hex": sovd_packet,
                    "sovd_request": sovd_request,
                },
                self.network.NODE_INSTANCES,
                {},
            )

    def test_sovd_did_reads_are_converted_to_uds_and_routed_by_hpc(self):
        routes = [
            ("ecu-powertrain", ["hpc-vehicle", "ecu-powertrain"], ["CAN-FD"]),
            ("ecu-body-front", ["hpc-vehicle", "zcu-front-right", "ecu-body-front"], ["DoIP over Automotive Ethernet", "CAN"]),
            ("ecu-adas-radar", ["hpc-vehicle", "hpc-adas", "ecu-adas-radar"], ["SOME/IP over Automotive Ethernet", "UDS over CAN/CAN-FD"]),
        ]
        for component_id, expected_path, expected_transports in routes:
            with self.subTest(component=component_id):
                response = self.client.post(
                    "/sovd/v1/diagnostics",
                    json={
                        "vehicle_id": "simulated-vehicle",
                        "component_id": component_id,
                        "operation": "readDataByIdentifier",
                        "data_id": "F1B0",
                    },
                )
                self.assertEqual(response.status_code, 200, response.get_json())
                result = response.get_json()
                self.assertTrue(result["result"]["positive_response"])
                self.assertEqual(result["result"]["response_bytes"][0], 0x62)
                self.assertEqual(result["routing"]["path"], expected_path)
                self.assertEqual(result["routing"]["transports"], expected_transports)
                if component_id == "ecu-body-front":
                    self.assertTrue(result["doip_packets"]["request"])
                    self.assertTrue(result["doip_packets"]["response"])

        adas_response = self.client.post(
            "/sovd/v1/diagnostics",
            json={
                "vehicle_id": "simulated-vehicle",
                "gateway_hpc_id": "hpc-adas",
                "component_id": "ecu-adas-radar",
                "operation": "readDataByIdentifier",
                "data_id": "F1B0",
            },
        )
        self.assertEqual(adas_response.status_code, 200, adas_response.get_json())
        self.assertEqual(adas_response.get_json()["routing"]["path"], ["hpc-adas", "ecu-adas-radar"])

        cockpit_response = self.client.post(
            "/sovd/v1/diagnostics",
            json={
                "vehicle_id": "simulated-vehicle",
                "gateway_hpc_id": "hpc-cockpit",
                "component_id": "hpc-cockpit",
                "operation": "readDataByIdentifier",
                "data_id": "F1B0",
            },
        )
        self.assertEqual(cockpit_response.status_code, 200, cockpit_response.get_json())
        self.assertEqual(cockpit_response.get_json()["routing"]["path"], ["hpc-cockpit"])

    def test_hpc_zcu_can_uds_ota_download_and_bad_image_rejection(self):
        image = b"simulated-firmware-image"
        package = create_simulated_ota_package("hpc-vehicle", "zcu-front-right", "ecu-body-front", image, "SIM-2.0")
        accepted = self.client.post("/ota/flash", json=package)
        self.assertEqual(accepted.status_code, 200, accepted.get_json())
        result = accepted.get_json()
        self.assertEqual(result["status"], "completed")
        self.assertEqual(result["route"], {"source_hpc_id": "hpc-vehicle", "zcu_id": "zcu-front-right", "target_ecu_id": "ecu-body-front"})
        self.assertEqual(result["hops"][0]["transport"], "Ethernet socket")
        self.assertEqual(result["hops"][1]["transport"], "UDS over CAN/CAN-FD")
        self.assertFalse(result["hardware_flash_performed"])

        package["image_hex"] = b"tampered-image".hex()
        rejected = self.client.post("/ota/flash", json=package)
        self.assertEqual(rejected.status_code, 422)
        self.assertEqual(rejected.get_json().get("status"), "rejected")

    def test_target_node_rejects_ota_route_that_does_not_match_its_topology(self):
        package = create_simulated_ota_package(
            "hpc-vehicle",
            "zcu-front-left",
            "ecu-body-front",
            b"route-validation-image",
            "SIM-2.0",
        )

        response = self.client.post("/ota/flash", json=package)

        self.assertEqual(response.status_code, 422)
        self.assertEqual(response.get_json()["status"], "rejected")
        self.assertIn("ZCU route does not match", response.get_json()["reason"])

    def test_ota_socket_flashes_all_nodes_and_activates_software_profile(self):
        image = b"ota-model"
        for node_id, node in self.network.NODE_INSTANCES.items():
            role = getattr(node, "ROLE", "ecu")
            if role == "ecu":
                parent = node.CONNECTED_TO
                if self.network.NODES[parent]["role"] == "zone_controller":
                    zcu_id = parent
                    source_id = self.network.NODES[zcu_id]["connected_to"][0]
                else:
                    zcu_id = None
                    source_id = parent
            elif role == "zone_controller":
                zcu_id = node_id
                source_id = node.CONNECTED_TO[0]
            else:
                zcu_id = None
                source_id = node.TRUSTED_SOURCES[0]
            profile = None
            if node_id == "ecu-powertrain":
                profile = {
                    "security_access_required": False,
                    "signal_overrides": {"engine_rpm": 12000},
                }
            elif node_id == "ecu-body-front":
                profile = {"message_authentication": False}
            elif node_id == "zcu-front-left":
                profile = {"replay_protection": False}
            elif node_id == "ecu-body-rear":
                profile = {"freshness_protection": False}
            elif node_id == "hpc-adas":
                profile = {
                    "security_access_required": False,
                    "signal_overrides": {"cpu_load_pct": 150},
                }
            package = create_simulated_ota_package(
                source_id,
                zcu_id,
                node_id,
                image,
                "SIM-2.2",
                software_profile=profile,
            )
            with self.subTest(node=node_id):
                response = self.client.post("/ota/flash", json=package)
                self.assertEqual(response.status_code, 200, response.get_json())
                result = response.get_json()
                self.assertEqual(result["status"], "completed")
                self.assertFalse(result["hardware_flash_performed"])
                behavior_change = result["node_behavior_change"]
                self.assertEqual(behavior_change["status"], "completed")
                self.assertEqual(behavior_change["scope"], "target_node_only")
                self.assertEqual(behavior_change["target_node_id"], node_id)
                self.assertEqual(behavior_change["affected_node_ids"], [node_id])
                self.assertTrue(behavior_change["firmware_version_changed"])
                self.assertEqual(
                    set(behavior_change["changed_profile_keys"]),
                    set(profile or {}),
                )
                if role == "hpc":
                    self.assertEqual(result["update_framework"], "A/B partition swap")
                    self.assertIn(result["active_partition"], {"A", "B"})
                    socket_events = self.network.network_activity(200)[
                        "socket_events"
                    ]
                    self.assertTrue(
                        any(
                            event["socket_id"] == "cloud-hpc-tcp"
                            and event["target_node_id"] == node_id
                            and event["phase"] == "ota"
                            and event["action"] == "completed"
                            and event["active_partition"] == result["active_partition"]
                            for event in socket_events
                        )
                    )
                elif role == "zone_controller":
                    socket_events = self.network.network_activity(200)[
                        "socket_events"
                    ]
                    zcu_ota_events = [
                        event
                        for event in socket_events
                        if event["socket_id"] == "zcu-hpc-tcp"
                        and event["target_node_id"] == node_id
                        and event["phase"] == "ota"
                    ]
                    self.assertTrue(zcu_ota_events)
                    self.assertTrue(
                        any(
                            event["message_id"] == "TransferData"
                            and event["message_length_bytes"] > 0
                            for event in zcu_ota_events
                        )
                    )
                else:
                    self.assertEqual(
                        result["uds_trace"][0]["service_name"],
                        "DiagnosticSessionControl",
                    )
                    self.assertEqual(
                        result["uds_trace"][-1]["service_name"],
                        "RequestTransferExit",
                    )

        powertrain = self.network.NODE_INSTANCES["ecu-powertrain"]
        self.assertFalse(powertrain._software_profile["security_access_required"])
        self.assertFalse(
            self.network.NODE_INSTANCES["hpc-adas"]._software_profile[
                "security_access_required"
            ]
        )
        self.assertFalse(
            self.network.NODE_INSTANCES["zcu-front-left"]._software_profile[
                "replay_protection"
            ]
        )
        self.assertFalse(
            self.network.NODE_INSTANCES["ecu-body-rear"]._software_profile[
                "freshness_protection"
            ]
        )

        for node in self.network.NODE_INSTANCES.values():
            with self.subTest(node=node.NODE_ID):
                self.assertIn("validate_network_message", type(node).__dict__)
                self.assertIn(
                    "software_profile_freshness_protection_enabled",
                    type(node).__dict__,
                )
                for profile_method in (
                    "software_profile_security_access_required_enabled",
                    "software_profile_message_authentication_enabled",
                    "software_profile_replay_protection_enabled",
                    "software_profile_rate_limiting_enabled",
                    "software_profile_timing_validation_enabled",
                    "software_profile_range_validation_enabled",
                    "software_profile_message_id_validation_enabled",
                    "software_profile_diagnostic_access_control_enabled",
                    "software_profile_zonal_segmentation_enabled",
                    "software_profile_firmware_signature_required_enabled",
                    "software_profile_anti_downgrade_enabled",
                    "software_profile_ids_logging_enabled",
                ):
                    self.assertIn(profile_method, type(node).__dict__)

        freshness_source = "ecu-body-rear"
        freshness_node = self.network.NODE_INSTANCES[freshness_source]
        self.network.poll_node_messages()
        stale_frame = copy.deepcopy(freshness_node._message_history[0])
        stale_frame["sequence"] = freshness_node._message_sequence + 1
        stale_frame["sent_at_unix_ms"] = int(time.time() * 1000) - 10_000
        self.network._seal_node_message(
            freshness_source, stale_frame, self.network.socket_secret()
        )
        freshness_receiver = freshness_node.CONNECTED_TO
        self.assertIsNone(
            self.network._validate_message(
                freshness_source,
                stale_frame,
                "can",
                freshness_receiver,
                check_periodicity=False,
            )
        )
        self.assertTrue(
            any(
                event["node_id"] == freshness_source
                and event["category"] == "freshness_protection_bypass"
                for event in self.network.ACTIVE_SECURITY_EVENTS
            )
        )

        protected_source = "ecu-body-front"
        protected_node = self.network.NODE_INSTANCES[protected_source]
        stale_protected = copy.deepcopy(protected_node._message_history[0])
        stale_protected["sequence"] = protected_node._message_sequence + 1
        stale_protected["sent_at_unix_ms"] = int(time.time() * 1000) - 10_000
        self.network._seal_node_message(
            protected_source, stale_protected, self.network.socket_secret()
        )
        self.assertIn(
            "freshness",
            self.network._validate_message(
                protected_source,
                stale_protected,
                "can",
                protected_node.CONNECTED_TO,
                check_periodicity=False,
            ),
        )
        powertrain.handle_uds_request([0x10, 0x01])
        bypass = powertrain.handle_uds_request([0x27, 0x02])
        self.assertTrue(bypass["positive_response"])
        self.assertTrue(bypass["security_bypass"])
        self.network.poll_node_messages()
        self.assertTrue(
            any(
                event["node_id"] == "ecu-powertrain"
                and event["category"] == "signal_out_of_range"
                for event in self.network.ACTIVE_SECURITY_EVENTS
            )
        )
        self.assertTrue(
            any(
                event["node_id"] == "ecu-body-front"
                and event["category"] == "message_authentication_bypass"
                for event in self.network.ACTIVE_SECURITY_EVENTS
            )
        )
        probe_summary = self.network.run_simulated_protocol_probe_suite()
        self.assertGreater(
            probe_summary["category_counts"].get("uds_security_access_bypass", 0),
            0,
        )
        diagnostics = self.network.socket_action(
            {"action": "network_activity", "limit": 200}
        )["diagnostics"]
        self.assertTrue(any(item.get("phase") == "ota" for item in diagnostics))
        self.assertTrue(
            any(item.get("socket_id") == "zcu-hpc-tcp" for item in diagnostics)
        )

    def test_ota_profile_weakens_only_target_node_and_reports_bypasses(self):
        target_id = "ecu-body-front"
        sibling_id = "ecu-body-rear"
        profile = {
            "range_validation": False,
            "firmware_signature_required": False,
            "anti_downgrade": False,
        }
        package = create_simulated_ota_package(
            "hpc-vehicle",
            "zcu-front-right",
            target_id,
            b"target-only-profile",
            "SIM-2.2",
            software_profile=profile,
        )
        response = self.client.post("/ota/flash", json=package)
        self.assertEqual(response.status_code, 200, response.get_json())
        self.assertEqual(response.get_json()["status"], "completed")

        target = self.network.NODE_INSTANCES[target_id]
        sibling = self.network.NODE_INSTANCES[sibling_id]
        self.assertFalse(target.software_profile_range_validation_enabled())
        self.assertTrue(sibling.software_profile_range_validation_enabled())
        behavior = {
            item["node_id"]: item
            for item in self.network.node_behavior_report()
        }
        self.assertFalse(
            behavior[target_id]["software_profile_range_validation_enabled"]
        )
        self.assertTrue(
            behavior[sibling_id]["software_profile_range_validation_enabled"]
        )

        self.network.poll_node_messages()
        for node_id, node, should_accept in (
            (target_id, target, True),
            (sibling_id, sibling, False),
        ):
            message = copy.deepcopy(node._message_history[0])
            layout = message["signal_layout"]
            layout["encoded_value"] = layout["maximum"] + 1
            layout["value"] = layout["encoded_value"]
            message["signals"][layout["name"]] = layout["value"]
            payload_hex = layout["encoded_value"].to_bytes(8, "big").hex().upper()
            message["signal_payload_hex"] = payload_hex
            message["can_frame"]["data_hex"] = payload_hex
            message["sequence"] = node._message_sequence + 1
            message["sent_at_unix_ms"] = int(time.time() * 1000)
            message["sampled_at_monotonic_ms"] = time.monotonic() * 1000
            self.network._seal_node_message(
                node_id, message, self.network.socket_secret()
            )
            result = self.network._validate_message(
                node_id,
                message,
                "can",
                node.CONNECTED_TO,
                check_periodicity=False,
            )
            with self.subTest(node=node_id):
                self.assertEqual(result is None, should_accept, result)

        invalid_signature = create_simulated_ota_package(
            "hpc-vehicle",
            "zcu-front-right",
            target_id,
            b"unsigned-update",
            "SIM-2.3",
            software_profile=profile,
        )
        invalid_signature["manifest"]["signature"] = "0" * 64
        response = self.client.post("/ota/flash", json=invalid_signature)
        self.assertEqual(response.status_code, 200, response.get_json())
        self.assertEqual(response.get_json()["status"], "completed")

        downgrade = create_simulated_ota_package(
            "hpc-vehicle",
            "zcu-front-right",
            target_id,
            b"downgrade-update",
            "SIM-1.0",
            software_profile=profile,
        )
        response = self.client.post("/ota/flash", json=downgrade)
        self.assertEqual(response.status_code, 200, response.get_json())
        self.assertEqual(response.get_json()["status"], "completed")
        self.assertTrue(
            any(
                event["node_id"] == target_id
                and event["category"] == "firmware_signature_bypass"
                for event in self.network.ACTIVE_SECURITY_EVENTS
            )
        )
        self.assertTrue(
            any(
                event["node_id"] == target_id
                and event["category"] == "downgrade_protection_bypass"
                for event in self.network.ACTIVE_SECURITY_EVENTS
            )
        )
        ids_profile = create_simulated_ota_package(
            self.network.NODES[sibling.CONNECTED_TO]["connected_to"][0],
            sibling.CONNECTED_TO,
            sibling_id,
            b"disable-node-ids",
            "SIM-2.2",
            software_profile={"ids_logging": False},
        )
        response = self.client.post("/ota/flash", json=ids_profile)
        self.assertEqual(response.status_code, 200, response.get_json())
        self.assertEqual(response.get_json()["status"], "completed")
        self.assertTrue(
            any(
                event["node_id"] == sibling_id
                and event["category"] == "ids_logging_bypass"
                for event in self.network.ACTIVE_SECURITY_EVENTS
            )
        )

    def test_every_node_handles_its_declared_uds_services(self):
        image = b"node-local-firmware-image"
        for node_id, node in self.network.NODE_INSTANCES.items():
            with self.subTest(node=node_id):
                self.assertTrue(node.handle_uds_request([0x10, 0x03])["positive_response"])
                self.assertTrue(node.handle_uds_request([0x11, 0x03])["positive_response"])
                self.assertTrue(node.handle_uds_request([0x10, 0x03])["positive_response"])

                seed = node.handle_uds_request([0x27, 0x01])
                key = security_key_for_seed(node_id, bytes(seed["response_bytes"][2:]))
                self.assertTrue(node.handle_uds_request([0x27, 0x02, *key])["positive_response"])
                self.assertTrue(node.handle_uds_request([0x14, 0xFF, 0xFF, 0xFF])["positive_response"])
                self.assertTrue(node.handle_uds_request([0x19, 0x01])["positive_response"])
                self.assertTrue(node.handle_uds_request([0x28, 0x00, 0x01])["positive_response"])

                rid = next(iter(node.UDS_RIDS))
                routine = [0x31, 0x01, int(rid[2:4], 16), int(rid[4:6], 16)]
                self.assertTrue(node.handle_uds_request(routine)["positive_response"])
                self.assertTrue(node.handle_uds_request([0x3E, 0x00])["positive_response"])
                self.assertTrue(node.handle_uds_request([0x85, 0x02])["positive_response"])
                self.assertFalse(node._uds_state["dtc_enabled"])
                self.assertTrue(node.handle_uds_request([0x85, 0x01])["positive_response"])

                role = getattr(node, "ROLE", "ecu")
                if role == "hpc":
                    source_id = node.TRUSTED_SOURCES[0]
                    zcu_id = None
                elif role == "zone_controller":
                    source_id = node.CONNECTED_TO[0]
                    zcu_id = node_id
                else:
                    parent_id = node.CONNECTED_TO
                    if self.network.NODES[parent_id]["role"] == "zone_controller":
                        zcu_id = parent_id
                        source_id = self.network.NODES[zcu_id]["connected_to"][0]
                    else:
                        zcu_id = None
                        source_id = parent_id
                package = create_simulated_ota_package(
                    source_id, zcu_id, node_id, image, "SIM-2.1"
                )
                self.assertEqual(
                    node.perform_ota(
                        package, node_instances=self.network.NODE_INSTANCES
                    )["status"],
                    "completed",
                )

    def test_zcu_sockets_deliver_all_zone_messages_to_vehicle_hpc(self):
        self.network.poll_node_messages()
        hpc = self.network.NODE_INSTANCES["hpc-vehicle"]
        received = hpc.aggregated_zcu_messages()
        self.assertGreaterEqual(len(received), 120)
        self.assertEqual(
            {message["relayed_by_zcu_id"] for message in received if "relayed_by_zcu_id" in message},
            {"zcu-front-left", "zcu-front-right", "zcu-rear-left", "zcu-rear-right"},
        )
        self.assertEqual(
            {message["source_node_id"] for message in received},
            {node_id for node_id, spec in self.network.NODES.items() if spec["role"] in {"ecu", "zone_controller"}},
        )
        for zcu_id in ("zcu-front-left", "zcu-front-right", "zcu-rear-left", "zcu-rear-right"):
            self.assertTrue(self.network.NODE_INSTANCES[zcu_id]._received_message_history)

    def test_can_ids_signal_ranges_and_periodicity_anomalies_are_dropped(self):
        self.network.poll_node_messages()
        source_id = "ecu-body-front"
        original = self.network.NODE_INSTANCES[source_id]._message_history[0]
        receiver_id = "zcu-front-right"

        tampered_id = dict(original)
        tampered_id["message_id"] = "0x7FF"
        tampered_id["can_frame"] = {**tampered_id["can_frame"], "can_id": 0x7FF, "can_id_hex": "0x7FF"}
        self.network._seal_node_message(source_id, tampered_id, self.network.socket_secret())
        bad_id = self.network._send_internal_socket(
            self.network.CAN_SOCKET_PORT,
            {"action": "can_frames", "source_node_id": source_id, "frames": [tampered_id]},
        )
        self.assertEqual(bad_id["dropped_frames"], 1)

        tampered_value = dict(original)
        tampered_value["signal_layout"] = {**tampered_value["signal_layout"], "encoded_value": 99999}
        tampered_value["signal_payload_hex"] = (99999).to_bytes(8, "big").hex().upper()
        tampered_value["can_frame"] = {**tampered_value["can_frame"], "data_hex": tampered_value["signal_payload_hex"]}
        self.network._seal_node_message(source_id, tampered_value, self.network.socket_secret())
        bad_signal = self.network._send_internal_socket(
            self.network.CAN_SOCKET_PORT,
            {"action": "can_frames", "source_node_id": source_id, "frames": [tampered_value]},
        )
        self.assertEqual(bad_signal["dropped_frames"], 1)

        tampered_period = dict(original)
        tampered_period["cycle_time_ms"] += 25
        tampered_period["periodicity_ms"] += 25
        self.network._seal_node_message(source_id, tampered_period, self.network.socket_secret())
        bad_period = self.network._send_internal_socket(
            self.network.CAN_SOCKET_PORT,
            {"action": "can_frames", "source_node_id": source_id, "frames": [tampered_period]},
        )
        self.assertEqual(bad_period["dropped_frames"], 1)
        self.assertGreaterEqual(len(self.network.ACTIVE_SECURITY_EVENTS), 3)
        self.assertTrue(all(event["action"] == "dropped" for event in self.network.ACTIVE_SECURITY_EVENTS[-3:]))

    def test_ids_validation_rejects_stale_and_early_telemetry(self):
        self.network.poll_node_messages()
        source_id = "ecu-body-front"
        receiver_id = "zcu-front-right"
        original = copy.deepcopy(
            self.network.NODE_INSTANCES[source_id]._message_history[0]
        )
        stale = copy.deepcopy(original)
        stale["sent_at_unix_ms"] = int(time.time() * 1000) - 10_000
        self.network._seal_node_message(
            source_id, stale, self.network.socket_secret()
        )
        stale_reason = self.network._validate_message(
            source_id, stale, "can", receiver_id
        )
        self.assertIn("freshness", stale_reason)

        first = copy.deepcopy(original)
        first["sequence"] += 1
        first["sampled_at_monotonic_ms"] += first["cycle_time_ms"]
        first["sent_at_unix_ms"] = int(time.time() * 1000)
        self.network._seal_node_message(
            source_id, first, self.network.socket_secret()
        )
        self.assertIsNone(
            self.network._validate_message(source_id, first, "can", receiver_id)
        )
        early = copy.deepcopy(first)
        early["sequence"] += 1
        early["sampled_at_monotonic_ms"] += 1
        early["sent_at_unix_ms"] = int(time.time() * 1000)
        self.network._seal_node_message(
            source_id, early, self.network.socket_secret()
        )
        early_reason = self.network._validate_message(
            source_id, early, "can", receiver_id
        )
        self.assertIn("flood rate", early_reason)

        self.assertEqual(
            self.network._validation_failure_category(stale_reason),
            "freshness_failure",
        )
        self.assertEqual(
            self.network._validation_failure_category(early_reason),
            "message_flood",
        )

    def test_every_node_emits_30_transport_messages_with_8_byte_signal_contracts(self):
        self.network.poll_node_messages()
        for node_id, spec in self.network.NODES.items():
            with self.subTest(node=node_id):
                self.assertEqual(len(spec["message_catalog"]), 30)
                self.assertTrue(spec["rx_message_catalog"])
                self.assertTrue(all(entry["cycle_time_ms"] > 0 for entry in spec["message_catalog"]))
                self.assertTrue(all(entry["signal_layout"]["bit_length"] == 64 for entry in spec["message_catalog"]))
                emitted = self.network.NODE_INSTANCES[node_id]._message_history
                self.assertTrue(all(message["periodicity_ms"] == message["cycle_time_ms"] for message in emitted))
                if spec["role"] == "ecu":
                    self.assertTrue(all("can_frame" in message and message["can_frame"]["dlc"] == 8 for message in emitted))
                else:
                    self.assertTrue(all("someip" in message and len(bytes.fromhex(message["someip"]["packet_hex"])) >= 16 for message in emitted))

    def test_socket_rejects_unsigned_request(self):
        import json
        import socket
        import time

        frame = json.dumps({"request_id": uuid4().hex, "timestamp": int(time.time()), "action": "snapshot"}).encode() + b"\n"
        with socket.create_connection(self.server.server_address, timeout=3) as connection:
            connection.sendall(frame)
            with connection.makefile("rb") as stream:
                response = json.loads(stream.readline())
        self.assertEqual(response["status"], "error")
        self.assertIn("auth", response["message"])


if __name__ == "__main__":
    unittest.main()
