import importlib.util
import pathlib
import unittest
from unittest.mock import Mock, patch
from uuid import uuid4


CLOUD_APP_PATH = (
    pathlib.Path(__file__).resolve().parents[1] / "cloud-app" / "app.py"
)


def load_cloud_app():
    module_name = f"cloud_app_route_test_{uuid4().hex}"
    spec = importlib.util.spec_from_file_location(module_name, CLOUD_APP_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load the cloud application")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class CloudServiceRouteTests(unittest.TestCase):
    def setUp(self):
        self.cloud = load_cloud_app()
        self.client = self.cloud.app.test_client()

    def test_sovd_and_someip_routes_forward_component_and_signal_requests(self):
        sovd_response = Mock()
        sovd_response.status_code = 200
        sovd_response.json.return_value = {
            "status": "completed",
            "component_id": "ecu-body-front",
        }
        signal_response = Mock()
        signal_response.status_code = 200
        signal_response.json.return_value = {
            "found": True,
            "target_node_id": "zcu-front-right",
        }
        with patch.object(
            self.cloud,
            "central_request",
            side_effect=[sovd_response, signal_response],
        ) as central_request:
            sovd = self.client.post(
                "/api/diagnostics/sovd",
                json={
                    "component_id": "ecu-body-front",
                    "operation": "readDTCInformation",
                },
            )
            signal = self.client.post(
                "/api/signals/read",
                json={
                    "target_node_id": "zcu-front-right",
                    "signal_name": "window_position_pct",
                },
            )

        self.assertEqual(sovd.status_code, 200)
        self.assertEqual(sovd.get_json()["component_id"], "ecu-body-front")
        self.assertTrue(
            central_request.call_args_list[0].args[1].endswith("/sovd/v1/diagnostics")
        )
        self.assertEqual(signal.status_code, 200)
        self.assertTrue(
            central_request.call_args_list[1].args[1].endswith("/signals/read")
        )

    def test_signal_catalog_route_forwards_selected_target(self):
        catalog_response = Mock()
        catalog_response.status_code = 200
        catalog_response.json.return_value = {
            "status": "ok",
            "target_node_id": "hpc-vehicle",
            "signals": ["vehicle_speed_kph"],
        }
        with patch.object(
            self.cloud,
            "central_request",
            return_value=catalog_response,
        ) as central_request:
            response = self.client.get(
                "/api/signals/catalog?target_node_id=hpc-vehicle"
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["signals"], ["vehicle_speed_kph"])
        self.assertTrue(
            central_request.call_args.args[1].endswith("/signals/catalog")
        )
        self.assertEqual(
            central_request.call_args.kwargs["params"],
            {"target_node_id": "hpc-vehicle"},
        )

    def test_live_activity_keeps_socket_metadata_but_filters_raw_packet_bytes(self):
        central_response = Mock()
        central_response.raise_for_status.return_value = None
        central_response.json.return_value = {
            "observed_at": "now",
            "messages": [],
            "security_events": [
                {
                    "event_id": "security-1",
                    "event_type": "attack_marker",
                    "phase": "attack",
                    "attack_generated": True,
                }
            ],
            "diagnostics": [],
            "socket_events": [
                {
                    "event_id": "event-1",
                    "socket_id": "zcu-hpc-tcp",
                    "phase": "attack",
                    "attack_generated": True,
                    "message_name": "DoIP UDS request / response",
                    "message_id": "TransferData",
                    "message_length_bytes": 8,
                    "packet_hex": "sensitive firmware bytes",
                    "detail": "DoIP target zcu-front-right",
                }
            ],
        }

        with patch.object(
            self.cloud, "central_request", return_value=central_response
        ) as central_request:
            response = self.client.get("/api/network/activity?limit=25")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(central_request.call_args.kwargs["timeout"], 13)
        event = response.get_json()["socket_events"][0]
        self.assertEqual(event["socket_id"], "zcu-hpc-tcp")
        self.assertEqual(event["message_id"], "TransferData")
        self.assertEqual(event["message_length_bytes"], 8)
        self.assertEqual(event["phase"], "attack")
        self.assertTrue(event["attack_generated"])
        self.assertNotIn("packet_hex", event)
        security_event = response.get_json()["security_events"][0]
        self.assertEqual(security_event["phase"], "attack")
        self.assertTrue(security_event["attack_generated"])


if __name__ == "__main__":
    unittest.main()
