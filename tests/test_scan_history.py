import base64
import hashlib
import hmac
import json
import importlib.util
import os
import pathlib
import sqlite3
import tempfile
import unittest
from contextlib import closing
from datetime import datetime, timedelta, timezone
from unittest.mock import Mock, patch
from uuid import uuid4

from cryptography.fernet import Fernet


CLOUD_APP_PATH = pathlib.Path(__file__).resolve().parents[1] / "cloud-app" / "app.py"


def load_cloud_app():
    module_name = f"cloud_app_test_{uuid4().hex}"
    spec = importlib.util.spec_from_file_location(module_name, CLOUD_APP_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load cloud app module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ScanHistoryTests(unittest.TestCase):
    def setUp(self):
        self.data_dir = tempfile.TemporaryDirectory()
        self.previous_data_dir = os.environ.get("DATA_DIR")
        self.previous_encryption_key = os.environ.get(
            "SCAN_HISTORY_ENCRYPTION_KEY"
        )
        self.previous_retention_days = os.environ.get("SCAN_RETENTION_DAYS")
        self.previous_cloud_region = os.environ.get("CLOUD_REGION")
        self.previous_jwt_secret = os.environ.get("CENTRAL_SERVICE_JWT_SECRET")
        os.environ["DATA_DIR"] = self.data_dir.name
        os.environ["SCAN_HISTORY_ENCRYPTION_KEY"] = Fernet.generate_key().decode()
        os.environ["SCAN_RETENTION_DAYS"] = "30"
        os.environ["CLOUD_REGION"] = "test-region-1"
        os.environ["CENTRAL_SERVICE_JWT_SECRET"] = (
            "test-central-service-jwt-secret-at-least-32-bytes"
        )
        self.cloud_app = load_cloud_app()
        self.client = self.cloud_app.app.test_client()

    def tearDown(self):
        if self.previous_data_dir is None:
            os.environ.pop("DATA_DIR", None)
        else:
            os.environ["DATA_DIR"] = self.previous_data_dir
        if self.previous_encryption_key is None:
            os.environ.pop("SCAN_HISTORY_ENCRYPTION_KEY", None)
        else:
            os.environ["SCAN_HISTORY_ENCRYPTION_KEY"] = self.previous_encryption_key
        if self.previous_retention_days is None:
            os.environ.pop("SCAN_RETENTION_DAYS", None)
        else:
            os.environ["SCAN_RETENTION_DAYS"] = self.previous_retention_days
        if self.previous_cloud_region is None:
            os.environ.pop("CLOUD_REGION", None)
        else:
            os.environ["CLOUD_REGION"] = self.previous_cloud_region
        if self.previous_jwt_secret is None:
            os.environ.pop("CENTRAL_SERVICE_JWT_SECRET", None)
        else:
            os.environ["CENTRAL_SERVICE_JWT_SECRET"] = self.previous_jwt_secret
        self.data_dir.cleanup()

    def test_scan_history_survives_app_reload(self):
        record = self.cloud_app.save_scan(
            {
                "attack_type": "replay_attack",
                "severity": "high",
                "risk_level": "high",
                "summary": "Replay activity detected",
            }
        )

        restarted_app = load_cloud_app()
        restarted_client = restarted_app.app.test_client()
        history = restarted_client.get("/api/history?limit=10")
        latest = restarted_client.get("/api/last-scan")

        self.assertEqual(history.status_code, 200)
        self.assertEqual(history.get_json()["scans"][0]["scan_id"], record["scan_id"])
        self.assertEqual(latest.get_json()["attack_type"], "replay_attack")
        self.assertEqual(latest.get_json()["scan_id"], record["scan_id"])
        self.assertEqual(len(record["created_at"]), 25)

    def test_scan_record_is_encrypted_at_rest(self):
        record = self.cloud_app.save_scan(
            {
                "test_session_id": "pseudonymous-session",
                "summary": "Sensitive summary text",
                "risk_level": "medium",
            }
        )
        with closing(
            sqlite3.connect(self.cloud_app.history_db_path())
        ) as connection:
            stored = connection.execute(
                "SELECT record_json FROM scan_history WHERE scan_id = ?",
                (record["scan_id"],),
            ).fetchone()[0]

        self.assertTrue(stored.startswith("fernet:v1:"))
        self.assertNotIn("pseudonymous-session", stored)
        self.assertNotIn("Sensitive summary text", stored)

    def test_saved_evidence_filters_node_data_and_retains_sanitized_report(self):
        record = self.cloud_app.save_scan(
            {
                "attack_type": "flooding",
                "risk_level": "medium",
                "node_id": "private-ecu-id",
                "vin": "VIN-SECRET",
                "raw_frames": ["private-payload"],
                "target_summary": {
                    "target_node_ids": ["ecu-powertrain", "private-ecu-id"]
                },
                "before_attack": {
                    "network_node_count": 12,
                    "security_event_count": 0,
                    "node_ids": ["private-ecu-id"],
                },
                "threat_report": {
                    "status": "local_rag_only",
                    "provider": "local_rag",
                    "executive_summary": "Aggregate simulator finding.",
                    "raw_prompt": "private-payload",
                    "recommendations": ["Validate the rate limit."],
                },
            }
        )

        loaded = self.cloud_app.saved_scan(record["scan_id"])
        serialized = json.dumps(loaded)
        self.assertIn("Aggregate simulator finding.", serialized)
        self.assertIn("network_node_count", serialized)
        self.assertNotIn("ecu-powertrain", serialized)
        self.assertNotIn("private-ecu-id", serialized)
        self.assertNotIn("VIN-SECRET", serialized)
        self.assertNotIn("private-payload", serialized)
        self.assertNotIn("raw_prompt", serialized)

    def test_network_observability_proxy_returns_only_aggregated_fields(self):
        central_response = Mock()
        central_response.raise_for_status.return_value = None
        central_response.json.return_value = {
            "observed_at": "2026-10-10T00:00:00Z",
            "network": {"node_count": 15, "zone_count": 4, "node_ids": ["private-node"]},
            "sockets": [
                {
                    "name": "CAN gateway",
                    "service": "vehicle-network",
                    "transport": "TCP",
                    "protocols": ["CAN"],
                    "host": "vehicle-network",
                    "port": 6003,
                    "status": "listening",
                    "direction": "ECU <-> gateway",
                    "security": "simulator",
                    "raw_frame": "private-payload",
                }
            ],
            "traffic_by_protocol": {
                "CAN": {
                    "tx_generated": 10,
                    "tx_delivered": 9,
                    "rx_accepted": 9,
                    "security_event_count": 1,
                    "node_id": "private-node",
                }
            },
            "security_events": {
                "retained_event_count": 1,
                "category_counts": {"signal_out_of_range": 1},
                "events": [{"node_id": "private-node"}],
            },
            "uds": {
                "component_count": 15,
                "successful_count": 14,
                "failed_count": 1,
                "active_dtc_count": 2,
                "response_categories": {"positive": 14, "timeout": 1},
                "node_results": [{"node_id": "private-node"}],
            },
            "raw_frames": ["private-payload"],
        }

        with patch.object(
            self.cloud_app, "central_request", return_value=central_response
        ):
            response = self.client.get("/api/network/observability")

        self.assertEqual(response.status_code, 200, response.get_json())
        serialized = json.dumps(response.get_json())
        self.assertIn("listening", serialized)
        self.assertIn("signal_out_of_range", serialized)
        self.assertIn("response_categories", serialized)
        self.assertNotIn("private-node", serialized)
        self.assertNotIn("private-payload", serialized)
        self.assertNotIn("raw_frames", serialized)
        self.assertNotIn("node_results", serialized)

    def test_network_activity_proxy_filters_raw_frames_and_authentication(self):
        central_response = Mock()
        central_response.raise_for_status.return_value = None
        central_response.json.return_value = {
            "observed_at": "2026-10-10T00:00:00Z",
            "messages": [
                {
                    "source_node_id": "ecu-powertrain",
                    "message_name": "speed_status",
                    "message_id": "0x101",
                    "transport_type": "CAN",
                    "direction": "tx",
                    "signals": {"vehicle_speed_kph": 42, "latitude": 37.5},
                    "signal_payload_hex": "PRIVATE-FRAME",
                    "auth_tag": "PRIVATE-AUTH",
                }
            ],
            "security_events": [
                {
                    "event_id": "event-1",
                    "node_id": "ecu-powertrain",
                    "detected_at_node_id": "zcu-front-left",
                    "category": "signal_out_of_range",
                    "detail": "Simulator rejected out-of-range signal",
                    "raw_payload": "PRIVATE-FRAME",
                },
                {
                    "source_node_id": "ecu-telematics",
                    "message_name": "GNSSPosition",
                    "signals": {"longitude": -122.1},
                },
            ],
            "diagnostics": [
                {
                    "event_type": "diagnostic",
                    "timestamp": 1_791_640_800.0,
                    "phase": "before_attack",
                    "source_node_id": "hpc-vehicle",
                    "target_node_id": "ecu-powertrain",
                    "transport_type": "CAN",
                    "socket_id": "hpc-can",
                    "direction": "request / response",
                    "message_id": "0x100",
                    "service_id": "0x19",
                    "response_service_id": "0x59",
                    "status": "positive",
                    "nrc": None,
                    "latency_ms": 1.2,
                    "raw_response": "PRIVATE-DIAGNOSTIC-PAYLOAD",
                }
            ],
            "scan_phase": "before_attack",
            "scan_phase_updated_at": 1_791_640_800.0,
            "attack_active": True,
        }

        with patch.object(
            self.cloud_app, "central_request", return_value=central_response
        ):
            response = self.client.get("/api/network/activity?limit=20")

        self.assertEqual(response.status_code, 200, response.get_json())
        serialized = json.dumps(response.get_json())
        self.assertIn("vehicle_speed_kph", serialized)
        self.assertIn("signal_out_of_range", serialized)
        self.assertNotIn("PRIVATE-FRAME", serialized)
        self.assertNotIn("PRIVATE-AUTH", serialized)
        self.assertNotIn("raw_payload", serialized)
        self.assertNotIn("latitude", serialized)
        self.assertNotIn("GNSSPosition", serialized)
        self.assertNotIn("longitude", serialized)
        self.assertIn("before_attack", serialized)
        self.assertIn("0x19", serialized)
        self.assertIn("0x59", serialized)
        self.assertNotIn("PRIVATE-DIAGNOSTIC-PAYLOAD", serialized)
        self.assertTrue(response.get_json()["attack_active"])
        self.assertEqual(
            response.get_json()["scan_phase_updated_at"],
            1_791_640_800.0,
        )

    def test_scan_stop_proxy_uses_authenticated_central_service(self):
        central_response = Mock()
        central_response.status_code = 202
        central_response.json.return_value = {
            "status": "stop_requested",
            "message": "Stop requested; post-attack diagnostics will still run.",
        }
        central_response.raise_for_status.return_value = None

        with patch.object(
            self.cloud_app, "central_request", return_value=central_response
        ) as central_request:
            response = self.client.post("/api/scan/stop")

        self.assertEqual(response.status_code, 202)
        self.assertEqual(response.get_json()["status"], "stop_requested")
        self.assertEqual(central_request.call_args.args[0], "post")
        self.assertTrue(central_request.call_args.args[1].endswith("/scan/stop"))

    def test_ota_package_is_relayed_to_central_compute(self):
        package = {
            "source_hpc_id": "hpc-vehicle",
            "zcu_id": "zcu-front-right",
            "target_ecu_id": "ecu-body-front",
            "image_hex": "01020304",
            "manifest": {
                "ecu_id": "ecu-body-front",
                "version": "SIM-2.0",
                "image_size": 4,
                "sha256": "a" * 64,
            },
        }
        central_response = Mock()
        central_response.status_code = 200
        central_response.json.return_value = {
            "status": "completed",
            "uds_trace": [{"service": "0x10", "service_name": "DiagnosticSessionControl"}],
        }
        central_response.raise_for_status.return_value = None

        with patch.object(
            self.cloud_app, "central_request", return_value=central_response
        ) as central_request:
            response = self.client.post("/api/ota/flash", json=package)

        self.assertEqual(response.status_code, 200, response.get_json())
        self.assertEqual(response.get_json()["status"], "completed")
        self.assertEqual(central_request.call_args.args[0], "post")
        self.assertTrue(central_request.call_args.args[1].endswith("/ota/flash"))
        self.assertEqual(central_request.call_args.kwargs["json"], package)

    def test_ota_proxy_rejects_oversized_or_missing_image_before_relay(self):
        with patch.object(self.cloud_app, "central_request") as central_request:
            missing = self.client.post("/api/ota/flash", json={})
            oversized = self.client.post(
                "/api/ota/flash",
                json={"image_hex": "0" * 2_097_154},
            )

        self.assertEqual(missing.status_code, 400)
        self.assertEqual(oversized.status_code, 400)
        central_request.assert_not_called()

    def test_expired_scan_records_are_removed(self):
        old_created_at = "2020-01-01T00:00:00+00:00"
        old_record = self.cloud_app.encrypt_record(
            {
                "scan_id": "expired-scan",
                "created_at": old_created_at,
                "risk_level": "low",
            }
        )
        self.cloud_app.ensure_history_table()
        with closing(
            sqlite3.connect(self.cloud_app.history_db_path())
        ) as connection, connection:
            connection.execute(
                "INSERT INTO scan_history (scan_id, created_at, record_json) VALUES (?, ?, ?)",
                ("expired-scan", old_created_at, old_record),
            )

        self.assertEqual(self.cloud_app.saved_scans(10), [])

    def test_history_limit_must_be_between_one_and_one_hundred(self):
        for query in ("limit=0", "limit=101", "limit=invalid"):
            with self.subTest(query=query):
                self.assertEqual(self.client.get(f"/api/history?{query}").status_code, 400)

    def test_cloud_scan_storage_and_response_exclude_raw_vehicle_data(self):
        central_result = {
            "risk_level": "high",
            "summary": "Aggregated analysis found high risk.",
            "alert_action": "block_and_alert",
            "test_session_id": "per-scan-pseudonym",
            "pseudonym_scope": "single_test_session",
            "assessment_purpose": "vehicle_security_assessment",
            "test_scenario_id": "simulator:spoofing:v1",
            "started_at": "2026-10-10T09:00:00+00:00",
            "ended_at": "2026-10-10T09:00:03+00:00",
            "timestamp_precision": "seconds",
            "attack_started_at": "2026-10-10T09:00:01Z",
            "attack_ended_at": "2026-10-10T09:00:02Z",
            "test_execution_result": "passed",
            "security_assessment_result": "not_assessed",
            "recovery_status": "not_assessed",
            "confidence_status": "uncalibrated_isolation_forest",
            "diagnostic_coverage_percent": 100.0,
            "evidence_references": [
                "per-scan-pseudonym:baseline",
                "per-scan-pseudonym:during-test-summary",
            ],
            "attack_summary": {
                "status": "completed",
                "elapsed_seconds": 1.0,
                "message_count": 10,
                "message_rate_per_second": 10.0,
                "message_loss_percentage": 0.0,
                "affected_interfaces": ["CAN-FD"],
            },
            "probe_summary": {
                "suite": "bounded_simulator_protocol_probes_v1",
                "status": "completed",
                "attempted_count": 24,
                "rejected_count": 20,
                "target_node_count": 8,
                "category_counts": {
                    "can_id_mismatch": 1,
                    "uds_security_access": 1,
                },
                "protocols": {
                    "can": {
                        "attempted_count": 5,
                        "rejected_count": 5,
                        "target_node_count": 1,
                    }
                },
                "private_node_id": "private-node",
            },
            "during_attack": {
                "sample_window_seconds": 1.0,
                "message_count": 10,
                "message_rate_per_second": 10.0,
                "message_loss_percentage": 0.0,
                "security_event_count": 1,
                "affected_interfaces": ["CAN-FD"],
                "raw_messages": [{"signal": "private"}],
            },
            "cloud_region": "test-region-1",
            "before_attack": {
                "network_node_count": 15,
                "uds_tested_node_count": 15,
                "uds_successful_count": 15,
                "active_dtc_count": 0,
                "ecu_family_counts": {"powertrain:ecu": 2},
                "ecu_software_version_counts": {"1.2.3": 2},
                "gateway_configuration_version": "simulator-config-v1",
                "network_protocol_counts": {"CAN-FD": 2},
                "observed_interface_counts": {"CAN-FD": 10},
                "sampled_message_count": 10,
                "sampled_message_rate_per_second": 5.0,
                "inter_arrival_ms_mean": 200.0,
                "inter_arrival_ms_p95": 250.0,
                "inter_arrival_ms_max": 300.0,
                "tx_generated_count": 10,
                "tx_delivered_count": 10,
                "rx_accepted_count": 10,
                "message_loss_percentage": 0.0,
                "network_error_rate_percentage": None,
                "network_error_rate_status": "not_measured_by_simulator",
                "bus_utilization_percentage": None,
                "bus_utilization_status": "not_measured_no_bus_rate_configuration",
                "diagnostic_latency_mean_ms": 1.2,
                "diagnostic_latency_max_ms": 2.4,
                "diagnostic_timeout_count": 0,
                "diagnostic_timeout_rate_percent": 0.0,
                "diagnostic_response_categories": {
                    "positive": 15,
                    "negative": 0,
                    "timeout": 0,
                    "transport_error": 0,
                },
                "ecu_availability_percent": 100.0,
                "behavior_variation_count": 0,
                "security_event_count": 0,
                "anomaly_score": 0.0,
                "risk_level": "low",
                "summary": "Before attack",
                "diagnostic_records": [{"node_id": "private-node"}],
            },
            "after_attack": {
                "network_node_count": 15,
                "uds_tested_node_count": 15,
                "uds_successful_count": 15,
                "active_dtc_count": 0,
                "ecu_family_counts": {"powertrain:ecu": 2},
                "ecu_software_version_counts": {"1.2.3": 2},
                "gateway_configuration_version": "simulator-config-v1",
                "network_protocol_counts": {"CAN-FD": 2},
                "observed_interface_counts": {"CAN-FD": 10},
                "sampled_message_count": 10,
                "sampled_message_rate_per_second": 5.0,
                "inter_arrival_ms_mean": 200.0,
                "inter_arrival_ms_p95": 250.0,
                "inter_arrival_ms_max": 300.0,
                "tx_generated_count": 10,
                "tx_delivered_count": 10,
                "rx_accepted_count": 10,
                "message_loss_percentage": 0.0,
                "network_error_rate_percentage": None,
                "network_error_rate_status": "not_measured_by_simulator",
                "bus_utilization_percentage": None,
                "bus_utilization_status": "not_measured_no_bus_rate_configuration",
                "diagnostic_latency_mean_ms": 1.2,
                "diagnostic_latency_max_ms": 2.4,
                "diagnostic_timeout_count": 0,
                "diagnostic_timeout_rate_percent": 0.0,
                "diagnostic_response_categories": {
                    "positive": 15,
                    "negative": 0,
                    "timeout": 0,
                    "transport_error": 0,
                },
                "ecu_availability_percent": 100.0,
                "behavior_variation_count": 1,
                "security_event_count": 3,
                "security_event_categories": {"spoofing": 3},
                "anomaly_score": 0.25,
                "isolation_forest_max_anomaly_score": 0.87,
                "isolation_forest_deviation_node_count": 1,
                "ota_weakness_count": 1,
                "ota_tested_weakness_count": 1,
                "ota_weakness_findings": [
                    {
                        "weakness_id": "W4",
                        "finding_id": "NET-AUTH-001",
                        "severity": "high",
                        "title": "Message authentication is disabled.",
                        "affected_target_count": 1,
                        "affected_controls": ["message_authentication"],
                        "relevant_test_ids": ["T2", "T3"],
                        "test_coverage": "covered",
                        "affected_node_ids": ["private-node"],
                    }
                ],
                "private_node_scores": [{"node_id": "private-node"}],
                "risk_level": "medium",
                "summary": "After attack",
            },
            "comparison": {
                "isolation_forest_score_delta": 0.62,
                "isolation_forest_deviation_count_delta": 1,
                "change_point_indicator": True,
                "change_point_method": "phase_score_delta_threshold",
                "change_point_threshold": 0.1,
                "private_node_ids": ["private-node"],
            },
            "ml_models": {
                "isolation_forest": "active_per_scan_baseline",
                "private_model_path": "secret/model.pkl",
            },
            "events": [{"node_id": "private-node", "signals": {"speed": 65}}],
            "network_snapshot": {"nodes": [{"id": "private-node"}]},
        }
        central_response = Mock()
        central_response.status_code = 200
        central_response.raise_for_status.return_value = None
        central_response.json.return_value = central_result
        service_state_response = Mock()
        service_state_response.raise_for_status.return_value = None
        service_state_response.json.return_value = {"service_state": "in_service"}

        with patch.object(
            self.cloud_app.requests, "post", return_value=central_response
        ) as central_post, patch.object(
            self.cloud_app.requests, "get", return_value=service_state_response
        ) as central_get:
            response = self.client.post(
                "/api/scan/start",
                json={
                    "attack_type": "spoofing",
                    "severity": "medium",
                    "duration_seconds": 3,
                },
            )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            central_post.call_args.kwargs["json"]["duration_seconds"], 3
        )
        self.assertEqual(central_post.call_args.kwargs["timeout"], 48)
        self.assertEqual(
            central_post.call_args.kwargs["verify"],
            self.cloud_app.CENTRAL_TLS_CA,
        )
        self.assertEqual(
            central_post.call_args.kwargs["cert"],
            (
                self.cloud_app.CENTRAL_TLS_CLIENT_CERT,
                self.cloud_app.CENTRAL_TLS_CLIENT_KEY,
            ),
        )
        self.assertEqual(central_get.call_args.kwargs["verify"], self.cloud_app.CENTRAL_TLS_CA)
        self.assertEqual(
            central_get.call_args.kwargs["cert"],
            (
                self.cloud_app.CENTRAL_TLS_CLIENT_CERT,
                self.cloud_app.CENTRAL_TLS_CLIENT_KEY,
            ),
        )
        self.assertTrue(
            central_post.call_args.kwargs["headers"]["Authorization"].startswith(
                "Bearer "
            )
        )
        self.assertTrue(
            central_get.call_args.kwargs["headers"]["Authorization"].startswith(
                "Bearer "
            )
        )
        token = central_post.call_args.kwargs["headers"]["Authorization"].split(
            " ", 1
        )[1]
        encoded_header, encoded_claims, encoded_signature = token.split(".")
        signing_input = f"{encoded_header}.{encoded_claims}".encode("ascii")
        expected_signature = hmac.new(
            os.environ["CENTRAL_SERVICE_JWT_SECRET"].encode("utf-8"),
            signing_input,
            hashlib.sha256,
        ).digest()
        actual_signature = base64.urlsafe_b64decode(
            encoded_signature + "=" * (-len(encoded_signature) % 4)
        )
        header = json.loads(
            base64.urlsafe_b64decode(
                encoded_header + "=" * (-len(encoded_header) % 4)
            )
        )
        claims = json.loads(
            base64.urlsafe_b64decode(
                encoded_claims + "=" * (-len(encoded_claims) % 4)
            )
        )
        self.assertTrue(hmac.compare_digest(expected_signature, actual_signature))
        self.assertEqual(header, {"alg": "HS256", "typ": "JWT"})
        self.assertEqual(claims["iss"], "cloud-app")
        self.assertEqual(claims["aud"], "vehicle-central-compute")
        self.assertGreater(claims["exp"], claims["iat"])
        self.assertLessEqual(claims["exp"] - claims["iat"], 60)
        content = response.get_data(as_text=True)
        self.assertNotIn("private-node", content)
        self.assertNotIn("network_snapshot", content)
        self.assertNotIn("diagnostic_records", content)
        self.assertNotIn('"events"', content)
        self.assertIn('"duration_seconds":3', content)
        self.assertNotIn("raw_result", content)
        self.assertIn('"isolation_forest_deviation_node_count":1', content)
        self.assertIn('"isolation_forest_score_delta":0.62', content)
        self.assertIn('"isolation_forest_deviation_count_delta":1', content)
        self.assertIn('"active_per_scan_baseline"', content)
        self.assertIn('"test_session_id"', content)
        self.assertIn('"security_assessment_result":"not_assessed"', content)
        self.assertIn('"recovery_status":"not_assessed"', content)
        self.assertIn('"diagnostic_timeout_rate_percent":0.0', content)
        self.assertIn('"diagnostic_response_categories":{"negative":0,"positive":15,"timeout":0,"transport_error":0}', content)
        self.assertIn('"bus_utilization_percentage":null', content)
        self.assertIn('"bus_utilization_status":"not_measured_no_bus_rate_configuration"', content)
        self.assertIn('"network_error_rate_percentage":null', content)
        self.assertIn('"gateway_configuration_version":"simulator-config-v1"', content)
        self.assertIn('"change_point_indicator"', content)
        self.assertIn('"ota_weakness_count":1', content)
        self.assertIn('"weakness_id":"W4"', content)
        self.assertIn('"test_coverage":"covered"', content)
        self.assertIn('"cloud_region":"test-region-1"', content)
        self.assertIn('"suite":"bounded_simulator_protocol_probes_v1"', content)
        self.assertIn('"attempted_count":24', content)
        self.assertIn('"uds_security_access":1', content)
        self.assertNotIn('"private_node_id"', content)
        self.assertIn('"affected_interfaces":["CAN-FD"]', content)
        self.assertNotIn("raw_messages", content)
        self.assertNotIn("private_node_scores", content)
        self.assertNotIn("private_model_path", content)
        evidence = self.client.get("/api/evidence/latest")
        self.assertEqual(evidence.status_code, 200)
        evidence_payload = evidence.get_json()["evidence"]
        self.assertEqual(evidence_payload["probe_summary"]["status"], "completed")
        self.assertEqual(
            evidence_payload["before_attack"]["network_node_count"], 15
        )
        by_id = self.client.get(f"/api/evidence/{evidence_payload['scan_id']}")
        self.assertEqual(by_id.status_code, 200)
        self.assertEqual(
            by_id.get_json()["evidence"]["scan_id"], evidence_payload["scan_id"]
        )
        self.assertNotIn("private-node", by_id.get_data(as_text=True))

        legacy_created_at = (
            datetime.now(timezone.utc) - timedelta(days=2)
        ).isoformat(timespec="seconds")
        self.cloud_app.ensure_history_table()
        with closing(
            sqlite3.connect(self.cloud_app.history_db_path())
        ) as connection, connection:
            connection.execute(
                "INSERT INTO scan_history (scan_id, created_at, record_json) VALUES (?, ?, ?)",
                (
                    "legacy-scan",
                    legacy_created_at,
                    self.cloud_app.json.dumps(
                        {
                            "scan_id": "legacy-scan",
                            "created_at": legacy_created_at,
                            "risk_level": "high",
                            "summary": "Legacy result",
                            "raw_result": {"node_id": "private-node"},
                            "events": [{"node_id": "private-node"}],
                        }
                    ),
                ),
            )
            connection.execute(
                "DELETE FROM scan_history_migrations WHERE migration_id = ?",
                ("encrypted_privacy_safe_records_v2",),
            )

        history = self.client.get("/api/history").get_json()["scans"]
        self.assertEqual(len(history), 2)
        self.assertNotIn("private-node", repr(history))
        self.assertNotIn("events", history[0])
        with closing(sqlite3.connect(self.cloud_app.history_db_path())) as connection:
            legacy_record = connection.execute(
                "SELECT record_json FROM scan_history WHERE scan_id = ?",
                ("legacy-scan",),
            ).fetchone()
        self.assertNotIn("private-node", legacy_record[0])
        self.assertNotIn('"events"', legacy_record[0])
        self.assertNotIn('"raw_result"', legacy_record[0])

    def test_scan_is_rejected_before_central_trigger_when_vehicle_is_not_in_service(self):
        state_response = Mock()
        state_response.raise_for_status.return_value = None
        state_response.json.return_value = {"service_state": "out_of_service"}

        with patch.object(
            self.cloud_app.requests, "get", return_value=state_response
        ), patch.object(self.cloud_app.requests, "post") as central_post:
            response = self.client.post(
                "/api/scan/start",
                json={
                    "attack_type": "spoofing",
                    "severity": "medium",
                    "duration_seconds": 1,
                },
            )

        self.assertEqual(response.status_code, 409)
        self.assertEqual(response.get_json()["service_state"], "out_of_service")
        central_post.assert_not_called()


if __name__ == "__main__":
    unittest.main()