import pathlib
import sys
import unittest


CENTRAL_DIR = pathlib.Path(__file__).resolve().parents[1] / "vehicle-central-compute"
sys.path.insert(0, str(CENTRAL_DIR))

from behavior_analysis.analyzer import MODEL_STATUS
from scanner.service import run_scan


class ScanWorkflowTests(unittest.TestCase):
    def make_snapshot(self, after_attack, weak_controls=None):
        weak_controls = weak_controls or set()
        return {
            "network_snapshot": {
                "node_count": 4,
                "nodes": [
                    {
                        "id": "private-vehicle-node-0",
                        "role": "zone_controller",
                        "zone": "front_left",
                        "functional_domain": "zonal_control",
                        "protocol": "CAN-FD",
                        "connected_to": ["private-vehicle-hpc"],
                        "max_message_rate_hz": 500,
                        "max_message_count": 64,
                        "max_payload_bytes": 64,
                        "baseline_message": {"signals": {}},
                    }
                ],
            },
            "diagnostics": [
                {
                    "node_id": f"private-vehicle-node-{index}",
                    "messages_sent": 10,
                    "uds_session": 1,
                    "active_dtcs": [],
                }
                for index in range(4)
            ],
            "node_behavior": [
                {
                    "node_id": f"private-vehicle-node-{index}",
                    "behavior_state": (
                        "variation_detected"
                        if after_attack and index == 0
                        else "within_declared_contract"
                    ),
                    "tx_generated": 10,
                    "tx_delivered": 10,
                    "rx_accepted": 10,
                    **(
                        {
                            f"software_profile_{control}_enabled": False
                            for control in weak_controls
                        }
                        if index == 0
                        else {}
                    ),
                }
                for index in range(4)
            ],
            "security_events": (
                [
                    {
                        "node_id": "private-vehicle-node-0",
                        "category": "periodicity_violation",
                    }
                ]
                if after_attack
                else []
            ),
        }

    def test_scan_collects_before_and_after_analytics_without_raw_records(self):
        calls = []
        snapshots = iter(
            [self.make_snapshot(False), self.make_snapshot(True)]
        )

        def network_request(action, **parameters):
            calls.append((action, parameters))
            if action == "vehicle_service_state":
                return {"service_state": "in_service"}
            if action == "scan_activity_phase":
                return {"status": "ok", "scan_phase": parameters["phase"]}
            if action == "snapshot":
                return next(snapshots)
            if action == "network_diagnostics":
                return {
                    "component_count": 4,
                    "successful_count": 4,
                    "failed_count": 0,
                    "active_dtc_count": 0,
                }
            if action == "authorized_attack_test":
                return {
                    "status": "completed",
                    "execution_mode": "bounded_simulator_socket_traffic",
                    "elapsed_seconds": 1,
                    "event_count": 1,
                    "attack_frame_count": 512,
                    "accepted_frame_count": 1,
                    "dropped_frame_count": 511,
                    "affected_node_count": 1,
                    "affected_interfaces": ["CAN-FD"],
                    "affected_sockets": ["zcu-can"],
                    "targeting_mode": "operator_selected",
                    "target_role_counts": {"ecu": 1},
                    "target_security_level_counts": {"standard": 1},
                }
            raise AssertionError(f"unexpected simulator action: {action}")

        result = run_scan(
            network_request,
            "flooding",
            "medium",
            MODEL_STATUS,
            duration_seconds=1,
            target_node_ids=["private-vehicle-node-0"],
        )

        self.assertEqual(
            [action for action, _ in calls],
            [
                "vehicle_service_state",
                "scan_activity_phase",
                "snapshot",
                "network_diagnostics",
                "scan_activity_phase",
                "authorized_attack_test",
                "scan_activity_phase",
                "snapshot",
                "network_diagnostics",
                "scan_activity_phase",
            ],
        )
        self.assertTrue(calls[5][1]["authorized_simulation"])
        self.assertEqual(calls[5][1]["duration_seconds"], 1)
        attack_plan = calls[5][1]["attack_frames"]
        self.assertEqual(len(attack_plan), 1)
        self.assertEqual(
            attack_plan[0]["target_ecu_id"], "private-vehicle-node-0"
        )
        self.assertEqual(attack_plan[0]["attack_type"], "flooding")
        self.assertEqual(attack_plan[0]["severity"], "medium")
        self.assertEqual(attack_plan[0]["message_count"], 512)
        self.assertEqual(
            calls[5][1]["target_node_ids"], ["private-vehicle-node-0"]
        )
        self.assertEqual(result["status"], "completed")
        self.assertEqual(len(result["test_session_id"]), 32)
        self.assertEqual(result["timestamp_precision"], "seconds")
        self.assertEqual(result["target_summary"]["targeting_mode"], "operator_selected")
        self.assertEqual(result["target_summary"]["target_count"], 1)
        self.assertEqual(
            result["attack_summary"]["execution_mode"],
            "bounded_simulator_socket_traffic",
        )
        self.assertEqual(result["attack_summary"]["attack_frame_count"], 512)
        self.assertEqual(result["attack_summary"]["affected_sockets"], ["zcu-can"])
        self.assertEqual(len(result["started_at"]), 25)
        self.assertEqual(len(result["ended_at"]), 25)
        self.assertEqual(result["before_attack"]["uds_tested_node_count"], 4)
        self.assertEqual(result["after_attack"]["security_event_count"], 1)
        for phase in (result["before_attack"], result["after_attack"]):
            self.assertIsNone(phase["bus_utilization_percentage"])
            self.assertEqual(
                phase["bus_utilization_status"],
                "not_measured_no_bus_rate_configuration",
            )
            self.assertIsNone(phase["network_error_rate_percentage"])
            self.assertEqual(
                phase["network_error_rate_status"],
                "not_measured_by_simulator",
            )
        self.assertIn("change_point_indicator", result["comparison"])
        self.assertEqual(result["recovery_status"], "not_assessed")
        self.assertEqual(
            result["after_attack"]["analysis_method"],
            "weighted_security_rules+isolation_forest",
        )
        self.assertGreater(
            result["after_attack"]["isolation_forest_max_anomaly_score"],
            result["before_attack"]["isolation_forest_max_anomaly_score"],
        )
        self.assertNotIn("xgboost", result["ml_models"])
        self.assertGreater(
            result["comparison"]["isolation_forest_score_delta"], 0
        )
        self.assertGreater(
            result["comparison"]["isolation_forest_deviation_count_delta"], 0
        )
        self.assertTrue(result["comparison"]["risk_increased"])
        self.assertNotIn("private-vehicle-node", repr(result))
        self.assertNotIn("network_snapshot", result)
        self.assertNotIn("security_events", result)
        self.assertFalse(result["raw_vehicle_data_shared_with_cloud"])

    def test_scan_reports_ota_weakness_on_target_and_matching_test(self):
        target_id = "private-vehicle-node-0"
        snapshots = iter(
            [
                self.make_snapshot(False, {"message_authentication"}),
                self.make_snapshot(True, {"message_authentication"}),
            ]
        )

        def network_request(action, **parameters):
            if action == "vehicle_service_state":
                return {"service_state": "in_service"}
            if action in {"scan_activity_phase", "network_diagnostics"}:
                return {"status": "ok", "component_count": 4}
            if action == "snapshot":
                return next(snapshots)
            if action == "authorized_attack_test":
                return {
                    "status": "completed",
                    "event_count": 1,
                    "attack_frame_count": 1,
                    "affected_node_count": 1,
                }
            raise AssertionError(f"unexpected simulator action: {action}")

        result = run_scan(
            network_request,
            "spoofing",
            "medium",
            MODEL_STATUS,
            duration_seconds=1,
            target_node_ids=[target_id],
        )

        before_findings = result["before_attack"]["ota_weakness_findings"]
        after_findings = result["after_attack"]["ota_weakness_findings"]
        self.assertEqual([finding["weakness_id"] for finding in after_findings], ["W4"])
        self.assertEqual(after_findings[0]["finding_id"], "NET-AUTH-001")
        self.assertEqual(after_findings[0]["affected_target_count"], 1)
        self.assertEqual(after_findings[0]["test_coverage"], "covered")
        self.assertEqual(after_findings[0]["relevant_test_ids"], ["T2", "T3"])
        self.assertEqual(result["after_attack"]["ota_weakness_count"], 1)
        self.assertEqual(
            result["after_attack"]["ota_tested_weakness_count"], 1
        )
        self.assertEqual(result["risk_level"], "high")
        self.assertEqual(before_findings[0]["test_coverage"], "not_covered")
        self.assertNotIn(target_id, repr(after_findings))

    def test_scan_is_rejected_before_diagnostics_when_vehicle_is_not_in_service(self):
        calls = []

        def network_request(action, **parameters):
            calls.append(action)
            return {"service_state": "out_of_service"}

        with self.assertRaisesRegex(PermissionError, "must be in service"):
            run_scan(
                network_request,
                "flooding",
                "medium",
                {},
                duration_seconds=1,
            )
        self.assertEqual(calls, ["vehicle_service_state"])

    def test_post_diagnostics_still_run_when_simulator_attack_action_fails(self):
        calls = []

        def network_request(action, **parameters):
            calls.append(action)
            if action == "vehicle_service_state":
                return {"service_state": "in_service"}
            if action == "scan_activity_phase":
                return {"status": "ok", "scan_phase": parameters["phase"]}
            if action == "snapshot":
                return self.make_snapshot(after_attack=len(calls) > 3)
            if action == "network_diagnostics":
                return {
                    "component_count": 4,
                    "successful_count": 4,
                    "failed_count": 0,
                    "active_dtc_count": 0,
                }
            if action == "authorized_attack_test":
                raise RuntimeError("simulated test unavailable")
            raise AssertionError(f"unexpected simulator action: {action}")

        result = run_scan(
            network_request,
            "flooding",
            "medium",
            {},
            duration_seconds=1,
        )

        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["attack_summary"]["status"], "failed")
        self.assertEqual(
            calls[-4:],
            [
                "scan_activity_phase",
                "snapshot",
                "network_diagnostics",
                "scan_activity_phase",
            ],
        )
        self.assertIn("RuntimeError", result["summary"])

    def test_attack_duration_is_bounded_and_rejects_boolean(self):
        def network_request(action, **parameters):
            return {"service_state": "in_service"}

        for duration in (0, 61, True):
            with self.subTest(duration=duration):
                with self.assertRaises(ValueError):
                    run_scan(
                        network_request,
                        "flooding",
                        "medium",
                        {},
                        duration_seconds=duration,
                    )


if __name__ == "__main__":
    unittest.main()
