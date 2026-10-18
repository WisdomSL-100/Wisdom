import importlib.util
import json
import pathlib
import unittest
from unittest.mock import Mock, patch
from uuid import uuid4


THREAT_EXPLAINER_PATH = (
    pathlib.Path(__file__).resolve().parents[1]
    / "cloud-app"
    / "threat_explainer.py"
)


def load_threat_explainer():
    module_name = f"threat_explainer_test_{uuid4().hex}"
    spec = importlib.util.spec_from_file_location(
        module_name, THREAT_EXPLAINER_PATH
    )
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load threat explainer module")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class ThreatExplainerTests(unittest.TestCase):
    def setUp(self):
        self.explainer = load_threat_explainer()

    def test_local_rag_returns_attack_references_and_limits(self):
        report = self.explainer.create_threat_report(
            {"attack_type": "flooding", "risk_level": "high"}
        )

        self.assertEqual(report["status"], "local_rag_only")
        self.assertEqual(report["provider"], "local_rag")
        self.assertTrue(any("CWE-400" in item for item in report["evidence_citations"]))
        self.assertTrue(any("does not query a live" in item for item in report["limitations"]))

    def test_minimized_evidence_excludes_direct_identifiers_and_raw_payloads(self):
        evidence = self.explainer.minimized_evidence(
            {
                "attack_type": "flooding",
                "vehicle_id": "VIN-SECRET",
                "node_id": "private-ecu-id",
                "raw_frames": [{"payload": "private-data"}],
                "before_attack": {
                    "network_node_count": 12,
                    "security_event_count": 0,
                    "node_ids": ["private-ecu-id"],
                    "raw_log": "private-data",
                },
                "target_summary": {
                    "target_count": 1,
                    "target_node_ids": ["private-ecu-id"],
                    "role_counts": {"ecu": 1},
                },
                "during_attack": {
                    "event_count": 1,
                    "affected_node_ids": ["private-ecu-id"],
                },
            }
        )

        serialized = json.dumps(evidence)
        self.assertIn("network_node_count", serialized)
        self.assertNotIn("VIN-SECRET", serialized)
        self.assertNotIn("private-ecu-id", serialized)
        self.assertNotIn("private-data", serialized)

    def test_report_names_specific_ota_weakness_and_aggregate_diagnostic_failure(self):
        finding = {
            "weakness_id": "W9",
            "finding_id": "OTA-ANTI-DOWNGRADE-001",
            "severity": "high",
            "title": "Anti-downgrade protection disabled",
            "affected_target_count": 1,
            "affected_node_ids": ["private-ecu-id"],
            "affected_controls": ["ota_anti_downgrade"],
            "relevant_test_ids": ["T7"],
            "test_coverage": "covered",
        }
        scan = {
            "attack_type": "invalid_firmware",
            "risk_level": "high",
            "before_attack": {
                "uds_failed_count": 0,
                "security_event_categories": {},
            },
            "after_attack": {
                "uds_failed_count": 1,
                "security_event_categories": {"secure_flash_failure": 1},
                "ota_weakness_findings": [finding],
            },
        }

        report = self.explainer.create_threat_report(scan)
        evidence = self.explainer.minimized_evidence(scan)
        serialized_evidence = json.dumps(evidence)

        self.assertIn("W9 Anti-downgrade protection disabled", report["technical_explanation"])
        self.assertIn("ota_anti_downgrade", report["technical_explanation"])
        self.assertIn("T7", report["technical_explanation"])
        self.assertIn("UDS diagnostic failures increased by 1", report["technical_explanation"])
        self.assertIn("W9", serialized_evidence)
        self.assertNotIn("private-ecu-id", serialized_evidence)
        self.assertNotIn("test_coverage", serialized_evidence)
        self.assertNotIn("ota_tested_weakness_count", serialized_evidence)

    @patch.dict("os.environ", {"GEMINI_API_KEY": "test-key", "GEMINI_MODEL": "test-model"})
    @patch("requests.post")
    def test_gemini_receives_only_minimized_evidence(self, post):
        response = Mock()
        response.json.return_value = {
            "candidates": [
                {
                    "content": {
                        "parts": [
                            {
                                "text": json.dumps(
                                    {
                                        "executive_summary": "Simulator finding.",
                                        "technical_explanation": "Measured deviation.",
                                        "recommendations": ["Validate the control."],
                                    }
                                )
                            }
                        ]
                    }
                }
            ]
        }
        post.return_value = response
        scan = {
            "attack_type": "flooding",
            "risk_level": "medium",
            "node_id": "private-ecu-id",
            "raw_frames": ["private-data"],
            "after_attack": {
                "network_node_count": 12,
                "security_event_count": 2,
                "raw_log": "private-data",
            },
        }

        report = self.explainer.create_threat_report(scan)

        self.assertEqual(report["provider"], "gemini_with_local_rag")
        self.assertEqual(report["model"], "test-model")
        prompt = json.dumps(post.call_args.kwargs["json"])
        self.assertNotIn("private-ecu-id", prompt)
        self.assertNotIn("private-data", prompt)
        self.assertIn("network_node_count", prompt)

    @patch.dict("os.environ", {"GEMINI_API_KEY": "test-key"})
    @patch("requests.post")
    def test_gemini_failure_returns_local_report(self, post):
        import requests

        post.side_effect = requests.Timeout("request timed out")

        report = self.explainer.create_threat_report(
            {"attack_type": "replay_attack", "risk_level": "medium"}
        )

        self.assertEqual(report["status"], "fallback_gemini_unavailable")
        self.assertEqual(report["provider"], "local_rag")
        self.assertTrue(any("Gemini was configured" in item for item in report["limitations"]))


if __name__ == "__main__":
    unittest.main()
