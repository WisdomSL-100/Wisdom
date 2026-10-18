import importlib.util
from io import BytesIO
import pathlib
import unittest
from unittest.mock import Mock, patch
from xml.etree import ElementTree
from zipfile import ZipFile
from uuid import uuid4


FRONTEND_APP_PATH = (
    pathlib.Path(__file__).resolve().parents[1] / "frontend" / "app.py"
)


def load_frontend_app():
    module_name = f"frontend_dashboard_test_{uuid4().hex}"
    spec = importlib.util.spec_from_file_location(module_name, FRONTEND_APP_PATH)
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load the frontend application")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class FrontendDashboardTests(unittest.TestCase):
    def setUp(self):
        self.frontend = load_frontend_app()
        self.client = self.frontend.app.test_client()

    def test_dashboard_has_controls_logs_and_decision_tabs(self):
        response = self.client.get("/")
        html = response.get_data(as_text=True)

        self.assertEqual(response.status_code, 200)
        self.assertIn('id="page-controls"', html)
        self.assertIn('id="page-logs"', html)
        self.assertIn('id="page-analytics"', html)
        self.assertIn('id="tab-controls"', html)
        self.assertIn('id="tab-logs"', html)
        self.assertIn('id="tab-analytics"', html)
        self.assertLess(html.index('<nav class="nav"'), html.index('id="scan-phase-banner"'))
        self.assertIn("position: sticky; top: 0", html)
        self.assertIn("AegisDrive Cyber Assurance", html)
        self.assertIn('id="outcome-decision"', html)
        self.assertIn('id="outcome-risk"', html)
        self.assertIn('id="outcome-scope"', html)
        self.assertIn('id="outcome-action"', html)
        self.assertIn("Assessment setup", html)
        for label in (
            "T1 - Replay test",
            "T2 - Spoofing / unauthorized-message test",
            "T3 - Tampering / integrity test",
            "T4 - Flooding / DoS resilience test",
            "T5 - Unauthorized diagnostic / service-access test",
            "T6 - Cross-zone segmentation test",
            "T7 - Invalid firmware / secure-flash test",
            "T8 - IDS and auditability regression test",
            "Replay test",
            "Spoofing / unauthorized-message test",
            "Tampering / integrity test",
            "Flooding / DoS resilience test",
            "Unauthorized diagnostic / service-access test",
            "Cross-zone segmentation test",
            "Invalid firmware / secure-flash test",
            "IDS and auditability regression test",
        ):
            self.assertIn(label, html)
        self.assertNotIn("Authentication / repudiation test", html)
        self.assertNotIn("'dos': 'Flooding / DoS resilience test", html)
        self.assertIn("Object.keys(attackLabels).filter(value =>", html)
        self.assertIn("Your scan report", html)
        self.assertIn('id="download-report-md"', html)
        self.assertIn('id="download-report-xlsx"', html)
        self.assertIn("Download Markdown", html)
        self.assertIn("Download Excel (.xlsx)", html)
        self.assertIn("function scanReportRows(scan)", html)
        self.assertIn("function downloadScanReport(format)", html)
        self.assertIn("FINAL REPORT GENERATION", html)
        self.assertIn("<span>Generate report</span>", html)
        self.assertNotIn('id="assessment-workflow"', html)
        self.assertNotIn("Assessment flow", html)
        self.assertIn("Before the attack", html)
        self.assertIn("After the attack", html)
        self.assertIn("What happened", html)
        self.assertIn("Problem found", html)
        self.assertIn("What to fix", html)
        self.assertNotIn("Fleet and release analytics", html)
        self.assertNotIn("Audience-specific report", html)
        self.assertNotIn("Recent scan history", html)
        self.assertNotIn("Before / during / after analysis", html)
        self.assertIn("HPC nodes", html)
        self.assertIn("ZCU nodes", html)
        self.assertIn("ECU nodes", html)
        self.assertIn("scan target selected", html)
        self.assertIn("const targetPanel = {hpc: 'hpc', zone_controller: 'zcu', ecu: 'ecu'}[node.role]", html)
        self.assertIn("ota_weakness_findings", html)
        self.assertIn("Installed OTA security posture", html)
        self.assertIn("Weaknesses / failures found", html)
        self.assertIn("finding.weakness_id} · ${finding.title}", html)
        self.assertIn("Security event:", html)
        self.assertIn("Message rate exceeded the configured flood threshold", html)
        self.assertIn("block.classList.add('problem-found')", html)
        self.assertNotIn("covered by this test", html)
        self.assertIn('class="controls-layout"', html)
        self.assertIn('class="node-selection-grid"', html)
        self.assertIn('class="service-stack"', html)
        self.assertIn('class="assessment-options"', html)
        self.assertIn('class="assessment-column"', html)
        self.assertIn('class="panel weakness-tracker"', html)
        self.assertIn("Weakness &amp; test tracker", html)
        self.assertIn("Downgrade protection failure", html)
        self.assertIn("Test key", html)
        self.assertIn("align-content: start; align-items: start; gap: 2px 14px", html)
        self.assertIn(".assessment-actions { display: grid;", html)
        self.assertIn("@media (max-width: 900px) { .controls-layout { grid-template-columns: 1fr; }", html)
        self.assertLess(html.index("<h3>OTA</h3>"), html.index("<h3>SOME/IP</h3>"))
        self.assertLess(html.index("<h3>SOME/IP</h3>"), html.index("<h3>SOVD</h3>"))
        self.assertIn("<summary>How to use</summary>", html)
        self.assertIn("HPC scan target", html)
        self.assertIn("ZCU scan target", html)
        self.assertIn("ECU scan target", html)
        self.assertNotIn('id="targets-hpc" multiple', html)
        self.assertIn("Socket selection", html)
        self.assertIn("Live packet console", html)
        self.assertIn("<h3>SOVD</h3>", html)
        self.assertIn("<h3>OTA</h3>", html)
        self.assertIn("<h3>SOME/IP</h3>", html)
        self.assertIn('<select id="someip-signal"', html)
        self.assertIn("loadSomeipSignalCatalog", html)
        self.assertNotIn('<input id="someip-signal"', html)
        self.assertIn('id="sovd-component"', html)
        self.assertIn('id="ota-package-file"', html)
        self.assertIn('id="ota-flash-button"', html)
        self.assertIn('id="someip-target"', html)
        self.assertIn('id="live-log"', html)
        self.assertIn("ZCU local ECU CAN/CAN-FD socket", html)
        self.assertIn("HPC local safety ECU CAN/CAN-FD socket", html)
        self.assertIn("HPC-ZCU authenticated TCP socket", html)
        self.assertIn("Cloud-HPC authenticated TCP socket", html)
        self.assertEqual(html.count("All simulator sockets"), 1)
        for obsolete in ("'hpc-ingress':", "'can-gateway':", "'doip-gateway':"):
            self.assertNotIn(obsolete, html)
        self.assertIn("CAN ID", html)
        self.assertIn("message_length_bytes", html)
        self.assertIn('id="stop-scan-button"', html)
        self.assertIn('id="log-socket-filter"', html)
        self.assertIn('id="log-phase-filter"', html)
        self.assertIn('id="log-protocol-filter"', html)
        self.assertIn('id="phase-summary"', html)
        self.assertIn('id="live-attention"', html)
        self.assertIn('id="scan-phase-banner"', html)
        self.assertIn('data-running="false" role="status" aria-live="polite"', html)
        self.assertIn('id="phase-progress"', html)
        self.assertIn("background: linear-gradient(90deg, #16a34a 0 var(--progress), #fff", html)
        self.assertIn("background: linear-gradient(90deg, #16a34a 0 var(--progress), #fff var(--progress) 100%) center 9px / 75% 2px", html)
        self.assertIn(".scan-phase-banner[data-running=\"true\"] { animation: phase-alert", html)
        self.assertIn(".phase-progress-step[data-state=\"active\"] input { border-color: #f97316;", html)
        self.assertIn("@media (prefers-reduced-motion: reduce)", html)
        self.assertIn("const phaseIsRecent = Number.isFinite(phaseUpdatedAt)", html)
        self.assertIn("&& Date.now() / 1000 - phaseUpdatedAt <= 120;", html)
        self.assertIn("|| data.attack_active === true", html)
        self.assertIn("const displayPhase = isRunning ? phase : 'idle';", html)
        self.assertIn("renderPhaseProgress(displayPhase, data, isRunning);", html)
        self.assertIn("renderScanPhaseStatus({\n          scan_phase: runBaselineChecks ? 'before_attack' : 'attack'\n        });", html)
        self.assertIn("if (isRunning) {", html)
        self.assertIn("· skipped", html)
        self.assertIn("Baseline checks", html)
        self.assertNotIn("Pre-attack probes", html)
        self.assertIn("Authorized attack", html)
        self.assertIn("Post-attack checks", html)
        self.assertIn('id="run-baseline-checks"', html)
        self.assertIn("Run baseline checks before the attack", html)
        self.assertIn("latestScan = null;\n      renderAnalytics(null);", html)
        self.assertNotIn("overview.last_scan", html)
        self.assertNotIn("workflow-strip", html)
        self.assertIn('id="log-filter-message"', html)
        self.assertIn('id="log-filter-route"', html)
        self.assertIn("setInterval(loadActivity, 750)", html)
        self.assertIn("Authorized attack</strong> simulator-only attack frame or request", html)
        self.assertIn("PRE-ATTACK PROBE", html)
        self.assertIn("AUTHORIZED ATTACK", html)
        self.assertIn("POST-ATTACK CHECK", html)
        self.assertIn("Timed attack scenarios send bounded CAN/CAN-FD frames, UDS requests, or invalid-firmware probes through the selected simulator socket handlers", html)
        self.assertNotIn('id="live-messages"', html)
        self.assertNotIn('id="live-events"', html)
        self.assertIn("conic-gradient", html)
        self.assertNotIn("background: #0b1020", html)

    def test_excel_report_endpoint_returns_a_valid_xlsx_workbook(self):
        response = self.client.post(
            "/api/reports/xlsx",
            json={
                "scan_id": "scan/123",
                "rows": [
                    {
                        "section": "Weakness finding",
                        "item": "W9 Firmware downgrade protection disabled",
                        "value": "high",
                        "details": "Control: anti_downgrade & secure-flash",
                    }
                ],
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.mimetype,
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        )
        self.assertIn("cybersecurity-assessment-scan_123.xlsx", response.headers["Content-Disposition"])
        with ZipFile(BytesIO(response.data)) as workbook:
            self.assertEqual(
                set(workbook.namelist()),
                {
                    "[Content_Types].xml",
                    "_rels/.rels",
                    "xl/workbook.xml",
                    "xl/_rels/workbook.xml.rels",
                    "xl/worksheets/sheet1.xml",
                },
            )
            self.assertIsNone(workbook.testzip())
            for name in workbook.namelist():
                if name.endswith(".xml") or name.endswith(".rels"):
                    ElementTree.fromstring(workbook.read(name))
            worksheet = workbook.read("xl/worksheets/sheet1.xml").decode("utf-8")
        self.assertIn("W9 Firmware downgrade protection disabled", worksheet)
        self.assertIn("anti_downgrade &amp; secure-flash", worksheet)

    def test_excel_report_endpoint_rejects_invalid_rows(self):
        response = self.client.post("/api/reports/xlsx", json={"rows": []})
        self.assertEqual(response.status_code, 400)

    @patch("requests.get")
    def test_live_activity_route_proxies_limit_to_cloud(self, get):
        cloud_response = Mock()
        cloud_response.status_code = 200
        cloud_response.json.return_value = {
            "observed_at": "now",
            "messages": [],
            "security_events": [],
        }
        get.return_value = cloud_response

        response = self.client.get("/api/network/activity?limit=25")

        self.assertEqual(response.status_code, 200)
        self.assertEqual(get.call_args.kwargs["params"], {"limit": 25})

    def test_live_activity_route_rejects_invalid_limit(self):
        for value in ("0", "201", "invalid"):
            with self.subTest(value=value):
                response = self.client.get(f"/api/network/activity?limit={value}")
                self.assertEqual(response.status_code, 400)

    @patch("requests.post")
    def test_scan_route_allows_time_for_all_assessment_phases(self, post):
        cloud_response = Mock()
        cloud_response.status_code = 200
        cloud_response.json.return_value = {
            "status": "accepted",
            "scan": {"scan_id": "scan-test"},
        }
        post.return_value = cloud_response
        duration_seconds = 10

        response = self.client.post(
            "/api/scan/run",
            json={
                "attack_type": "flooding",
                "severity": "low",
                "duration_seconds": duration_seconds,
            },
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            post.call_args.kwargs["timeout"],
            duration_seconds + self.frontend.SCAN_TIMEOUT_MARGIN_SECONDS,
        )

    @patch("requests.post")
    def test_ota_flash_route_validates_and_proxies_package(self, post):
        ota_response = Mock()
        ota_response.status_code = 200
        ota_response.json.return_value = {
            "status": "completed",
            "node_behavior_change": {
                "target_node_id": "ecu-powertrain",
                "scope": "target_node_only",
            },
        }
        post.return_value = ota_response
        package = {
            "source_hpc_id": "hpc-vehicle",
            "target_ecu_id": "ecu-powertrain",
            "image_hex": "abcd",
            "manifest": {
                "ecu_id": "ecu-powertrain",
                "image_size": 2,
            },
        }

        response = self.client.post("/api/ota/flash", json=package)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["status"], "completed")
        self.assertTrue(post.call_args.args[0].endswith("/api/ota/flash"))
        self.assertEqual(post.call_args.kwargs["json"], package)
        self.assertEqual(post.call_args.kwargs["timeout"], 195)

    @patch("requests.post")
    def test_ota_flash_route_rejects_invalid_or_oversized_package(self, post):
        invalid = self.client.post(
            "/api/ota/flash",
            json={
                "target_ecu_id": "ecu-powertrain",
                "image_hex": "xz",
                "manifest": {
                    "ecu_id": "ecu-powertrain",
                    "image_size": 1,
                },
            },
        )
        oversized = self.client.post(
            "/api/ota/flash",
            data=b" " * (3_145_729),
            content_type="application/json",
        )

        self.assertEqual(invalid.status_code, 400)
        self.assertEqual(oversized.status_code, 413)
        post.assert_not_called()

    def test_ota_package_catalog_exposes_generated_fault_sets(self):
        response = self.client.get("/api/ota/packages")

        self.assertEqual(response.status_code, 200)
        packages = response.get_json()["packages"]
        self.assertGreaterEqual(len(packages), 10)
        controls = {item["control"] for item in packages}
        self.assertIn("anti_downgrade", controls)
        self.assertIn("baseline_secure", controls)
        package_names = [item["package_name"] for item in packages]
        self.assertTrue(any(name.startswith("W1 - ") for name in package_names))
        self.assertTrue(any(name.startswith("W10 - ") for name in package_names))
        self.assertTrue(
            any(name.startswith("BASELINE - ") for name in package_names)
        )

    @patch("requests.post")
    def test_service_request_routes_proxy_sovd_and_someip(self, post):
        sovd_response = Mock()
        sovd_response.status_code = 200
        sovd_response.json.return_value = {
            "status": "completed",
            "component_id": "ecu-body-front",
        }
        someip_response = Mock()
        someip_response.status_code = 200
        someip_response.json.return_value = {
            "found": True,
            "signal_name": "window_position_pct",
            "value": 40,
        }
        post.side_effect = [sovd_response, someip_response]

        sovd = self.client.post(
            "/api/diagnostics/sovd",
            json={
                "component_id": "ecu-body-front",
                "operation": "readDataByIdentifier",
                "data_id": "F1B0",
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
        self.assertEqual(signal.status_code, 200)
        self.assertEqual(signal.get_json()["value"], 40)
        self.assertTrue(
            post.call_args_list[0].args[0].endswith("/api/diagnostics/sovd")
        )
        self.assertTrue(post.call_args_list[1].args[0].endswith("/api/signals/read"))

    @patch("requests.get")
    def test_someip_signal_catalog_route_proxies_selected_target(self, get):
        catalog_response = Mock()
        catalog_response.status_code = 200
        catalog_response.json.return_value = {
            "status": "ok",
            "target_node_id": "hpc-vehicle",
            "signals": ["vehicle_speed_kph"],
        }
        get.return_value = catalog_response

        response = self.client.get(
            "/api/signals/catalog?target_node_id=hpc-vehicle"
        )

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["signals"], ["vehicle_speed_kph"])
        self.assertTrue(
            get.call_args.args[0].endswith("/api/signals/catalog")
        )
        self.assertEqual(
            get.call_args.kwargs["params"],
            {"target_node_id": "hpc-vehicle"},
        )

    @patch("requests.post")
    def test_stop_route_proxies_simulator_stop_request(self, post):
        stop_response = Mock()
        stop_response.status_code = 202
        stop_response.json.return_value = {
            "status": "stop_requested",
            "message": "Stop requested; post-attack diagnostics will still run.",
        }
        post.return_value = stop_response

        response = self.client.post("/api/scan/stop")

        self.assertEqual(response.status_code, 202)
        self.assertEqual(response.get_json()["status"], "stop_requested")
        self.assertTrue(post.call_args.args[0].endswith("/api/scan/stop"))


if __name__ == "__main__":
    unittest.main()
