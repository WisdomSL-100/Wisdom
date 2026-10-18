import importlib.util
import os
import pathlib
import tempfile
import unittest
from unittest.mock import Mock, patch
from uuid import uuid4


CLOUD_APP_PATH = pathlib.Path(__file__).resolve().parents[1] / "cloud-app"


def load_cve_store():
    module_name = f"cve_store_test_{uuid4().hex}"
    spec = importlib.util.spec_from_file_location(module_name, CLOUD_APP_PATH / "cve_store.py")
    if spec is None or spec.loader is None:
        raise RuntimeError("Unable to load CVE store")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class CveStoreTests(unittest.TestCase):
    def test_import_search_and_component_match(self):
        store = load_cve_store()
        with tempfile.TemporaryDirectory() as directory, patch.dict(
            os.environ, {"DATA_DIR": directory}
        ):
            imported = store.import_records(
                [
                    {
                        "cve": {
                            "id": "CVE-2026-12345",
                            "descriptions": [{"lang": "en", "value": "Radar runtime issue"}],
                            "metrics": {
                                "cvssMetricV31": [
                                    {"cvssData": {"baseSeverity": "HIGH", "baseScore": 8.1}}
                                ]
                            },
                            "configurations": [{"product": "radar-runtime"}],
                        }
                    }
                ],
                "test",
            )
            self.assertEqual(imported, 1)
            self.assertEqual(store.list_cves("radar")[0]["cve_id"], "CVE-2026-12345")
            matches = store.match_components([{"name": "radar-runtime", "version": "1.0"}])
            self.assertEqual(matches[0]["cve"]["severity"], "high")

    @patch("requests.get")
    def test_nvd_sync_imports_bounded_response(self, get):
        store = load_cve_store()
        get.return_value = Mock(
            json=lambda: {"totalResults": 1, "vulnerabilities": [{"cve": {"id": "CVE-2026-1"}}]},
            raise_for_status=lambda: None,
        )
        with tempfile.TemporaryDirectory() as directory, patch.dict(
            os.environ, {"DATA_DIR": directory}
        ):
            result = store.sync_nvd("radar", 50)
        self.assertEqual(result["imported"], 1)
        self.assertEqual(get.call_args.kwargs["params"]["resultsPerPage"], 50)


if __name__ == "__main__":
    unittest.main()
