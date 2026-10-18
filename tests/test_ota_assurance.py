import hashlib
import hmac
import json
import pathlib
import sys
import unittest


CENTRAL_DIR = pathlib.Path(__file__).resolve().parents[1] / "vehicle-central-compute"
sys.path.insert(0, str(CENTRAL_DIR))

from scanner.assurance import build_ota_assurance, make_oem_baseline


def package_for(profile):
    image = bytes.fromhex("01020304")
    manifest = {
        "ecu_id": "ecu-adas-radar",
        "version": "SIM-2.0.0",
        "image_size": len(image),
        "sha256": hashlib.sha256(image).hexdigest(),
        "signature": "",
        "software_profile": profile,
    }
    signed_data = {
        "ecu_id": manifest["ecu_id"],
        "version": manifest["version"],
        "image_size": manifest["image_size"],
        "sha256": manifest["sha256"],
        "software_profile": profile,
    }
    manifest["signature"] = hmac.new(
        b"firmware-signature:ecu-adas-radar",
        json.dumps(
            signed_data, sort_keys=True, separators=(",", ":")
        ).encode(),
        hashlib.sha256,
    ).hexdigest()
    return {
        "target_ecu_id": "ecu-adas-radar",
        "image_hex": image.hex(),
        "manifest": manifest,
    }


class OtaAssuranceTests(unittest.TestCase):
    def test_secure_package_passes_signed_baseline(self):
        profile = {
            control: True
            for control in (
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
        }
        package = package_for(profile)
        baseline = make_oem_baseline(
            "ecu-adas-radar",
            "SIM-2.0.0",
            package["manifest"]["sha256"],
        )

        result = build_ota_assurance(package, baseline)

        self.assertEqual(result["status"], "pass")
        self.assertEqual(result["baseline_status"], "verified")
        self.assertEqual(result["firmware_hash"]["status"], "pass")
        self.assertEqual(result["finding_count"], 0)

    def test_attack_prone_profile_reports_downgrade_finding(self):
        profile = {control: True for control in ("anti_downgrade", "firmware_signature_required")}
        profile["anti_downgrade"] = False
        package = package_for(profile)
        baseline = make_oem_baseline(
            "ecu-adas-radar",
            "SIM-2.0.0",
            package["manifest"]["sha256"],
        )

        result = build_ota_assurance(package, baseline)

        self.assertEqual(result["status"], "fail")
        self.assertIn(
            "OTA-DOWNGRADE-001",
            {finding["finding_id"] for finding in result["findings"]},
        )

    def test_invalid_baseline_is_a_critical_finding(self):
        package = package_for({"anti_downgrade": True})
        baseline = make_oem_baseline("ecu-adas-radar", "SIM-2.0.0")
        baseline["signature"] = "tampered"

        result = build_ota_assurance(package, baseline)

        self.assertEqual(result["baseline_status"], "invalid_signature")
        self.assertEqual(result["highest_severity"], "critical")


if __name__ == "__main__":
    unittest.main()
