"""Safe, explainable OTA assurance checks for the simulator."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from typing import Any, Dict, Iterable


SECURITY_CONTROLS = (
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

CONTROL_FINDINGS = {
    "security_access_required": (
        "OTA-SECURITY-ACCESS",
        "high",
        "Security access is not required for protected diagnostics.",
    ),
    "message_authentication": (
        "NET-AUTH-001",
        "high",
        "Message authentication is disabled.",
    ),
    "replay_protection": (
        "NET-REPLAY-001",
        "high",
        "Replay protection is disabled.",
    ),
    "freshness_protection": (
        "NET-FRESHNESS-001",
        "high",
        "Freshness protection is disabled.",
    ),
    "rate_limiting": (
        "NET-RATE-001",
        "medium",
        "Rate limiting is disabled.",
    ),
    "timing_validation": (
        "NET-TIMING-001",
        "medium",
        "Timing validation is disabled.",
    ),
    "range_validation": (
        "NET-RANGE-001",
        "high",
        "Signal range validation is disabled.",
    ),
    "message_id_validation": (
        "NET-ID-001",
        "high",
        "Message identifier validation is disabled.",
    ),
    "diagnostic_access_control": (
        "OTA-DIAGNOSTIC-001",
        "high",
        "Diagnostic access control is disabled.",
    ),
    "zonal_segmentation": (
        "NET-ZONE-001",
        "high",
        "Zonal segmentation is disabled.",
    ),
    "firmware_signature_required": (
        "OTA-SIGNATURE-001",
        "critical",
        "Firmware signature enforcement is disabled.",
    ),
    "anti_downgrade": (
        "OTA-DOWNGRADE-001",
        "high",
        "Anti-downgrade protection is disabled.",
    ),
    "ids_logging": (
        "OTA-AUDIT-001",
        "medium",
        "Security event logging is disabled.",
    ),
}

SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}


def _baseline_key() -> bytes:
    value = os.getenv(
        "OEM_BASELINE_SIGNING_KEY",
        "simulator-only-oem-baseline-key-change-me",
    )
    return value.encode("utf-8")


def _canonical(value: Dict[str, Any]) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def sign_baseline(baseline: Dict[str, Any]) -> str:
    unsigned = {key: value for key, value in baseline.items() if key != "signature"}
    return hmac.new(_baseline_key(), _canonical(unsigned), hashlib.sha256).hexdigest()


def make_oem_baseline(
    target_node_id: str,
    approved_version: str,
    approved_sha256: str | None = None,
    required_controls: Iterable[str] = SECURITY_CONTROLS,
) -> Dict[str, Any]:
    baseline = {
        "baseline_id": f"oem:{target_node_id}:{approved_version}",
        "target_node_id": target_node_id,
        "approved_version": approved_version,
        "approved_sha256": approved_sha256,
        "required_controls": {
            control: True for control in required_controls if control in SECURITY_CONTROLS
        },
        "baseline_type": "simulator_oem_release_policy",
    }
    baseline["signature"] = sign_baseline(baseline)
    return baseline


def verify_baseline(baseline: Dict[str, Any]) -> bool:
    signature = baseline.get("signature")
    return isinstance(signature, str) and hmac.compare_digest(
        signature, sign_baseline(baseline)
    )


def _version_key(version: Any) -> tuple[int, ...] | None:
    if not isinstance(version, str):
        return None
    pieces = version.removeprefix("SIM-").split(".")
    if not pieces or any(not piece.isdigit() for piece in pieces):
        return None
    return tuple(int(piece) for piece in pieces)


def build_ota_assurance(
    package: Dict[str, Any],
    baseline: Dict[str, Any] | None = None,
    previous_firmware: Dict[str, Any] | None = None,
) -> Dict[str, Any]:
    target = package.get("target_ecu_id")
    manifest = package.get("manifest")
    image_hex = package.get("image_hex")
    if not isinstance(target, str) or not isinstance(manifest, dict):
        raise ValueError("OTA package is missing a target or manifest")

    profile = manifest.get("software_profile")
    profile = profile if isinstance(profile, dict) else {}
    findings = []
    for control in SECURITY_CONTROLS:
        if profile.get(control) is False:
            finding_id, severity, title = CONTROL_FINDINGS[control]
            findings.append(
                {
                    "finding_id": finding_id,
                    "category": "ota_security_profile",
                    "severity": severity,
                    "confidence": 0.99,
                    "affected_node_ids": [target],
                    "title": title,
                    "evidence": [f"manifest.software_profile.{control}=false"],
                    "recommendation": f"Require {control}=true in the approved OEM baseline.",
                }
            )

    calculated_sha256 = None
    if isinstance(image_hex, str):
        try:
            calculated_sha256 = hashlib.sha256(bytes.fromhex(image_hex)).hexdigest()
        except ValueError:
            findings.append(
                {
                    "finding_id": "OTA-PACKAGE-001",
                    "category": "package_integrity",
                    "severity": "critical",
                    "confidence": 1.0,
                    "affected_node_ids": [target],
                    "title": "Firmware image encoding is invalid.",
                    "evidence": ["image_hex could not be decoded"],
                    "recommendation": "Reject the package and regenerate the firmware image.",
                }
            )
    declared_sha256 = manifest.get("sha256")
    if calculated_sha256 and isinstance(declared_sha256, str):
        if not hmac.compare_digest(calculated_sha256, declared_sha256.lower()):
            findings.append(
                {
                    "finding_id": "OTA-INTEGRITY-001",
                    "category": "package_integrity",
                    "severity": "critical",
                    "confidence": 1.0,
                    "affected_node_ids": [target],
                    "title": "Firmware image hash does not match its manifest.",
                    "evidence": [f"calculated={calculated_sha256}", f"declared={declared_sha256}"],
                    "recommendation": "Reject the package and verify the release artifact.",
                }
            )

    signed_data = {
        "ecu_id": target,
        "version": manifest.get("version"),
        "image_size": manifest.get("image_size"),
        "sha256": str(declared_sha256).lower() if declared_sha256 else declared_sha256,
    }
    if "software_profile" in manifest:
        signed_data["software_profile"] = manifest["software_profile"]
    expected_signature = hmac.new(
        f"firmware-signature:{target}".encode("utf-8"),
        _canonical(signed_data),
        hashlib.sha256,
    ).hexdigest()
    signature = manifest.get("signature")
    signature_status = (
        "pass"
        if isinstance(signature, str)
        and hmac.compare_digest(signature.lower(), expected_signature)
        else "fail"
        if isinstance(signature, str)
        else "not_available"
    )
    if signature_status == "fail":
        findings.append(
            {
                "finding_id": "OTA-SIGNATURE-002",
                "category": "cryptographic_posture",
                "severity": "critical",
                "confidence": 1.0,
                "affected_node_ids": [target],
                "title": "Firmware signature does not match the simulator release key.",
                "evidence": ["manifest signature verification failed"],
                "recommendation": "Reject the package and verify its OEM signing key.",
            }
        )

    baseline_status = "not_provided"
    if baseline is not None:
        if not verify_baseline(baseline):
            baseline_status = "invalid_signature"
            findings.append(
                {
                    "finding_id": "BASELINE-SIGNATURE-001",
                    "category": "oem_baseline",
                    "severity": "critical",
                    "confidence": 1.0,
                    "affected_node_ids": [target],
                    "title": "OEM security baseline signature is invalid.",
                    "evidence": ["baseline signature verification failed"],
                    "recommendation": "Use a trusted OEM-signed baseline.",
                }
            )
        else:
            baseline_status = "verified"
            if baseline.get("target_node_id") != target:
                findings.append(
                    {
                        "finding_id": "BASELINE-TARGET-001",
                        "category": "oem_baseline",
                        "severity": "critical",
                        "confidence": 1.0,
                        "affected_node_ids": [target],
                        "title": "Package target does not match the OEM baseline.",
                        "evidence": [f"baseline target={baseline.get('target_node_id')}"],
                        "recommendation": "Use the baseline issued for this node.",
                    }
                )
            if baseline.get("approved_version") != manifest.get("version"):
                findings.append(
                    {
                        "finding_id": "BASELINE-VERSION-001",
                        "category": "oem_baseline",
                        "severity": "high",
                        "confidence": 1.0,
                        "affected_node_ids": [target],
                        "title": "Package version is not the approved OEM release.",
                        "evidence": [
                            f"approved={baseline.get('approved_version')}",
                            f"package={manifest.get('version')}",
                        ],
                        "recommendation": "Deploy only the approved release artifact.",
                    }
                )
            for control, required in baseline.get("required_controls", {}).items():
                if required and profile.get(control) is not True:
                    finding_id, severity, title = CONTROL_FINDINGS.get(
                        control,
                        ("BASELINE-CONTROL-001", "high", "Required security control is disabled."),
                    )
                    findings.append(
                        {
                            "finding_id": finding_id,
                            "category": "oem_baseline",
                            "severity": severity,
                            "confidence": 1.0,
                            "affected_node_ids": [target],
                            "title": title,
                            "evidence": [f"required control {control}=true"],
                            "recommendation": f"Restore {control} before fleet deployment.",
                        }
                    )

    previous_version = (
        previous_firmware.get("version") if isinstance(previous_firmware, dict) else None
    )
    current_version = manifest.get("version")
    version_comparison = {
        "previous_version": previous_version,
        "installed_version": current_version,
        "version_changed": previous_version != current_version,
        "direction": "unknown",
    }
    old_key = _version_key(previous_version)
    new_key = _version_key(current_version)
    if old_key is not None and new_key is not None:
        version_comparison["direction"] = (
            "upgrade" if new_key > old_key else "downgrade" if new_key < old_key else "same"
        )

    highest = max(
        (SEVERITY_RANK[item["severity"]] for item in findings),
        default=-1,
    )
    status = "pass" if not findings else "fail" if highest >= SEVERITY_RANK["high"] else "warn"
    return {
        "status": status,
        "assurance_scope": "simulator_ota_update",
        "target_node_id": target,
        "baseline_status": baseline_status,
        "firmware_hash": {
            "declared_sha256": declared_sha256,
            "calculated_sha256": calculated_sha256,
            "status": (
                "pass"
                if declared_sha256 and calculated_sha256 == str(declared_sha256).lower()
                else "not_available"
            ),
        },
        "cryptographic_posture": {
            "signature_required": profile.get("firmware_signature_required"),
            "signature_metadata_present": isinstance(manifest.get("signature"), str),
            "signature_status": signature_status,
            "hash_algorithm": "SHA-256",
            "simulator_signature_scheme": "HMAC-SHA256",
            "production_hardware_validation": False,
        },
        "version_comparison": version_comparison,
        "security_profile": {
            control: profile.get(control) for control in SECURITY_CONTROLS
        },
        "findings": findings,
        "finding_count": len(findings),
        "highest_severity": (
            next(
                severity
                for severity, rank in sorted(
                    SEVERITY_RANK.items(), key=lambda item: item[1], reverse=True
                )
                if rank == highest
            )
            if findings
            else "none"
        ),
        "cve_summary": {
            "status": "not_provided",
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
        },
        "sbom_summary": {"status": "not_provided", "component_count": 0},
    }
