from typing import Any, Callable, Dict

from scanner.assurance import build_ota_assurance, make_oem_baseline
from behavior_analysis.analyzer import summarize_network_phase
from behavior_analysis.models import BehaviorModelSuite


def flash_firmware(
    network_request: Callable[..., Dict[str, Any]], package: Dict[str, Any]
) -> Dict[str, Any]:
    target_node_id = package.get("target_ecu_id")
    model_suite = BehaviorModelSuite()
    before_analysis = None
    analysis_error = None
    if isinstance(target_node_id, str):
        try:
            before_snapshot = network_request("snapshot")
            before_analysis = summarize_network_phase(
                before_snapshot, {}, model_suite, include_node_scores=True
            )
        except (OSError, RuntimeError, ValueError, TypeError, KeyError) as exc:
            analysis_error = str(exc)

    result = network_request("ota_flash", package=package)
    if result.get("status") != "completed" or not isinstance(target_node_id, str):
        return result

    if before_analysis is None:
        result["node_behavior_change"] = {
            "status": "unavailable",
            "target_node_id": target_node_id,
            "scope": "target_node_only",
            "reason": analysis_error or "Pre-update node snapshot is unavailable.",
        }
        return result

    try:
        after_snapshot = network_request("snapshot")
        after_analysis = summarize_network_phase(
            after_snapshot, {}, model_suite, include_node_scores=True
        )
    except (OSError, RuntimeError, ValueError, TypeError, KeyError) as exc:
        result["node_behavior_change"] = {
            "status": "unavailable",
            "target_node_id": target_node_id,
            "scope": "target_node_only",
            "reason": str(exc),
        }
        return result

    def find_node(items, node_id):
        return next(
            (
                item
                for item in items
                if isinstance(item, dict) and item.get("node_id") == node_id
            ),
            None,
        )

    before_diagnostic = find_node(
        before_snapshot.get("diagnostics", []), target_node_id
    )
    after_diagnostic = find_node(
        after_snapshot.get("diagnostics", []), target_node_id
    )
    before_firmware = (
        before_diagnostic.get("firmware", {})
        if isinstance(before_diagnostic, dict)
        else {}
    )
    after_firmware = (
        after_diagnostic.get("firmware", {})
        if isinstance(after_diagnostic, dict)
        else {}
    )
    before_profile = (
        before_firmware.get("software_profile", {})
        if isinstance(before_firmware, dict)
        else {}
    )
    after_profile = (
        after_firmware.get("software_profile", {})
        if isinstance(after_firmware, dict)
        else {}
    )
    before_profile = before_profile if isinstance(before_profile, dict) else {}
    after_profile = after_profile if isinstance(after_profile, dict) else {}
    manifest = package.get("manifest", {})
    baseline = make_oem_baseline(
        target_node_id,
        manifest.get("version", ""),
        manifest.get("sha256"),
    )
    assurance = build_ota_assurance(
        package,
        baseline=baseline,
        previous_firmware=before_firmware if isinstance(before_firmware, dict) else None,
    )
    sbom = package.get("sbom")
    cves = package.get("cves")
    if isinstance(sbom, dict):
        components = sbom.get("components")
        assurance["sbom_summary"] = {
            "status": "provided",
            "component_count": len(components) if isinstance(components, list) else 0,
        }
    if isinstance(cves, list):
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for cve in cves:
            if isinstance(cve, dict):
                severity = cve.get("severity")
                if severity in counts:
                    counts[severity] += 1
        assurance["cve_summary"] = {
            "status": "provided",
            **counts,
            "total": sum(counts.values()),
        }
    assurance["baseline"] = baseline
    result["ota_assurance"] = assurance
    before_node_score = find_node(
        before_analysis["node_anomaly_scores"], target_node_id
    )
    after_node_score = find_node(
        after_analysis["node_anomaly_scores"], target_node_id
    )
    score_before = (
        before_node_score.get("score")
        if isinstance(before_node_score, dict)
        else None
    )
    score_after = (
        after_node_score.get("score")
        if isinstance(after_node_score, dict)
        else None
    )
    changed_profile_keys = sorted(
        key
        for key in set(before_profile) | set(after_profile)
        if before_profile.get(key) != after_profile.get(key)
    )

    result["node_behavior_change"] = {
        "status": "completed",
        "scope": "target_node_only",
        "target_node_id": target_node_id,
        "affected_node_ids": [target_node_id],
        "firmware_before": before_firmware,
        "firmware_after": after_firmware,
        "firmware_version_changed": (
            before_firmware.get("version") != after_firmware.get("version")
            if isinstance(before_firmware, dict)
            and isinstance(after_firmware, dict)
            else None
        ),
        "changed_profile_keys": changed_profile_keys,
        "isolation_forest_score_before": score_before,
        "isolation_forest_score_after": score_after,
        "isolation_forest_score_delta": (
            round(score_after - score_before, 3)
            if isinstance(score_before, (int, float))
            and isinstance(score_after, (int, float))
            else None
        ),
    }
    return result
