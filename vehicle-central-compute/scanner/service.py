from datetime import datetime, timezone
from typing import Any, Callable, Dict
from uuid import uuid4

from scanner.attack_engine import ATTACK_SCENARIOS, create_attack_frames
from behavior_analysis.analyzer import (
    BehaviorModelSuite,
    classify_risk,
    summarize_network_phase,
)
from scanner.assurance import CONTROL_FINDINGS, SEVERITY_RANK


ATTACK_TYPES = set(ATTACK_SCENARIOS)
SEVERITIES = {"low", "medium", "high", "critical"}
ALERT_ACTIONS = {
    "low": "monitor",
    "medium": "investigate",
    "high": "block_and_alert",
    "critical": "isolate_and_escalate",
}
MIN_ATTACK_DURATION_SECONDS = 1
MAX_ATTACK_DURATION_SECONDS = 60
CHANGE_POINT_SCORE_THRESHOLD = 0.1
SCAN_MODES = {
    "service_center_safe": {
        "max_severity": "medium",
        "blocked_attacks": {"flooding", "dos"},
    },
    "oem_validation": {"max_severity": "critical", "blocked_attacks": set()},
    "lab_penetration_test": {"max_severity": "critical", "blocked_attacks": set()},
}
OTA_WEAKNESS_TESTS = {
    "replay_protection": ("W1", ("replay_attack",), ("T1",)),
    "freshness_protection": ("W1", ("replay_attack",), ("T1",)),
    "message_id_validation": (
        "W2",
        ("spoofing", "cross_zone_access"),
        ("T2", "T6"),
    ),
    "security_access_required": (
        "W3",
        ("unauthorized_diagnostics",),
        ("T5",),
    ),
    "diagnostic_access_control": (
        "W3",
        ("unauthorized_diagnostics", "cross_zone_access"),
        ("T5", "T6"),
    ),
    "message_authentication": ("W4", ("spoofing", "tampering"), ("T2", "T3")),
    "rate_limiting": ("W5", ("flooding", "dos"), ("T4",)),
    "timing_validation": ("W5", ("flooding", "dos"), ("T4",)),
    "range_validation": ("W6", ("tampering",), ("T3",)),
    "zonal_segmentation": ("W7", ("cross_zone_access",), ("T6",)),
    "firmware_signature_required": ("W8", ("invalid_firmware",), ("T7",)),
    "anti_downgrade": ("W9", ("invalid_firmware",), ("T7",)),
    "ids_logging": (
        "W10",
        (
            "replay_attack",
            "spoofing",
            "tampering",
            "flooding",
            "unauthorized_diagnostics",
            "invalid_firmware",
            "ids_auditability_regression",
        ),
        ("T1", "T2", "T3", "T4", "T5", "T7", "T8"),
    ),
}


def _timestamp_seconds() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _apply_ota_weakness_assessment(
    phase: Dict[str, Any],
    snapshot: Dict[str, Any],
    target_node_ids: set[str],
    attack_type: str,
    scenario_executed: bool,
) -> None:
    findings_by_weakness: Dict[str, Dict[str, Any]] = {}
    for behavior in snapshot.get("node_behavior", []):
        if (
            not isinstance(behavior, dict)
            or behavior.get("node_id") not in target_node_ids
        ):
            continue
        node_id = behavior["node_id"]
        for control, (weakness_id, attack_types, test_ids) in OTA_WEAKNESS_TESTS.items():
            if behavior.get(f"software_profile_{control}_enabled", True) is not False:
                continue
            finding_id, severity, title = CONTROL_FINDINGS[control]
            finding = findings_by_weakness.setdefault(
                weakness_id,
                {
                    "weakness_id": weakness_id,
                    "finding_id": finding_id,
                    "severity": severity,
                    "title": title,
                    "affected_node_ids": set(),
                    "affected_controls": set(),
                    "relevant_test_ids": set(),
                    "attack_types": set(),
                },
            )
            if SEVERITY_RANK[severity] > SEVERITY_RANK[finding["severity"]]:
                finding["severity"] = severity
                finding["finding_id"] = finding_id
                finding["title"] = title
            finding["affected_node_ids"].add(node_id)
            finding["affected_controls"].add(control)
            finding["relevant_test_ids"].update(test_ids)
            finding["attack_types"].update(attack_types)

    findings = []
    for weakness_id in sorted(findings_by_weakness):
        finding = findings_by_weakness[weakness_id]
        scenario_tested = (
            scenario_executed and attack_type in finding["attack_types"]
        )
        findings.append(
            {
                "weakness_id": finding["weakness_id"],
                "finding_id": finding["finding_id"],
                "severity": finding["severity"],
                "title": finding["title"],
                "affected_target_count": len(finding["affected_node_ids"]),
                "affected_controls": sorted(finding["affected_controls"]),
                "relevant_test_ids": sorted(finding["relevant_test_ids"]),
                "test_coverage": (
                    "covered" if scenario_tested else "not_covered"
                ),
            }
        )

    highest_severity_rank = max(
        (
            SEVERITY_RANK[finding["severity"]]
            for finding in findings
        ),
        default=-1,
    )
    risk_floor = {
        SEVERITY_RANK["medium"]: 0.25,
        SEVERITY_RANK["high"]: 0.5,
        SEVERITY_RANK["critical"]: 0.75,
    }.get(highest_severity_rank, 0.0)
    phase["ota_weakness_findings"] = findings
    phase["ota_weakness_count"] = len(findings)
    phase["ota_tested_weakness_count"] = sum(
        finding["test_coverage"] == "covered" for finding in findings
    )
    if risk_floor:
        phase["anomaly_score"] = max(phase["anomaly_score"], risk_floor)
        phase["risk_level"] = classify_risk(phase["anomaly_score"])
    if findings:
        finding_summary = "; ".join(
            f"{finding['weakness_id']} {finding['title']}"
            for finding in findings
        )
        phase["summary"] += (
            f" Active OTA weaknesses found: {finding_summary}."
        )


def run_scan(
    network_request: Callable[..., Dict[str, Any]],
    attack_type: str,
    severity: str,
    model_status: Dict[str, str],
    duration_seconds: int = 10,
    target_node_ids: list[str] | None = None,
    scan_mode: str = "oem_validation",
    run_baseline_checks: bool = True,
) -> Dict[str, Any]:
    if type(duration_seconds) is not int or not (
        MIN_ATTACK_DURATION_SECONDS
        <= duration_seconds
        <= MAX_ATTACK_DURATION_SECONDS
    ):
        raise ValueError(
            "duration_seconds must be an integer between "
            f"{MIN_ATTACK_DURATION_SECONDS} and {MAX_ATTACK_DURATION_SECONDS}"
        )
    policy = SCAN_MODES.get(scan_mode)
    if policy is None:
        raise ValueError(f"Unsupported scan_mode: {scan_mode}")
    if type(run_baseline_checks) is not bool:
        raise ValueError("run_baseline_checks must be a boolean")
    if attack_type in policy["blocked_attacks"]:
        raise PermissionError(
            f"{attack_type} is not permitted in {scan_mode} mode"
        )
    severity_rank = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    if severity_rank[severity] > severity_rank[policy["max_severity"]]:
        raise PermissionError(
            f"{severity} severity is not permitted in {scan_mode} mode"
        )
    service = network_request("vehicle_service_state")
    if service.get("service_state") != "in_service":
        raise PermissionError("vehicle must be in service before a scan can start")

    test_session_id = uuid4().hex
    scan_started_at = _timestamp_seconds()
    if run_baseline_checks:
        network_request("scan_activity_phase", phase="before_attack")
    before_snapshot = network_request("snapshot")
    before_uds = (
        network_request("network_diagnostics") if run_baseline_checks else {}
    )
    model_suite = BehaviorModelSuite()
    before_analysis = summarize_network_phase(
        before_snapshot, before_uds, model_suite
    )
    topology = before_snapshot.get("network_snapshot", {})
    if not isinstance(topology, dict):
        raise ValueError("simulator returned an invalid network topology")
    selected_targets = target_node_ids or None
    attack_frames = create_attack_frames(
        attack_type,
        severity,
        topology,
        selected_targets,
    )
    assessed_target_ids = {
        frame["target_ecu_id"]
        for frame in attack_frames
        if isinstance(frame.get("target_ecu_id"), str)
    }
    _apply_ota_weakness_assessment(
        before_analysis,
        before_snapshot,
        assessed_target_ids,
        attack_type,
        scenario_executed=False,
    )

    attack_error_type = None
    attack_window_started_at = _timestamp_seconds()
    if run_baseline_checks:
        network_request("scan_activity_phase", phase="protocol_probes")
    try:
        attack = network_request(
            "authorized_attack_test",
            authorized_simulation=True,
            attack_type=attack_type,
            severity=severity,
            duration_seconds=duration_seconds,
            attack_frames=attack_frames,
            run_protocol_probes=run_baseline_checks,
            **(
                {"target_node_ids": selected_targets}
                if selected_targets is not None
                else {}
            ),
        )
    except Exception as exc:
        attack = {"status": "failed"}
        attack_error_type = type(exc).__name__
        print(f"authorized_attack_test failed: {type(exc).__name__}: {exc}", flush=True)
    attack_window_ended_at = _timestamp_seconds()

    network_request("scan_activity_phase", phase="after_attack")
    after_snapshot = network_request("snapshot")
    after_uds = network_request("network_diagnostics")
    after_analysis = summarize_network_phase(
        after_snapshot, after_uds, model_suite
    )
    scan_status = attack.get("status", "unknown")
    _apply_ota_weakness_assessment(
        after_analysis,
        after_snapshot,
        assessed_target_ids,
        attack_type,
        scenario_executed=scan_status == "completed",
    )
    score_delta = round(
        after_analysis["anomaly_score"] - before_analysis["anomaly_score"], 3
    )
    comparison = {
        "anomaly_score_delta": score_delta,
        "isolation_forest_score_delta": round(
            after_analysis["isolation_forest_max_anomaly_score"]
            - before_analysis["isolation_forest_max_anomaly_score"],
            3,
        ),
        "isolation_forest_deviation_count_delta": (
            after_analysis["isolation_forest_deviation_node_count"]
            - before_analysis["isolation_forest_deviation_node_count"]
        ),
        "risk_increased": (
            after_analysis["anomaly_score"] > before_analysis["anomaly_score"]
        ),
        "new_security_event_count": max(
            0,
            after_analysis["security_event_count"]
            - before_analysis["security_event_count"],
        ),
        "new_active_dtc_count": max(
            0,
            after_analysis["active_dtc_count"]
            - before_analysis["active_dtc_count"],
        ),
        "behavior_variation_delta": (
            after_analysis["behavior_variation_count"]
            - before_analysis["behavior_variation_count"]
        ),
        "change_point_indicator": (
            abs(score_delta) >= CHANGE_POINT_SCORE_THRESHOLD
        ),
        "change_point_method": "phase_score_delta_threshold",
        "change_point_threshold": CHANGE_POINT_SCORE_THRESHOLD,
    }
    diagnostic_coverage = round(
        after_analysis["diagnostic_record_count"]
        * 100.0
        / max(after_analysis["network_node_count"], 1),
        3,
    )
    scan_ended_at = _timestamp_seconds()
    attack_started_at = attack.get("started_at", attack_window_started_at)
    attack_ended_at = attack.get("ended_at", attack_window_ended_at)
    attack_summary = {
        "status": attack.get("status", "unknown"),
        "execution_mode": attack.get("execution_mode"),
        "elapsed_seconds": attack.get("elapsed_seconds"),
        "event_count": attack.get("event_count", 0),
        "attack_frame_count": attack.get("attack_frame_count", 0),
        "accepted_frame_count": attack.get("accepted_frame_count", 0),
        "dropped_frame_count": attack.get("dropped_frame_count", 0),
        "affected_node_count": attack.get("affected_node_count", 0),
        "affected_interfaces": attack.get("affected_interfaces", []),
        "affected_sockets": attack.get("affected_sockets", []),
        **(
            attack["during_metrics"]
            if isinstance(attack.get("during_metrics"), dict)
            else {}
        ),
    }
    network_request("scan_activity_phase", phase="idle")
    if scan_status == "completed":
        network_summary = (
            f"Completed a {duration_seconds}-second simulated {attack_type} test; "
            f"post-test analysis found {after_analysis['risk_level']} risk."
        )
    elif scan_status == "stopped":
        network_summary = (
            f"The simulated {attack_type} test stopped before its requested "
            f"{duration_seconds}-second duration; post-test analysis found "
            f"{after_analysis['risk_level']} risk."
        )
    else:
        network_summary = (
            f"The simulated {attack_type} test failed; post-test analysis "
            f"found {after_analysis['risk_level']} risk."
        )
    summary = after_analysis["summary"]
    if scan_status != "completed":
        failure_type = (
            f" ({attack_error_type})" if attack_error_type is not None else ""
        )
        summary = f"{network_summary}{failure_type}"
    return {
        "status": scan_status,
        "service": "vehicle-central-compute",
        "attack_type": attack_type,
        "test_scenario_id": f"simulator:{attack_type}:v1",
        "assessment_purpose": "vehicle_security_assessment",
        "test_session_id": test_session_id,
        "pseudonym_scope": "single_test_session",
        "started_at": scan_started_at,
        "ended_at": scan_ended_at,
        "timestamp_precision": "seconds",
        "attack_started_at": attack_started_at,
        "attack_ended_at": attack_ended_at,
        "severity": severity,
        "scan_mode": scan_mode,
        "duration_seconds": duration_seconds,
        "baseline_checks_run": run_baseline_checks,
        "target_summary": {
            "targeting_mode": attack.get("targeting_mode", "scenario_default"),
            "target_count": attack.get("affected_node_count", 0),
            "role_counts": attack.get("target_role_counts", {}),
            "security_level_counts": attack.get(
                "target_security_level_counts", {}
            ),
        },
        "baseline_model": model_suite.baseline_training_summary(),
        "execution_mode": attack.get(
            "execution_mode", "bounded_simulator_socket_traffic"
        ),
        "network_summary": network_summary,
        "risk_level": after_analysis["risk_level"],
        "anomaly_score": after_analysis["anomaly_score"],
        "summary": summary,
        "alert_action": ALERT_ACTIONS[after_analysis["risk_level"]],
        "before_attack": before_analysis,
        "during_attack": {
            **(
                attack["during_metrics"]
                if isinstance(attack.get("during_metrics"), dict)
                else {}
            ),
            "affected_interfaces": attack.get("affected_interfaces", []),
            "affected_sockets": attack.get("affected_sockets", []),
            "attack_status": attack.get("status", "unknown"),
        },
        "probe_summary": attack.get("probe_summary", {}),
        "after_attack": after_analysis,
        "comparison": comparison,
        "attack_summary": attack_summary,
        "test_execution_result": "passed" if scan_status == "completed" else "failed",
        "security_assessment_result": "not_assessed",
        "recovery_status": "not_assessed",
        "confidence_status": "uncalibrated_isolation_forest",
        "diagnostic_coverage_percent": diagnostic_coverage,
        "evidence_references": [
            f"{test_session_id}:baseline",
            f"{test_session_id}:during-test-summary",
            f"{test_session_id}:post-test-summary",
        ],
        "ml_models": model_status,
        "raw_vehicle_data_shared_with_cloud": False,
    }
