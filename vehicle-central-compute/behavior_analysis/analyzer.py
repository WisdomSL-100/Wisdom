from collections import Counter
from typing import Any, Dict, List

import numpy as np

from behavior_analysis.models import BehaviorModelSuite, make_node_features


MODEL_STATUS = {
    "isolation_forest": "active_per_scan_observed_baseline",
    "security_rules": "active",
}


def classify_risk(score: float) -> str:
    if score >= 0.75:
        return "critical"
    if score >= 0.5:
        return "high"
    if score >= 0.25:
        return "medium"
    return "low"


def _network_phase_metrics(
    snapshot: Dict[str, Any], diagnostics: List[Dict[str, Any]]
) -> Dict[str, Any]:
    behavior = snapshot.get("node_behavior", [])
    messages = snapshot.get("vehicle_messages", [])
    events = snapshot.get("security_events", [])

    protocols = Counter(
        item.get("protocol", "unknown")
        for item in behavior
        if isinstance(item, dict)
    )
    ecu_families = Counter(
        f"{item.get('functional_domain', 'unknown')}:{item.get('role', 'unknown')}"
        for item in diagnostics
        if isinstance(item, dict)
    )
    software_versions = Counter(
        firmware.get("version", "unknown")
        for item in diagnostics
        if isinstance(item, dict)
        and isinstance((firmware := item.get("firmware")), dict)
    )
    tx_generated = sum(
        max(0, int(item.get("tx_generated", 0) or 0))
        for item in behavior
        if isinstance(item, dict)
    )
    tx_delivered = sum(
        max(0, int(item.get("tx_delivered", 0) or 0))
        for item in behavior
        if isinstance(item, dict)
    )
    rx_accepted = sum(
        max(0, int(item.get("rx_accepted", 0) or 0))
        for item in behavior
        if isinstance(item, dict)
    )

    message_times: Dict[tuple[str, str], List[float]] = {}
    observed_interfaces = Counter()
    for message in messages:
        if not isinstance(message, dict):
            continue
        source = str(message.get("source_node_id", ""))
        name = str(message.get("message_name", ""))
        timestamp = message.get("sampled_at_monotonic_ms")
        if source and name and isinstance(timestamp, (int, float)):
            message_times.setdefault((source, name), []).append(float(timestamp))
        interface = message.get("transport_type", message.get("protocol"))
        if isinstance(interface, str):
            observed_interfaces[interface] += 1

    inter_arrivals = [
        right - left
        for timestamps in message_times.values()
        for left, right in zip(sorted(timestamps), sorted(timestamps)[1:])
        if right >= left
    ]
    inter_arrival_stats = {
        "mean": round(float(np.mean(inter_arrivals)), 3) if inter_arrivals else None,
        "p95": round(float(np.percentile(inter_arrivals, 95)), 3)
        if inter_arrivals
        else None,
        "max": round(max(inter_arrivals), 3) if inter_arrivals else None,
    }
    observed_windows_seconds = [
        (max(timestamps) - min(timestamps)) / 1000.0
        for timestamps in message_times.values()
        if len(timestamps) > 1 and max(timestamps) > min(timestamps)
    ]
    sampled_message_rate = (
        round(len(inter_arrivals) / sum(observed_windows_seconds), 3)
        if observed_windows_seconds and inter_arrivals
        else None
    )
    event_count = len(events)

    return {
        "ecu_family_counts": dict(sorted(ecu_families.items())),
        "ecu_software_version_counts": dict(sorted(software_versions.items())),
        "gateway_configuration_version": snapshot.get(
            "gateway_configuration_version", "unspecified"
        ),
        "network_protocol_counts": dict(sorted(protocols.items())),
        "observed_interface_counts": dict(sorted(observed_interfaces.items())),
        "sampled_message_count": len(messages),
        "sampled_message_rate_per_second": sampled_message_rate,
        "inter_arrival_ms_mean": inter_arrival_stats["mean"],
        "inter_arrival_ms_p95": inter_arrival_stats["p95"],
        "inter_arrival_ms_max": inter_arrival_stats["max"],
        "tx_generated_count": tx_generated,
        "tx_delivered_count": tx_delivered,
        "rx_accepted_count": rx_accepted,
        "message_loss_percentage": round(
            max(0, tx_generated - tx_delivered) * 100.0 / max(tx_generated, 1),
            3,
        ),
        "network_error_rate_percentage": None,
        "network_error_rate_status": "not_measured_by_simulator",
        "security_event_rate_percentage": round(
            event_count * 100.0 / max(tx_generated, 1), 3
        ),
        "bus_utilization_percentage": None,
        "bus_utilization_status": "not_measured_no_bus_rate_configuration",
        "message_sample_status": "bounded_recent_buffer",
    }


def analyze_telemetry(diagnostics: List[Dict[str, Any]]) -> Dict[str, Any]:
    if not diagnostics:
        return {
            "score": 0.0,
            "risk_level": "low",
            "summary": "No ECU diagnostics were returned.",
        }

    weights = {
        "bus_load": 0.12,
        "latency_ms": 0.10,
        "error_rate": 0.14,
        "packet_loss_pct": 0.12,
        "timing_anomaly_score": 0.14,
        "unauthorized_access_attempts": 0.12,
        "invalid_response_count": 0.10,
        "message_frequency_hz": 0.08,
        "payload_size_bytes": 0.08,
    }
    limits = {
        "bus_load": 85,
        "latency_ms": 150,
        "error_rate": 0.2,
        "packet_loss_pct": 25,
        "timing_anomaly_score": 1,
        "unauthorized_access_attempts": 4,
        "invalid_response_count": 15,
        "message_frequency_hz": 900,
        "payload_size_bytes": 64,
    }
    ecu_scores = []
    for diagnostic in diagnostics:
        feature_scores = {
            name: min(1.0, max(0.0, float(diagnostic.get(name, 0)) / limit))
            for name, limit in limits.items()
        }
        weighted_score = sum(
            feature_scores[name] * weights[name] for name in weights
        )
        ecu_scores.append(
            {
                "ecu_id": diagnostic.get("ecu_id", "unknown"),
                "score": round(weighted_score, 3),
                "signals": [
                    name
                    for name, value in feature_scores.items()
                    if value >= 0.6
                ],
            }
        )

    score = max(item["score"] for item in ecu_scores)
    risk = classify_risk(score)
    summary = (
        f"Analyzed {len(diagnostics)} ECU diagnostic records; strongest "
        f"anomaly score is {score:.3f} ({risk} risk)."
    )
    return {
        "score": score,
        "risk_level": risk,
        "summary": summary,
        "ecu_scores": ecu_scores,
        "analysis_method": "weighted_security_rules",
    }


def summarize_network_phase(
    snapshot: Dict[str, Any],
    uds_summary: Dict[str, Any],
    model_suite: BehaviorModelSuite,
    include_node_scores: bool = False,
) -> Dict[str, Any]:
    diagnostics = snapshot.get("diagnostics", [])
    behavior = snapshot.get("node_behavior", [])
    events = snapshot.get("security_events", [])
    node_count = int(snapshot.get("network_snapshot", {}).get("node_count", 0))
    telemetry = analyze_telemetry(diagnostics)
    diagnostics_by_node = {
        item.get("node_id", f"anonymous:{index}"): item
        for index, item in enumerate(diagnostics)
        if isinstance(item, dict)
    }
    behavior_by_node = {
        item.get("node_id", f"anonymous:{index}"): item
        for index, item in enumerate(behavior)
        if isinstance(item, dict)
    }
    event_counts = Counter(
        event.get("node_id")
        for event in events
        if isinstance(event, dict) and event.get("node_id") is not None
    )
    node_features = {
        node_id: make_node_features(
            diagnostics_by_node.get(node_id, {}),
            behavior_by_node.get(node_id, {}),
            event_counts[node_id],
        )
        for node_id in dict.fromkeys(
            (*diagnostics_by_node.keys(), *behavior_by_node.keys())
        )
    }
    node_isolation_scores = model_suite.score_nodes(node_features)
    model_scores = model_suite.score(list(node_features.values()))
    network_metrics = _network_phase_metrics(snapshot, diagnostics)
    variation_count = sum(
        1
        for node in behavior
        if node.get("behavior_state") != "within_declared_contract"
    )
    categories = Counter(
        event.get("category", "unknown")
        for event in events
        if isinstance(event, dict)
    )
    severities = Counter(
        event.get("severity", "unknown")
        for event in events
        if isinstance(event, dict)
    )
    behavior_score = variation_count / max(node_count, 1)
    event_score = min(1.0, len(events) / max(node_count * 4, 1))
    score = round(
        max(
            telemetry["score"],
            behavior_score,
            event_score,
            model_scores["isolation_forest_max_anomaly_score"],
        ),
        3,
    )
    risk = classify_risk(score)

    summary = {
        "network_node_count": node_count,
        "diagnostic_record_count": len(diagnostics),
        "uds_tested_node_count": int(uds_summary.get("component_count", 0)),
        "uds_successful_count": int(uds_summary.get("successful_count", 0)),
        "uds_failed_count": int(uds_summary.get("failed_count", 0)),
        "active_dtc_count": int(uds_summary.get("active_dtc_count", 0)),
        "behavior_variation_count": variation_count,
        "security_event_count": len(events),
        "security_event_categories": dict(sorted(categories.items())),
        "security_event_severities": dict(sorted(severities.items())),
        **network_metrics,
        "diagnostic_latency_mean_ms": uds_summary.get(
            "diagnostic_latency_mean_ms"
        ),
        "diagnostic_latency_max_ms": uds_summary.get(
            "diagnostic_latency_max_ms"
        ),
        "diagnostic_timeout_count": int(uds_summary.get("timeout_count", 0)),
        "diagnostic_timeout_rate_percent": uds_summary.get(
            "timeout_rate_percent"
        ),
        "diagnostic_response_categories": uds_summary.get(
            "response_categories", {}
        ),
        "ecu_availability_percent": uds_summary.get(
            "ecu_availability_percent"
        ),
        "diagnostic_sample_precision": uds_summary.get(
            "sample_precision", "unspecified"
        ),
        **model_scores,
        "anomaly_score": score,
        "risk_level": risk,
        "summary": (
            f"Assessed {node_count} simulated nodes; "
            f"{variation_count} behavior variations and {len(events)} "
            f"security events were observed ({risk} risk)."
        ),
        "analysis_method": "weighted_security_rules+isolation_forest",
    }
    if include_node_scores:
        summary["node_anomaly_scores"] = [
            {
                "node_id": node_id,
                "score": round(score, 3),
                "risk_level": classify_risk(score),
            }
            for node_id, score in sorted(
                node_isolation_scores.items(),
                key=lambda item: (-item[1], item[0]),
            )
        ]
    return summary
