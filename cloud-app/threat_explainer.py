import json
import os
import re
from typing import Any, Dict, List

import requests


THREAT_KNOWLEDGE = [
    {
        "reference": "CWE-400",
        "url": "https://cwe.mitre.org/data/definitions/400.html",
        "attack_types": {"flooding", "dos"},
        "keywords": {"availability", "resource", "rate", "flood", "denial", "dos"},
        "summary": "Uncontrolled resource consumption can reduce service availability.",
        "recommendations": [
            "Apply per-interface rate limits and bounded queues.",
            "Monitor message-rate and diagnostic-latency baselines and alert on sustained deviations.",
            "Verify recovery and availability after the test using an approved simulator scenario.",
        ],
    },
    {
        "reference": "CWE-294",
        "url": "https://cwe.mitre.org/data/definitions/294.html",
        "attack_types": {"replay_attack"},
        "keywords": {"replay", "sequence", "freshness", "counter", "timestamp"},
        "summary": "Captured messages reused without effective freshness controls may be accepted as current.",
        "recommendations": [
            "Validate monotonic counters or protocol freshness values at each receiver.",
            "Reject duplicate and out-of-order messages and test counter rollover behavior.",
            "Use authenticated freshness protection for safety-relevant commands where supported.",
        ],
    },
    {
        "reference": "CWE-345",
        "url": "https://cwe.mitre.org/data/definitions/345.html",
        "attack_types": {"spoofing", "repudiation"},
        "keywords": {"spoof", "identity", "source", "authentication", "authenticity"},
        "summary": "Insufficient verification of message authenticity can allow an untrusted source to be treated as legitimate.",
        "recommendations": [
            "Bind messages to an authenticated sender and validate the sender against the network topology.",
            "Reject messages with invalid authentication or unauthorized origin identities.",
            "Retain tamper-evident, privacy-minimized security event evidence for investigation.",
        ],
    },
    {
        "reference": "CWE-1284",
        "url": "https://cwe.mitre.org/data/definitions/1284.html",
        "attack_types": {"tampering"},
        "keywords": {"range", "signal", "payload", "validation", "tamper"},
        "summary": "Improper validation of specified quantities can allow invalid values to affect downstream processing.",
        "recommendations": [
            "Validate signal ranges, identifiers, payload lengths, and protocol fields at ingress.",
            "Fail closed on malformed messages and record aggregate rejection categories.",
            "Add boundary-value tests for each signal definition and protocol parser.",
        ],
    },
    {
        "reference": "ISO/SAE 21434",
        "url": "https://www.iso.org/standard/70918.html",
        "attack_types": {"flooding", "replay_attack", "repudiation", "dos", "tampering", "spoofing"},
        "keywords": {"vehicle", "cybersecurity", "risk", "lifecycle", "automotive"},
        "summary": "Automotive cybersecurity engineering uses a lifecycle risk-management approach; this simulator report is not a formal TARA or compliance assessment.",
        "recommendations": [
            "Map validated findings to the OEM cybersecurity case and threat analysis process.",
            "Confirm control effectiveness on the intended ECU software and vehicle configuration.",
            "Keep simulator findings distinct from production-vehicle verification evidence.",
        ],
    },
]

AGGREGATE_FIELDS = {
    "attack_type",
    "severity",
    "duration_seconds",
    "risk_level",
    "test_execution_result",
    "security_assessment_result",
    "recovery_status",
    "diagnostic_coverage_percent",
    "target_summary",
    "baseline_model",
    "during_attack",
    "before_attack",
    "after_attack",
    "comparison",
    "probe_summary",
}
PHASE_COUNT_FIELDS = {
    "diagnostic_response_categories",
    "ecu_family_counts",
    "ecu_software_version_counts",
    "network_protocol_counts",
    "observed_interface_counts",
    "security_event_categories",
    "security_event_severities",
    "new_security_event_categories",
}
DURING_FIELDS = {
    "sample_window_seconds",
    "message_count",
    "message_rate_per_second",
    "message_loss_percentage",
    "security_event_count",
    "affected_node_count",
    "event_count",
    "elapsed_seconds",
    "attack_status",
    "affected_interfaces",
}
COMPARISON_FIELDS = {
    "anomaly_score_delta",
    "isolation_forest_score_delta",
    "isolation_forest_deviation_count_delta",
    "risk_increased",
    "new_security_event_count",
    "behavior_variation_delta",
    "change_point_indicator",
    "change_point_method",
    "change_point_threshold",
    "new_active_dtc_count",
}
PROBE_FIELDS = {
    "suite",
    "status",
    "attempted_count",
    "rejected_count",
    "target_node_count",
    "category_counts",
    "protocols",
}
PHASE_FIELDS = {
    "network_node_count",
    "uds_tested_node_count",
    "uds_successful_count",
    "uds_failed_count",
    "diagnostic_timeout_count",
    "diagnostic_record_count",
    "active_dtc_count",
    "behavior_variation_count",
    "security_event_count",
    "new_security_event_count",
    "new_security_event_categories",
    "sampled_message_count",
    "sampled_message_rate_per_second",
    "inter_arrival_ms_mean",
    "inter_arrival_ms_p95",
    "message_loss_percentage",
    "diagnostic_latency_mean_ms",
    "diagnostic_timeout_rate_percent",
    "isolation_forest_mean_anomaly_score",
    "isolation_forest_max_anomaly_score",
    "isolation_forest_deviation_node_count",
    "risk_level",
    "ota_weakness_count",
    "ota_weakness_findings",
}


def _words(text: str) -> set[str]:
    return set(re.findall(r"[a-z0-9-]+", text.lower()))


def retrieve_threat_knowledge(scan: Dict[str, Any], limit: int = 3) -> List[Dict[str, Any]]:
    attack_type = str(scan.get("attack_type", ""))
    query = _words(
        " ".join(
            (
                attack_type,
                str(scan.get("severity", "")),
                str(scan.get("summary", "")),
                str(scan.get("risk_level", "")),
            )
        )
    )
    ranked = []
    for entry in THREAT_KNOWLEDGE:
        keyword_hits = len(query & entry["keywords"])
        attack_match = attack_type in entry["attack_types"]
        score = keyword_hits + (3 if attack_match else 0)
        if score:
            ranked.append((score, entry))
    ranked.sort(key=lambda item: (-item[0], item[1]["reference"]))
    return [
        {
            "reference": entry["reference"],
            "url": entry["url"],
            "summary": entry["summary"],
            "recommendations": entry["recommendations"],
        }
        for _, entry in ranked[:limit]
    ]


def minimized_evidence(scan: Dict[str, Any]) -> Dict[str, Any]:
    evidence = {
        key: scan[key]
        for key in AGGREGATE_FIELDS
        if key in scan
    }
    for phase_name in ("before_attack", "after_attack"):
        phase = evidence.get(phase_name)
        if isinstance(phase, dict):
            safe_phase = {}
            for key, value in phase.items():
                if key not in PHASE_FIELDS:
                    continue
                if key in PHASE_COUNT_FIELDS and isinstance(value, dict):
                    safe_phase[key] = {
                        label: count
                        for label, count in value.items()
                        if isinstance(label, str)
                        and len(label) <= 80
                        and type(count) in (int, float)
                    }
                elif key == "ota_weakness_findings" and isinstance(value, list):
                    safe_phase[key] = [
                        {
                            "weakness_id": finding["weakness_id"],
                            "finding_id": finding["finding_id"],
                            "severity": finding["severity"],
                            "title": finding["title"],
                            "affected_target_count": finding[
                                "affected_target_count"
                            ],
                            "affected_controls": [
                                control
                                for control in finding.get(
                                    "affected_controls", []
                                )
                                if isinstance(control, str)
                                and len(control) <= 80
                            ],
                            "relevant_test_ids": [
                                test_id
                                for test_id in finding.get(
                                    "relevant_test_ids", []
                                )
                                if isinstance(test_id, str)
                                and re.fullmatch(r"T[1-8]", test_id)
                            ],
                        }
                        for finding in value
                        if isinstance(finding, dict)
                        and isinstance(finding.get("weakness_id"), str)
                        and isinstance(finding.get("finding_id"), str)
                        and isinstance(finding.get("severity"), str)
                        and isinstance(finding.get("title"), str)
                        and type(finding.get("affected_target_count")) is int
                        and finding["affected_target_count"] >= 0
                    ]
                elif value is None or type(value) in (int, float, bool):
                    safe_phase[key] = value
                elif isinstance(value, str) and len(value) <= 80:
                    safe_phase[key] = value
            evidence[phase_name] = safe_phase
    target_summary = evidence.get("target_summary")
    if isinstance(target_summary, dict):
        safe_targets = {
            key: target_summary[key]
            for key in ("targeting_mode", "target_count")
            if key in target_summary
            and (
                isinstance(target_summary[key], str)
                or type(target_summary[key]) is int
            )
        }
        for key in ("role_counts", "security_level_counts"):
            counts = target_summary.get(key)
            if isinstance(counts, dict):
                safe_targets[key] = {
                    label: count
                    for label, count in counts.items()
                    if isinstance(label, str)
                    and len(label) <= 80
                    and type(count) is int
                    and count >= 0
                }
        evidence["target_summary"] = safe_targets
    during = evidence.get("during_attack")
    if isinstance(during, dict):
        safe_during = {
            key: value
            for key, value in during.items()
            if key in DURING_FIELDS
            and (
                value is None
                or type(value) in (int, float, bool)
                or (isinstance(value, str) and len(value) <= 80)
            )
        }
        interfaces = during.get("affected_interfaces")
        if isinstance(interfaces, list):
            safe_during["affected_interfaces"] = [
                item for item in interfaces
                if isinstance(item, str) and len(item) <= 40
            ][:16]
        evidence["during_attack"] = safe_during
    comparison = evidence.get("comparison")
    if isinstance(comparison, dict):
        evidence["comparison"] = {
            key: value
            for key, value in comparison.items()
            if key in COMPARISON_FIELDS
            and (
                value is None
                or type(value) in (int, float, bool)
                or (isinstance(value, str) and len(value) <= 80)
            )
        }
    probe_summary = evidence.get("probe_summary")
    if isinstance(probe_summary, dict):
        safe_probes = {
            key: value
            for key, value in probe_summary.items()
            if key in PROBE_FIELDS
            and (
                value is None
                or type(value) in (int, float, bool)
                or (isinstance(value, str) and len(value) <= 80)
            )
        }
        categories = probe_summary.get("category_counts")
        if isinstance(categories, dict):
            safe_probes["category_counts"] = {
                label: count
                for label, count in categories.items()
                if isinstance(label, str)
                and len(label) <= 80
                and type(count) is int
                and count >= 0
            }
        protocols = probe_summary.get("protocols")
        if isinstance(protocols, dict):
            safe_probes["protocols"] = {
                protocol: {
                    key: value
                    for key, value in metrics.items()
                    if key in {"attempted_count", "rejected_count", "target_node_count"}
                    and type(value) is int
                    and value >= 0
                }
                for protocol, metrics in protocols.items()
                if isinstance(protocol, str)
                and len(protocol) <= 40
                and isinstance(metrics, dict)
            }
        evidence["probe_summary"] = safe_probes
    return evidence


def _fallback_report(scan: Dict[str, Any], references: List[Dict[str, Any]]) -> Dict[str, Any]:
    attack = str(scan.get("attack_type", "unknown"))
    risk = str(scan.get("risk_level", "unknown"))
    before = scan.get("before_attack", {})
    after = scan.get("after_attack", {})
    comparison = scan.get("comparison", {})
    recommendations = list(
        dict.fromkeys(
            recommendation
            for item in references
            for recommendation in item["recommendations"]
        )
    )
    ota_findings = after.get("ota_weakness_findings", [])
    specific_findings = [
        (
            f"{finding['weakness_id']} {finding['title']} "
            f"(control: {', '.join(finding.get('affected_controls', [])) or 'not specified'}; "
            f"relevant checks: {', '.join(finding.get('relevant_test_ids', [])) or 'not specified'})"
        )
        for finding in ota_findings
        if isinstance(finding, dict)
        and isinstance(finding.get("weakness_id"), str)
        and isinstance(finding.get("title"), str)
    ] if isinstance(ota_findings, list) else []
    issue_details = (
        ["Specific OTA weaknesses: " + "; ".join(specific_findings)]
        if specific_findings else []
    )
    scan_categories = after.get("new_security_event_categories")
    categories = (
        scan_categories if isinstance(scan_categories, dict)
        else after.get("security_event_categories", {})
    )
    before_categories = (
        {} if isinstance(scan_categories, dict)
        else before.get("security_event_categories", {})
    )
    event_details = []
    if isinstance(categories, dict):
        for category, count in sorted(categories.items()):
            if not isinstance(category, str) or type(count) is not int:
                continue
            previous_count = (
                before_categories.get(category, 0)
                if isinstance(before_categories, dict)
                else 0
            )
            delta = max(0, count - (previous_count if type(previous_count) is int else 0))
            if delta:
                event_details.append(f"{category.replace('_', ' ')} ({delta})")
    if event_details:
        issue_details.append("New security events: " + "; ".join(event_details))
    if not issue_details:
        issue_details.append(
            "No OTA weakness or new security event was identified in the aggregate evidence."
        )
    for field, label in (
        ("uds_failed_count", "UDS diagnostic failures"),
        ("diagnostic_timeout_count", "Diagnostic timeouts"),
    ):
        after_count = after.get(field, 0)
        before_count = before.get(field, 0)
        if type(after_count) is int and type(before_count) is int:
            delta = after_count - before_count
            if delta > 0:
                issue_details.append(f"{label} increased by {delta}")
    issue_detail = "; ".join(issue_details) + "."
    explanation = (
        f"The bounded simulator {attack} scenario completed with {risk} risk. "
        f"{issue_detail} "
        f"The observed before/after Isolation Forest score delta was "
        f"{comparison.get('isolation_forest_score_delta', 'not available')}; "
        f"post-test diagnostics covered {after.get('diagnostic_record_count', 'an unreported number')} "
        f"records versus {before.get('diagnostic_record_count', 'an unreported number')} at baseline. "
        "This is simulator evidence and does not establish production ECU exploitability."
    )
    return {
        "status": "local_rag_only",
        "provider": "local_rag",
        "model": "deterministic",
        "title": f"OEM security assessment: {attack}",
        "executive_summary": (
            f"Simulator assessment reported {risk} risk for the {attack} scenario. "
            f"{issue_detail} Review the measured behavior deltas and validate applicable controls on the approved vehicle configuration."
        ),
        "technical_explanation": explanation,
        "recommendations": recommendations[:8],
        "evidence_citations": [
            f"{item['reference']} — {item['url']}" for item in references
        ],
        "limitations": [
            "Analysis uses aggregate simulator evidence only; no raw frames, direct node identifiers, VINs, or credentials were provided.",
            "Local RAG matches general weakness classes and does not query a live OEM or vulnerability advisory feed.",
            "Isolation Forest is trained per scan on the observed pre-attack simulator baseline and is not calibrated for production vehicles.",
            "Security-control effectiveness and post-attack recovery require separate validation unless explicitly measured.",
        ],
    }


def _gemini_report(
    scan: Dict[str, Any],
    references: List[Dict[str, Any]],
    fallback: Dict[str, Any],
) -> Dict[str, Any]:
    api_key = os.getenv("GEMINI_API_KEY", "").strip()
    if not api_key:
        return fallback
    model = os.getenv("GEMINI_MODEL", "gemini-2.5-flash").strip()
    prompt = {
        "task": "Write an OEM-friendly cybersecurity assessment from the minimized simulator evidence and retrieved references. Return JSON with executive_summary, technical_explanation, recommendations (array), evidence_citations (array), and limitations (array). Explicitly preserve every supplied OTA weakness ID, title, affected control, and relevant T-test ID in the technical explanation; name specific new security event categories and counts. Do not claim a real-vehicle exploit, formal compliance, or validated recovery. Separate measured facts from recommendations.",
        "evidence": minimized_evidence(scan),
        "retrieved_references": references,
        "fallback_report": {
            "executive_summary": fallback["executive_summary"],
            "recommendations": fallback["recommendations"],
            "limitations": fallback["limitations"],
        },
    }
    endpoint = (
        "https://generativelanguage.googleapis.com/v1beta/models/"
        f"{model}:generateContent"
    )
    try:
        response = requests.post(
            endpoint,
            params={"key": api_key},
            json={
                "contents": [{"parts": [{"text": json.dumps(prompt)}]}],
                "generationConfig": {
                    "responseMimeType": "application/json",
                    "temperature": 0.2,
                },
            },
            timeout=20,
        )
        response.raise_for_status()
        payload = response.json()
        text = payload["candidates"][0]["content"]["parts"][0]["text"]
        generated = json.loads(text)
        if not isinstance(generated, dict):
            raise ValueError("Gemini report must be a JSON object")
        required_text = ("executive_summary", "technical_explanation")
        if any(
            not isinstance(generated.get(field), str)
            or not generated[field].strip()
            for field in required_text
        ):
            raise ValueError("Gemini report omitted a required text field")
        return {
            **fallback,
            "status": "generated",
            "provider": "gemini_with_local_rag",
            "model": model,
            "executive_summary": generated["executive_summary"][:2000],
            "technical_explanation": generated["technical_explanation"][:4000],
            "recommendations": [
                item[:500]
                for item in generated.get("recommendations", [])
                if isinstance(item, str)
            ][:8]
            or fallback["recommendations"],
            "evidence_citations": fallback["evidence_citations"],
        }
    except (requests.RequestException, KeyError, TypeError, ValueError, json.JSONDecodeError):
        return {
            **fallback,
            "status": "fallback_gemini_unavailable",
            "provider": "local_rag",
            "limitations": fallback["limitations"]
            + ["Gemini was configured but did not return a valid report; the local RAG report is shown."],
        }


def create_threat_report(scan: Dict[str, Any]) -> Dict[str, Any]:
    references = retrieve_threat_knowledge(scan)
    fallback = _fallback_report(scan, references)
    return _gemini_report(scan, references, fallback)
