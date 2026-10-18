import base64
import hashlib
import hmac
import importlib.util
import json
import os
import sqlite3
import time
from contextlib import closing
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List
from uuid import uuid4

import requests
try:
    from cve_store import import_records, list_cves, match_components, sync_nvd
except ModuleNotFoundError:
    _CVE_STORE_SPEC = importlib.util.spec_from_file_location(
        "cloud_cve_store", os.path.join(os.path.dirname(__file__), "cve_store.py")
    )
    if _CVE_STORE_SPEC is None or _CVE_STORE_SPEC.loader is None:
        raise RuntimeError("Unable to load the CVE store module")
    _CVE_STORE = importlib.util.module_from_spec(_CVE_STORE_SPEC)
    _CVE_STORE_SPEC.loader.exec_module(_CVE_STORE)
    import_records = _CVE_STORE.import_records
    list_cves = _CVE_STORE.list_cves
    match_components = _CVE_STORE.match_components
    sync_nvd = _CVE_STORE.sync_nvd
from cryptography.fernet import Fernet, InvalidToken
from flask import Flask, jsonify, request

_THREAT_EXPLAINER_PATH = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "threat_explainer.py"
)
_THREAT_EXPLAINER_SPEC = importlib.util.spec_from_file_location(
    "cloud_threat_explainer", _THREAT_EXPLAINER_PATH
)
if _THREAT_EXPLAINER_SPEC is None or _THREAT_EXPLAINER_SPEC.loader is None:
    raise RuntimeError("Unable to load the cloud threat explainer module")
_THREAT_EXPLAINER = importlib.util.module_from_spec(_THREAT_EXPLAINER_SPEC)
_THREAT_EXPLAINER_SPEC.loader.exec_module(_THREAT_EXPLAINER)

app = Flask(__name__)
PORT = int(os.getenv("PORT", "5003"))
SCAN_TIMEOUT_MARGIN_SECONDS = 300
CENTRAL_COMPUTE_URL = os.getenv(
    "CENTRAL_COMPUTE_URL", "https://vehicle-central-compute:5002"
)
CENTRAL_TLS_CA = os.getenv("CENTRAL_TLS_CA", "/run/tls/ca.crt")
CENTRAL_TLS_CLIENT_CERT = os.getenv(
    "CENTRAL_TLS_CLIENT_CERT", "/run/tls/cloud-client.crt"
)
CENTRAL_TLS_CLIENT_KEY = os.getenv(
    "CENTRAL_TLS_CLIENT_KEY", "/run/tls/cloud-client.key"
)
HISTORY_ENCRYPTION_KEY = os.getenv("SCAN_HISTORY_ENCRYPTION_KEY", "")
DEFAULT_RETENTION_DAYS = 30
ENCRYPTED_RECORD_PREFIX = "fernet:v1:"
JWT_ISSUER = "cloud-app"
JWT_AUDIENCE = "vehicle-central-compute"
JWT_LIFETIME_SECONDS = 60
ATTACK_LIBRARY: List[str] = [
    "flooding",
    "replay_attack",
    "repudiation",
    "dos",
    "tampering",
    "spoofing",
    "unauthorized_diagnostics",
    "cross_zone_access",
    "invalid_firmware",
    "ids_auditability_regression",
]
SEVERITIES = {"low", "medium", "high", "critical"}
SCAN_MODES = {
    "service_center_safe": {"max_severity": "medium", "blocked_attacks": {"flooding", "dos"}},
    "oem_validation": {"max_severity": "critical", "blocked_attacks": set()},
    "lab_penetration_test": {"max_severity": "critical", "blocked_attacks": set()},
}
LAST_SCAN: Dict[str, Any] = {
    "risk_level": "unknown",
    "summary": "No scan run yet",
    "attack_type": "none",
    "severity": "unknown",
    "duration_seconds": 0,
    "ai_summary": "AI provider is not configured; deterministic security-rule analysis is available.",
}
PHASE_FIELDS = {
    "network_node_count",
    "diagnostic_record_count",
    "uds_tested_node_count",
    "uds_successful_count",
    "uds_failed_count",
    "active_dtc_count",
    "behavior_variation_count",
    "security_event_count",
    "security_event_categories",
    "security_event_severities",
    "ecu_family_counts",
    "ecu_software_version_counts",
    "gateway_configuration_version",
    "network_protocol_counts",
    "observed_interface_counts",
    "sampled_message_count",
    "sampled_message_rate_per_second",
    "inter_arrival_ms_mean",
    "inter_arrival_ms_p95",
    "inter_arrival_ms_max",
    "tx_generated_count",
    "tx_delivered_count",
    "rx_accepted_count",
    "message_loss_percentage",
    "network_error_rate_percentage",
    "network_error_rate_status",
    "security_event_rate_percentage",
    "bus_utilization_percentage",
    "bus_utilization_status",
    "message_sample_status",
    "diagnostic_latency_mean_ms",
    "diagnostic_latency_max_ms",
    "diagnostic_timeout_count",
    "diagnostic_timeout_rate_percent",
    "diagnostic_response_categories",
    "ecu_availability_percent",
    "diagnostic_sample_precision",
    "isolation_forest_mean_anomaly_score",
    "isolation_forest_max_anomaly_score",
    "isolation_forest_deviation_node_count",
    "anomaly_score",
    "risk_level",
    "summary",
    "analysis_method",
    "ota_weakness_count",
    "ota_tested_weakness_count",
    "ota_weakness_findings",
}
COMPARISON_FIELDS = {
    "anomaly_score_delta",
    "isolation_forest_score_delta",
    "isolation_forest_deviation_count_delta",
    "risk_increased",
    "new_security_event_count",
    "new_active_dtc_count",
    "behavior_variation_delta",
    "change_point_indicator",
    "change_point_method",
    "change_point_threshold",
}
COUNT_MAP_FIELDS = {
    "security_event_categories",
    "security_event_severities",
    "ecu_family_counts",
    "ecu_software_version_counts",
    "network_protocol_counts",
    "observed_interface_counts",
    "diagnostic_response_categories",
}


def history_db_path() -> str:
    data_dir = os.getenv("DATA_DIR", os.path.join(os.path.dirname(__file__), "data"))
    db_path = os.getenv("SCAN_HISTORY_DB", os.path.join(data_dir, "scan_history.sqlite3"))
    os.makedirs(os.path.dirname(db_path) or ".", exist_ok=True)
    return db_path


def central_request(method: str, url: str, **kwargs: Any) -> requests.Response:
    headers = dict(kwargs.pop("headers", {}))
    headers["Authorization"] = f"Bearer {create_central_jwt()}"
    kwargs.setdefault("verify", CENTRAL_TLS_CA)
    kwargs.setdefault(
        "cert", (CENTRAL_TLS_CLIENT_CERT, CENTRAL_TLS_CLIENT_KEY)
    )
    kwargs["headers"] = headers
    return getattr(requests, method.lower())(url, **kwargs)


def _jwt_secret() -> bytes:
    secret = os.getenv("CENTRAL_SERVICE_JWT_SECRET", "")
    if len(secret.encode("utf-8")) < 32:
        raise RuntimeError(
            "CENTRAL_SERVICE_JWT_SECRET must contain at least 32 bytes"
        )
    return secret.encode("utf-8")


def _base64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def create_central_jwt() -> str:
    issued_at = int(time.time())
    header = {"alg": "HS256", "typ": "JWT"}
    claims = {
        "iss": JWT_ISSUER,
        "sub": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
        "iat": issued_at,
        "exp": issued_at + JWT_LIFETIME_SECONDS,
        "jti": uuid4().hex,
    }
    encoded_header = _base64url(
        json.dumps(header, separators=(",", ":"), sort_keys=True).encode("utf-8")
    )
    encoded_claims = _base64url(
        json.dumps(claims, separators=(",", ":"), sort_keys=True).encode("utf-8")
    )
    signing_input = f"{encoded_header}.{encoded_claims}".encode("ascii")
    signature = hmac.new(_jwt_secret(), signing_input, hashlib.sha256).digest()
    return f"{encoded_header}.{encoded_claims}.{_base64url(signature)}"


def history_fernet() -> Fernet:
    if not HISTORY_ENCRYPTION_KEY:
        raise RuntimeError(
            "SCAN_HISTORY_ENCRYPTION_KEY must be configured to read or write scan history"
        )
    try:
        return Fernet(HISTORY_ENCRYPTION_KEY.encode("ascii"))
    except (ValueError, UnicodeEncodeError) as exc:
        raise RuntimeError("SCAN_HISTORY_ENCRYPTION_KEY is not a valid Fernet key") from exc


def retention_cutoff() -> datetime:
    try:
        days = int(os.getenv("SCAN_RETENTION_DAYS", str(DEFAULT_RETENTION_DAYS)))
    except ValueError as exc:
        raise RuntimeError("SCAN_RETENTION_DAYS must be a positive integer") from exc
    if days <= 0:
        raise RuntimeError("SCAN_RETENTION_DAYS must be a positive integer")
    return datetime.now(timezone.utc).replace(microsecond=0) - timedelta(days=days)


def encrypt_record(record: Dict[str, Any]) -> str:
    ciphertext = history_fernet().encrypt(
        json.dumps(record, separators=(",", ":")).encode("utf-8")
    )
    return ENCRYPTED_RECORD_PREFIX + ciphertext.decode("ascii")


def decrypt_record(record_json: str) -> Dict[str, Any]:
    if not record_json.startswith(ENCRYPTED_RECORD_PREFIX):
        return json.loads(record_json)
    try:
        plaintext = history_fernet().decrypt(
            record_json[len(ENCRYPTED_RECORD_PREFIX) :].encode("ascii")
        )
    except (InvalidToken, UnicodeEncodeError) as exc:
        raise RuntimeError("Stored scan record could not be decrypted") from exc
    return json.loads(plaintext)


def ensure_history_table() -> None:
    with closing(sqlite3.connect(history_db_path())) as connection:
        with connection:
            connection.execute(
                """CREATE TABLE IF NOT EXISTS scan_history (
                    scan_id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    record_json TEXT NOT NULL
                )"""
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS scan_history_created_at ON scan_history(created_at)"
            )
            connection.execute(
                """CREATE TABLE IF NOT EXISTS scan_history_migrations (
                    migration_id TEXT PRIMARY KEY
                )"""
            )
            migrated = connection.execute(
                "SELECT 1 FROM scan_history_migrations WHERE migration_id = ?",
                ("encrypted_privacy_safe_records_v2",),
            ).fetchone()
            if migrated is None:
                rows = connection.execute(
                    "SELECT scan_id, record_json FROM scan_history"
                ).fetchall()
                for scan_id, record_json in rows:
                    safe_json = encrypt_record(
                        privacy_safe_scan(decrypt_record(record_json))
                    )
                    connection.execute(
                        "UPDATE scan_history SET record_json = ? WHERE scan_id = ?",
                        (safe_json, scan_id),
                    )
                connection.execute(
                    "INSERT INTO scan_history_migrations (migration_id) VALUES (?)",
                    ("encrypted_privacy_safe_records_v2",),
                )
            connection.execute(
                "DELETE FROM scan_history WHERE julianday(created_at) < julianday(?)",
                (retention_cutoff().isoformat(),),
            )


def privacy_safe_scan(scan: Dict[str, Any]) -> Dict[str, Any]:
    allowed = {
        "scan_id",
        "created_at",
        "risk_level",
        "summary",
        "attack_type",
        "scan_mode",
        "severity",
        "duration_seconds",
        "scan_status",
        "ai_summary",
        "alert_action",
        "ml_models",
        "test_session_id",
        "pseudonym_scope",
        "assessment_purpose",
        "test_scenario_id",
        "started_at",
        "ended_at",
        "timestamp_precision",
        "attack_started_at",
        "attack_ended_at",
        "test_execution_result",
        "security_assessment_result",
        "recovery_status",
        "confidence_status",
        "diagnostic_coverage_percent",
        "cloud_region",
        "probe_summary",
        "target_summary",
        "baseline_model",
        "threat_report",
        "ota_assurance",
    }
    safe = {key: value for key, value in scan.items() if key in allowed}
    if isinstance(scan.get("evidence_references"), list):
        safe["evidence_references"] = [
            reference
            for reference in scan["evidence_references"]
            if isinstance(reference, str) and len(reference) <= 160
        ]
    during_attack = scan.get("during_attack")
    if isinstance(during_attack, dict):
        safe["during_attack"] = {
            key: value
            for key, value in during_attack.items()
            if key
            in {
                "sample_window_seconds",
                "message_count",
                "message_rate_per_second",
                "message_loss_percentage",
                "security_event_count",
                "attack_frame_count",
                "accepted_frame_count",
                "dropped_frame_count",
                "affected_interfaces",
                "affected_sockets",
                "attack_status",
            }
        }
    attack_summary = scan.get("attack_summary")
    if isinstance(attack_summary, dict):
        safe["attack_summary"] = {
            key: value
            for key, value in attack_summary.items()
            if key
            in {
                "status",
                "execution_mode",
                "elapsed_seconds",
                "event_count",
                "attack_frame_count",
                "accepted_frame_count",
                "dropped_frame_count",
                "affected_node_count",
                "affected_interfaces",
                "affected_sockets",
                "sample_window_seconds",
                "message_count",
                "message_rate_per_second",
                "message_loss_percentage",
                "security_event_count",
                "targeting_mode",
                "target_count",
                "target_role_counts",
                "target_security_level_counts",
            }
        }
    probe_summary = scan.get("probe_summary")
    if isinstance(probe_summary, dict):
        categories = probe_summary.get("category_counts")
        protocols = probe_summary.get("protocols")
        safe["probe_summary"] = {
            key: value
            for key, value in probe_summary.items()
            if key
            in {
                "suite",
                "status",
                "attempted_count",
                "rejected_count",
                "target_node_count",
            }
            and (
                isinstance(value, str)
                or (type(value) is int and value >= 0)
            )
        }
        if isinstance(categories, dict):
            safe["probe_summary"]["category_counts"] = {
                category: count
                for category, count in categories.items()
                if isinstance(category, str)
                and type(count) is int
                and count >= 0
            }
        if isinstance(protocols, dict):
            safe["probe_summary"]["protocols"] = {
                protocol: {
                    key: value
                    for key, value in values.items()
                    if key
                    in {
                        "attempted_count",
                        "rejected_count",
                        "target_node_count",
                    }
                    and type(value) is int
                    and value >= 0
                }
                for protocol, values in protocols.items()
                if isinstance(protocol, str) and isinstance(values, dict)
            }
    target_summary = scan.get("target_summary")
    if isinstance(target_summary, dict):
        safe["target_summary"] = {
            key: value
            for key, value in target_summary.items()
            if key in {"targeting_mode", "target_count"}
            and (
                isinstance(value, str)
                or (type(value) is int and value >= 0)
            )
        }
        for key in ("role_counts", "security_level_counts"):
            counts = target_summary.get(key)
            if isinstance(counts, dict):
                safe["target_summary"][key] = {
                    label: count
                    for label, count in counts.items()
                    if isinstance(label, str)
                    and type(count) is int
                    and count >= 0
                }
    baseline_model = scan.get("baseline_model")
    if isinstance(baseline_model, dict):
        safe["baseline_model"] = {
            key: value
            for key, value in baseline_model.items()
            if key
            in {
                "algorithm",
                "training_phase",
                "training_node_count",
                "feature_count",
                "synthetic_training_samples",
                "status",
            }
        }
    threat_report = scan.get("threat_report")
    if isinstance(threat_report, dict):
        safe["threat_report"] = _sanitize_threat_report(threat_report)
    ota_assurance = scan.get("ota_assurance")
    if isinstance(ota_assurance, dict):
        safe["ota_assurance"] = {
            key: ota_assurance[key]
            for key in (
                "status",
                "assurance_scope",
                "target_node_id",
                "baseline_status",
                "firmware_hash",
                "cryptographic_posture",
                "version_comparison",
                "security_profile",
                "finding_count",
                "highest_severity",
                "cve_summary",
                "sbom_summary",
                "findings",
            )
            if key in ota_assurance
        }
    for phase_name in ("before_attack", "after_attack"):
        phase = scan.get(phase_name)
        if isinstance(phase, dict):
            filtered = {key: value for key, value in phase.items() if key in PHASE_FIELDS}
            for count_field in COUNT_MAP_FIELDS:
                counts = filtered.get(count_field)
                if isinstance(counts, dict):
                    filtered[count_field] = {
                        str(category): count
                        for category, count in counts.items()
                        if isinstance(category, str) and type(count) is int
                    }
            for count_field in (
                "ota_weakness_count",
                "ota_tested_weakness_count",
            ):
                count = filtered.get(count_field)
                if type(count) is not int or count < 0:
                    filtered.pop(count_field, None)
            findings = phase.get("ota_weakness_findings")
            if isinstance(findings, list):
                filtered["ota_weakness_findings"] = [
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
                            for control in finding.get("affected_controls", [])
                            if isinstance(control, str)
                        ],
                        "relevant_test_ids": [
                            test_id
                            for test_id in finding.get("relevant_test_ids", [])
                            if isinstance(test_id, str)
                            and test_id in {f"T{number}" for number in range(1, 9)}
                        ],
                        "test_coverage": finding["test_coverage"],
                    }
                    for finding in findings
                    if isinstance(finding, dict)
                    and isinstance(finding.get("weakness_id"), str)
                    and isinstance(finding.get("finding_id"), str)
                    and finding.get("severity")
                    in {"low", "medium", "high", "critical"}
                    and isinstance(finding.get("title"), str)
                    and type(finding.get("affected_target_count")) is int
                    and finding["affected_target_count"] >= 0
                    and finding.get("test_coverage")
                    in {"covered", "not_covered"}
                    and isinstance(finding.get("affected_controls", []), list)
                    and isinstance(finding.get("relevant_test_ids", []), list)
                ]
            safe[phase_name] = filtered
    comparison = scan.get("comparison")
    if isinstance(comparison, dict):
        safe["comparison"] = {
            key: value
            for key, value in comparison.items()
            if key in COMPARISON_FIELDS
        }
    ml_models = scan.get("ml_models")
    if isinstance(ml_models, dict):
        safe["ml_models"] = {
            key: value
            for key, value in ml_models.items()
            if key in {"isolation_forest", "security_rules"}
            and isinstance(value, str)
        }
    return safe


def save_scan(scan: Dict[str, Any]) -> Dict[str, Any]:
    record = privacy_safe_scan(scan)
    record.update(
        {
            "scan_id": uuid4().hex,
            "created_at": datetime.now(timezone.utc).replace(
                microsecond=0
            ).isoformat(),
        }
    )
    ensure_history_table()
    with closing(sqlite3.connect(history_db_path())) as connection:
        with connection:
            connection.execute(
                "INSERT INTO scan_history (scan_id, created_at, record_json) VALUES (?, ?, ?)",
                (
                    record["scan_id"],
                    record["created_at"],
                    encrypt_record(record),
                ),
            )
    return record


def latest_saved_scan() -> Dict[str, Any]:
    ensure_history_table()
    with closing(sqlite3.connect(history_db_path())) as connection:
        row = connection.execute(
            "SELECT record_json FROM scan_history ORDER BY created_at DESC, rowid DESC LIMIT 1"
        ).fetchone()
    return privacy_safe_scan(decrypt_record(row[0])) if row else {}


def saved_scans(limit: int) -> List[Dict[str, Any]]:
    ensure_history_table()
    with closing(sqlite3.connect(history_db_path())) as connection:
        rows = connection.execute(
            "SELECT record_json FROM scan_history ORDER BY created_at DESC, rowid DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [privacy_safe_scan(decrypt_record(row[0])) for row in rows]


def saved_scan(scan_id: str) -> Dict[str, Any] | None:
    ensure_history_table()
    with closing(sqlite3.connect(history_db_path())) as connection:
        row = connection.execute(
            "SELECT record_json FROM scan_history WHERE scan_id = ?",
            (scan_id,),
        ).fetchone()
    return privacy_safe_scan(decrypt_record(row[0])) if row else None


def _sanitize_threat_report(report: Dict[str, Any]) -> Dict[str, Any]:
    allowed = {
        "status",
        "provider",
        "model",
        "title",
        "executive_summary",
        "technical_explanation",
        "recommendations",
        "evidence_citations",
        "limitations",
    }
    safe = {
        key: value
        for key, value in report.items()
        if key in allowed and isinstance(value, (str, int, float, bool))
    }
    for key in ("recommendations", "evidence_citations", "limitations"):
        values = report.get(key)
        if isinstance(values, list):
            safe[key] = [
                item[:500]
                for item in values
                if isinstance(item, str) and len(item) <= 500
            ][:12]
    return safe


@app.get("/")
def root():
    return jsonify({"service": "cloud-app", "status": "ok"})


@app.get("/health")
def health():
    return jsonify({"status": "ok", "service": "cloud-app"})


@app.get("/api/attacks")
def available_attacks():
    return jsonify({"attack_types": ATTACK_LIBRARY})


@app.get("/api/security/profiles")
def security_profiles():
    try:
        response = central_request(
            "get",
            f"{CENTRAL_COMPUTE_URL}/security/profiles",
            timeout=10,
        )
        response.raise_for_status()
        profiles = response.json()
        if not isinstance(profiles, dict) or not isinstance(profiles.get("nodes"), list):
            raise ValueError("Central Compute returned invalid security profiles")
        return jsonify(profiles)
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 503


@app.post("/api/security/profiles")
def update_security_profile():
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"status": "error", "message": "Request body must be a JSON object"}), 400
    try:
        response = central_request(
            "post",
            f"{CENTRAL_COMPUTE_URL}/security/profiles",
            json=payload,
            timeout=10,
        )
        if response.status_code < 500:
            return jsonify(response.json()), response.status_code
        response.raise_for_status()
        raise RuntimeError("Central Compute rejected the security profile update")
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 503


@app.get("/api/network/observability")
def network_observability():
    try:
        response = central_request(
            "get",
            f"{CENTRAL_COMPUTE_URL}/network/observability",
            timeout=15,
        )
        response.raise_for_status()
        data = response.json()
        if (
            not isinstance(data, dict)
            or not isinstance(data.get("sockets"), list)
            or not isinstance(data.get("network"), dict)
            or not isinstance(data.get("uds"), dict)
        ):
            raise ValueError("Central Compute returned invalid network observability")

        sockets = []
        for endpoint in data["sockets"]:
            if not isinstance(endpoint, dict):
                raise ValueError("Central Compute returned an invalid socket entry")
            required_text = (
                "name",
                "service",
                "transport",
                "host",
                "direction",
                "security",
                "status",
            )
            if any(
                not isinstance(endpoint.get(field), str)
                for field in required_text
            ) or type(endpoint.get("port")) is not int:
                raise ValueError("Central Compute returned an incomplete socket entry")
            protocols = endpoint.get("protocols")
            if not isinstance(protocols, list) or any(
                not isinstance(protocol, str) for protocol in protocols
            ):
                raise ValueError("Central Compute returned invalid socket protocols")
            sockets.append(
                {
                    field: endpoint[field]
                    for field in required_text
                }
                | {
                    "port": endpoint["port"],
                    "protocols": protocols[:12],
                }
            )

        network = {
            key: value
            for key, value in data["network"].items()
            if key in {"node_count", "zone_count"}
            and type(value) is int
            and value >= 0
        }
        traffic = data.get("traffic_by_protocol", {})
        if not isinstance(traffic, dict):
            raise ValueError("Central Compute returned invalid protocol traffic")
        traffic_by_protocol = {}
        for protocol, metrics in traffic.items():
            if not isinstance(protocol, str) or not isinstance(metrics, dict):
                continue
            traffic_by_protocol[protocol[:80]] = {
                key: value
                for key, value in metrics.items()
                if key
                in {
                    "tx_generated",
                    "tx_delivered",
                    "rx_accepted",
                    "security_event_count",
                }
                and type(value) is int
                and value >= 0
            }

        security_events = data.get("security_events", {})
        if not isinstance(security_events, dict):
            security_events = {}
        category_counts = security_events.get("category_counts", {})
        safe_categories = (
            {
                category[:80]: count
                for category, count in category_counts.items()
                if isinstance(category, str)
                and type(count) is int
                and count >= 0
            }
            if isinstance(category_counts, dict)
            else {}
        )
        uds = {
            key: value
            for key, value in data["uds"].items()
            if key
            in {
                "component_count",
                "successful_count",
                "failed_count",
                "active_dtc_count",
                "timeout_count",
                "timeout_rate_percent",
                "ecu_availability_percent",
                "diagnostic_latency_mean_ms",
                "diagnostic_latency_max_ms",
                "diagnostic_elapsed_ms",
                "sample_precision",
                "supported_service_count",
                "did_count",
                "rid_count",
            }
            and (
                value is None
                or type(value) in (int, float, bool)
                or (key == "sample_precision" and isinstance(value, str))
            )
        }
        response_categories = data["uds"].get("response_categories", {})
        uds["response_categories"] = (
            {
                category[:40]: count
                for category, count in response_categories.items()
                if isinstance(category, str)
                and type(count) is int
                and count >= 0
            }
            if isinstance(response_categories, dict)
            else {}
        )
        return jsonify(
            {
                "observed_at": data.get("observed_at"),
                "network": network,
                "sockets": sockets,
                "traffic_by_protocol": traffic_by_protocol,
                "security_events": {
                    "retained_event_count": security_events.get(
                        "retained_event_count", 0
                    ),
                    "category_counts": safe_categories,
                },
                "uds": uds,
            }
        )
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 503


@app.get("/api/network/activity")
def network_activity():
    try:
        limit_text = request.args.get("limit", "100")
        if not limit_text.isdigit() or not 1 <= int(limit_text) <= 200:
            return jsonify(
                {
                    "status": "error",
                    "message": "limit must be an integer between 1 and 200",
                }
            ), 400
        response = central_request(
            "get",
            f"{CENTRAL_COMPUTE_URL}/network/activity",
            params={"limit": int(limit_text)},
            timeout=10,
        )
        response.raise_for_status()
        data = response.json()
        if not isinstance(data, dict):
            raise ValueError("Central Compute returned invalid network activity")

        allowed_message_fields = {
            "sampled_at_monotonic_ms",
            "source_node_id",
            "received_by_node_id",
            "message_name",
            "message_id",
            "transport_type",
            "direction",
            "sequence",
            "periodicity_ms",
            "signals",
            "socket_id",
            "event_type",
            "timestamp",
            "phase",
            "attack_generated",
            "service_id",
            "method_id",
        }
        sensitive_location_terms = (
            "latitude",
            "longitude",
            "gnssposition",
            "gpsposition",
            "gpslocation",
            "geocoordinate",
            "coordinates",
        )

        def contains_sensitive_location(value: Any) -> bool:
            if not isinstance(value, str):
                return False
            normalized = "".join(
                character for character in value.lower() if character.isalnum()
            )
            return any(term in normalized for term in sensitive_location_terms)

        messages = []
        for message in data.get("messages", []):
            if not isinstance(message, dict):
                continue
            if contains_sensitive_location(message.get("message_name")):
                continue
            safe_message = {
                key: value
                for key, value in message.items()
                if key in allowed_message_fields
                and (
                    value is None
                    or type(value) in (int, float, bool)
                    or (isinstance(value, str) and len(value) <= 160)
                )
            }
            signals = message.get("signals")
            if isinstance(signals, dict):
                safe_message["signals"] = {
                    name[:80]: value
                    for name, value in signals.items()
                    if isinstance(name, str)
                    and not contains_sensitive_location(name)
                    and (
                        value is None
                        or type(value) in (int, float, bool)
                        or (isinstance(value, str) and len(value) <= 120)
                    )
                }
            messages.append(safe_message)

        allowed_event_fields = {
            "event_id",
            "timestamp",
            "node_id",
            "detected_at_node_id",
            "category",
            "severity",
            "detail",
            "action",
            "message_name",
            "observed_message_id",
            "event_type",
            "socket_id",
            "phase",
            "attack_generated",
        }
        events = []
        for event in data.get("security_events", []):
            if not isinstance(event, dict):
                continue
            events.append(
                {
                    key: value
                    for key, value in event.items()
                    if key in allowed_event_fields
                    and not (
                        key in {"message_name", "detail"}
                        and contains_sensitive_location(value)
                    )
                    and (
                        value is None
                        or type(value) in (int, float, bool)
                        or (isinstance(value, str) and len(value) <= 500)
                    )
                }
            )
        allowed_diagnostic_fields = {
            "event_type",
            "timestamp",
            "phase",
            "source_node_id",
            "target_node_id",
            "transport_type",
            "socket_id",
            "direction",
            "message_id",
            "service_id",
            "response_service_id",
            "status",
            "nrc",
            "latency_ms",
            "detail",
        }
        diagnostics = []
        for diagnostic in data.get("diagnostics", []):
            if not isinstance(diagnostic, dict):
                continue
            diagnostics.append(
                {
                    key: value
                    for key, value in diagnostic.items()
                    if key in allowed_diagnostic_fields
                    and (
                        value is None
                        or type(value) in (int, float, bool)
                        or (isinstance(value, str) and len(value) <= 160)
                    )
                }
            )
        allowed_socket_event_fields = {
            "event_id",
            "timestamp",
            "event_type",
            "socket_id",
            "phase",
            "attack_generated",
            "source_node_id",
            "target_node_id",
            "action",
            "transport_type",
            "message_name",
            "message_id",
            "can_id",
            "can_id_hex",
            "dlc",
            "message_length_bytes",
            "frame_index",
            "frame_count",
            "someip_service_id",
            "someip_method_id",
            "packet_length",
            "firmware_version",
            "update_framework",
            "previous_partition",
            "active_partition",
            "detail",
        }
        socket_events = []
        for event in data.get("socket_events", []):
            if not isinstance(event, dict):
                continue
            safe_event = {
                key: value
                for key, value in event.items()
                if key in allowed_socket_event_fields
                and not (
                    key in {"message_name", "detail"}
                    and contains_sensitive_location(value)
                )
                and (
                    value is None
                    or type(value) in (int, float, bool)
                    or (isinstance(value, str) and len(value) <= 500)
                )
            }
            socket_events.append(safe_event)
        return jsonify(
            {
                "observed_at": data.get("observed_at"),
                "messages": messages[:200],
                "security_events": events[:200],
                "diagnostics": diagnostics[:200],
                "socket_events": socket_events[:200],
                "scan_phase": data.get("scan_phase"),
                "scan_phase_updated_at": (
                    data.get("scan_phase_updated_at")
                    if type(data.get("scan_phase_updated_at")) in (int, float)
                    else None
                ),
                "attack_active": data.get("attack_active") is True,
            }
        )
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 503


@app.post("/api/diagnostics/sovd")
def sovd_diagnostics():
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict) or not isinstance(payload.get("component_id"), str):
        return jsonify(
            {"status": "error", "message": "component_id is required"}
        ), 400
    try:
        response = central_request(
            "post",
            f"{CENTRAL_COMPUTE_URL}/sovd/v1/diagnostics",
            json=payload,
            timeout=30,
        )
        if response.status_code < 500:
            return jsonify(response.json()), response.status_code
        response.raise_for_status()
        raise RuntimeError("Central Compute rejected the SOVD diagnostic request")
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 503


@app.post("/api/signals/read")
def read_signal():
    payload = request.get_json(silent=True)
    if (
        not isinstance(payload, dict)
        or not isinstance(payload.get("target_node_id"), str)
        or not isinstance(payload.get("signal_name"), str)
    ):
        return jsonify(
            {
                "status": "error",
                "message": "target_node_id and signal_name are required",
            }
        ), 400
    try:
        response = central_request(
            "post",
            f"{CENTRAL_COMPUTE_URL}/signals/read",
            json=payload,
            timeout=20,
        )
        if response.status_code < 500:
            return jsonify(response.json()), response.status_code
        response.raise_for_status()
        raise RuntimeError("Central Compute rejected the SOME/IP signal request")
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 503


@app.get("/api/signals/catalog")
def get_signal_catalog():
    target_node_id = request.args.get("target_node_id", "")
    if not target_node_id:
        return jsonify(
            {"status": "error", "message": "target_node_id is required"}
        ), 400
    try:
        response = central_request(
            "get",
            f"{CENTRAL_COMPUTE_URL}/signals/catalog",
            params={"target_node_id": target_node_id},
            timeout=10,
        )
        if response.status_code < 500:
            return jsonify(response.json()), response.status_code
        response.raise_for_status()
        raise RuntimeError("Central Compute could not load the SOME/IP signal catalog")
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 503


@app.get("/api/overview")
def get_overview():
    last_scan = latest_saved_scan() or LAST_SCAN
    deps = {}
    try:
        central = central_request(
            "get", f"{CENTRAL_COMPUTE_URL}/health", timeout=5
        )
        deps["vehicle-central-compute"] = central.json() if central.ok else {"status": "unavailable"}
    except Exception as exc:
        deps["vehicle-central-compute"] = {"status": "error", "error": str(exc)}

    try:
        service_response = central_request(
            "get",
            f"{CENTRAL_COMPUTE_URL}/vehicle/service-state", timeout=5
        )
        vehicle_service_state = (
            service_response.json().get("service_state")
            if service_response.ok
            else "unknown"
        )
    except Exception:
        vehicle_service_state = "unknown"

    payload = {
        "service": "cloud-app",
        "status": "ok",
        "vehicle_service_state": vehicle_service_state,
        "risk_level": last_scan.get("risk_level", "unknown"),
        "last_analysis": last_scan.get("summary", "No scan run yet"),
        "last_scan": last_scan,
        "ai_summary": last_scan.get("ai_summary", "AI provider is not configured; deterministic security-rule analysis is available."),
        "dependencies": deps,
    }
    return jsonify(payload)


@app.get("/api/last-scan")
def last_scan():
    return jsonify(latest_saved_scan() or LAST_SCAN)


@app.get("/api/history")
def scan_history():
    try:
        limit = int(request.args.get("limit", "20"))
    except ValueError:
        return jsonify({"status": "error", "message": "limit must be an integer"}), 400
    if not 1 <= limit <= 100:
        return jsonify({"status": "error", "message": "limit must be between 1 and 100"}), 400
    return jsonify({"scans": saved_scans(limit)})


@app.get("/api/fleet/analytics")
def fleet_analytics():
    scans = saved_scans(100)
    risk_counts = {level: 0 for level in ("low", "medium", "high", "critical", "unknown")}
    mode_counts = {}
    attack_counts = {}
    ota_status_counts = {}
    for scan in scans:
        risk = scan.get("risk_level", "unknown")
        risk_counts[risk if risk in risk_counts else "unknown"] += 1
        mode = scan.get("scan_mode", "unknown")
        mode_counts[mode] = mode_counts.get(mode, 0) + 1
        attack = scan.get("attack_type", "unknown")
        attack_counts[attack] = attack_counts.get(attack, 0) + 1
        assurance = scan.get("ota_assurance")
        if isinstance(assurance, dict):
            status = assurance.get("status", "unknown")
            ota_status_counts[status] = ota_status_counts.get(status, 0) + 1
    return jsonify(
        {
            "status": "ok",
            "scope": "simulated_fleet",
            "vehicle_count": 1 if scans else 0,
            "scan_count": len(scans),
            "risk_counts": risk_counts,
            "scan_mode_counts": mode_counts,
            "attack_counts": attack_counts,
            "ota_assurance_counts": ota_status_counts,
            "raw_vehicle_data_shared": False,
        }
    )


@app.get("/api/cves")
def cve_catalog():
    try:
        limit = min(max(int(request.args.get("limit", "100")), 1), 200)
    except ValueError:
        return jsonify({"status": "error", "message": "limit must be an integer"}), 400
    return jsonify(
        {
            "status": "ok",
            "cves": list_cves(request.args.get("q", "")[:200], limit),
        }
    )


@app.post("/api/cves/import")
def import_cve_catalog():
    payload = request.get_json(silent=True)
    records = payload if isinstance(payload, list) else payload.get("vulnerabilities") if isinstance(payload, dict) else None
    if not isinstance(records, list) or len(records) > 10000:
        return jsonify({"status": "error", "message": "Provide a JSON list or vulnerabilities list of at most 10000 records"}), 400
    imported = import_records(records, "operator_import")
    return jsonify({"status": "ok", "imported": imported})


@app.post("/api/cves/sync")
def synchronize_cves():
    payload = request.get_json(silent=True) or {}
    if not isinstance(payload, dict):
        return jsonify({"status": "error", "message": "Request body must be a JSON object"}), 400
    try:
        result = sync_nvd(payload.get("keyword"), int(payload.get("limit", 50)))
    except (requests.RequestException, ValueError) as exc:
        return jsonify({"status": "error", "message": f"CVE synchronization failed: {exc}"}), 502
    return jsonify({"status": "ok", **result})


@app.post("/api/cves/match")
def match_cves():
    payload = request.get_json(silent=True)
    components = payload.get("components") if isinstance(payload, dict) else payload
    if not isinstance(components, list) or len(components) > 1000:
        return jsonify({"status": "error", "message": "components must be a list of at most 1000 items"}), 400
    return jsonify({"status": "ok", "matches": match_components(components)})


@app.get("/api/evidence/latest")
def latest_evidence():
    evidence = latest_saved_scan()
    return jsonify({"status": "ok", "evidence": evidence})


@app.get("/api/report/latest")
def latest_threat_report():
    latest = latest_saved_scan()
    audience = request.args.get("audience", "technician")
    if audience not in {"owner", "technician", "oem"}:
        return jsonify({"status": "error", "message": "audience must be owner, technician, or oem"}), 400
    if latest is None:
        report = {}
    elif audience == "owner":
        report = {
            "audience": audience,
            "status": latest.get("risk_level", "unknown"),
            "summary": (
                "Your vehicle needs a cybersecurity service review."
                if latest.get("risk_level") in {"high", "critical"}
                else "No high-severity cybersecurity issue was reported by this simulator assessment."
            ),
            "physical_hardware_tested": False,
            "raw_vehicle_data_shared": False,
        }
    elif audience == "oem":
        report = {
            "audience": audience,
            "scan": latest,
            "ota_assurance": latest.get("ota_assurance", {}),
            "threat_report": latest.get("threat_report", {}),
        }
    else:
        report = {
            "audience": audience,
            "status": latest.get("risk_level", "unknown"),
            "summary": latest.get("summary", ""),
            "recommended_action": latest.get("alert_action", "review"),
            "ota_assurance": latest.get("ota_assurance", {}),
            "threat_report": latest.get("threat_report", {}),
        }
    return jsonify(
        {
            "status": "ok",
            "report": report,
            "scan_id": latest.get("scan_id") if latest else None,
        }
    )


@app.get("/api/report/<scan_id>")
def threat_report(scan_id: str):
    if not scan_id or len(scan_id) > 64:
        return jsonify({"status": "error", "message": "Invalid scan ID"}), 400
    record = saved_scan(scan_id)
    if record is None:
        return jsonify({"status": "not_found", "message": "Scan report was not found"}), 404
    audience = request.args.get("audience", "technician")
    if audience not in {"owner", "technician", "oem"}:
        return jsonify({"status": "error", "message": "audience must be owner, technician, or oem"}), 400
    assurance = record.get("ota_assurance", {})
    if audience == "owner":
        report = {
            "audience": audience,
            "status": record.get("risk_level", "unknown"),
            "summary": (
                "Your vehicle needs a cybersecurity service review."
                if record.get("risk_level") in {"high", "critical"}
                else "No high-severity cybersecurity issue was reported by this simulator assessment."
            ),
            "physical_hardware_tested": False,
            "raw_vehicle_data_shared": False,
        }
    elif audience == "technician":
        report = {
            "audience": audience,
            "status": record.get("risk_level", "unknown"),
            "summary": record.get("summary", ""),
            "recommended_action": record.get("alert_action", "review"),
            "ota_assurance": assurance,
            "threat_report": record.get("threat_report", {}),
        }
    else:
        report = {
            "audience": audience,
            "scan": record,
            "ota_assurance": assurance,
            "threat_report": record.get("threat_report", {}),
        }
    return jsonify(
        {
            "status": "ok",
            "report": report,
            "scan_id": record.get("scan_id"),
        }
    )


@app.get("/api/evidence/<scan_id>")
def scan_evidence(scan_id: str):
    if not scan_id or len(scan_id) > 64:
        return jsonify({"status": "error", "message": "Invalid scan ID"}), 400
    evidence = saved_scan(scan_id)
    if evidence is None:
        return jsonify({"status": "not_found", "message": "Scan evidence was not found"}), 404
    return jsonify({"status": "ok", "evidence": evidence})


@app.post("/api/vehicle/service-state")
def update_vehicle_service_state():
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"status": "error", "message": "Request body must be a JSON object"}), 400
    service_state = payload.get("service_state")
    if not isinstance(service_state, str) or service_state not in {"in_service", "out_of_service"}:
        return jsonify(
            {
                "status": "error",
                "message": "service_state must be in_service or out_of_service",
            }
        ), 400
    try:
        response = central_request(
            "post",
            f"{CENTRAL_COMPUTE_URL}/vehicle/service-state",
            json={"service_state": service_state},
            timeout=10,
        )
        response.raise_for_status()
        return jsonify(response.json())
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 503


@app.post("/api/ota/flash")
def trigger_ota_flash():
    package = request.get_json(silent=True)
    if not isinstance(package, dict):
        return jsonify(
            {"status": "error", "message": "Request body must be an OTA package object"}
        ), 400
    image_hex = package.get("image_hex")
    if not isinstance(image_hex, str) or len(image_hex) > 2_097_152:
        return jsonify(
            {"status": "error", "message": "image_hex must encode a firmware image of at most 1 MiB"}
        ), 400
    try:
        response = central_request(
            "post",
            f"{CENTRAL_COMPUTE_URL}/ota/flash",
            json=package,
            timeout=195,
        )
        if response.status_code in {400, 403, 409, 422}:
            return jsonify(response.json()), response.status_code
        response.raise_for_status()
        result = response.json()
        if not isinstance(result, dict):
            raise ValueError("Central Compute returned an invalid OTA response")
        return jsonify(result), 200 if result.get("status") == "completed" else 422
    except requests.RequestException as exc:
        return jsonify({"status": "error", "message": f"OTA relay failed: {exc}"}), 503
    except (ValueError, json.JSONDecodeError) as exc:
        return jsonify({"status": "error", "message": str(exc)}), 502


@app.post("/api/scan/start")
def trigger_scan():
    payload = request.get_json(silent=True)
    if not isinstance(payload, dict):
        return jsonify({"status": "error", "message": "Request body must be a JSON object"}), 400
    attack_type = payload.get("attack_type")
    severity = payload.get("severity")
    scan_mode = payload.get("scan_mode", "oem_validation")
    duration_seconds = payload.get("duration_seconds", 10)
    target_node_ids = payload.get("target_node_ids")
    run_baseline_checks = payload.get("run_baseline_checks", True)

    if not isinstance(attack_type, str) or attack_type not in ATTACK_LIBRARY:
        return jsonify({"status": "error", "message": f"Unsupported attack type: {attack_type}"}), 400
    if not isinstance(severity, str) or severity not in SEVERITIES:
        return jsonify({"status": "error", "message": f"Unsupported severity: {severity}"}), 400
    if scan_mode not in SCAN_MODES:
        return jsonify({"status": "error", "message": f"Unsupported scan_mode: {scan_mode}"}), 400
    severity_rank = {"low": 0, "medium": 1, "high": 2, "critical": 3}
    policy = SCAN_MODES[scan_mode]
    if attack_type in policy["blocked_attacks"] or severity_rank[severity] > severity_rank[policy["max_severity"]]:
        return jsonify(
            {
                "status": "rejected",
                "message": f"{attack_type} at {severity} is not permitted in {scan_mode} mode",
            }
        ), 409
    if type(duration_seconds) is not int or not 1 <= duration_seconds <= 60:
        return jsonify(
            {
                "status": "error",
                "message": "duration_seconds must be an integer between 1 and 60",
            }
        ), 400
    if type(run_baseline_checks) is not bool:
        return jsonify(
            {"status": "error", "message": "run_baseline_checks must be a boolean"}
        ), 400
    if target_node_ids is not None and (
        not isinstance(target_node_ids, list)
        or not target_node_ids
        or len(target_node_ids) > 64
        or any(not isinstance(node_id, str) for node_id in target_node_ids)
        or len(target_node_ids) != len(set(target_node_ids))
    ):
        return jsonify(
            {
                "status": "error",
                "message": "target_node_ids must be a non-empty list of unique node IDs",
            }
        ), 400

    try:
        service_response = central_request(
            "get",
            f"{CENTRAL_COMPUTE_URL}/vehicle/service-state",
            timeout=5,
        )
        service_response.raise_for_status()
        service_data = service_response.json()
        service_state = (
            service_data.get("service_state")
            if isinstance(service_data, dict)
            else None
        )
        if service_state != "in_service":
            return jsonify(
                {
                    "status": "rejected",
                    "message": "Vehicle security scans can only start while the vehicle is in service.",
                    "service_state": service_state or "unknown",
                }
            ), 409

        response = central_request(
            "post",
            f"{CENTRAL_COMPUTE_URL}/scan/start",
            json={
                "attack_type": attack_type,
                "severity": severity,
                "scan_mode": scan_mode,
                "duration_seconds": duration_seconds,
                "run_baseline_checks": run_baseline_checks,
                **(
                    {"target_node_ids": target_node_ids}
                    if target_node_ids is not None
                    else {}
                ),
            },
            timeout=duration_seconds + SCAN_TIMEOUT_MARGIN_SECONDS,
        )
        if response.status_code == 409:
            return jsonify(response.json()), 409
        if 400 <= response.status_code < 500:
            return jsonify(response.json()), response.status_code
        response.raise_for_status()
        result = response.json()
        if not isinstance(result, dict):
            raise ValueError("Central Compute returned an invalid scan evidence response")
        record = save_scan(
            {
                "risk_level": result.get("risk_level", "unknown"),
                "summary": result.get("summary", "Scan completed."),
                "attack_type": attack_type,
                "severity": severity,
                "duration_seconds": duration_seconds,
                "scan_status": result.get("status", "unknown"),
                "ai_summary": (
                    f"Rule-based analysis found a {result.get('risk_level', 'unknown')} "
                    f"risk profile for {attack_type}; raw vehicle data is not shared."
                ),
                "alert_action": result.get("alert_action"),
                "ml_models": result.get("ml_models", {}),
                "test_session_id": result.get("test_session_id"),
                "pseudonym_scope": result.get("pseudonym_scope"),
                "assessment_purpose": result.get("assessment_purpose"),
                "test_scenario_id": result.get("test_scenario_id"),
                "started_at": result.get("started_at"),
                "ended_at": result.get("ended_at"),
                "timestamp_precision": result.get("timestamp_precision"),
                "attack_started_at": result.get("attack_started_at"),
                "attack_ended_at": result.get("attack_ended_at"),
                "test_execution_result": result.get("test_execution_result"),
                "security_assessment_result": result.get(
                    "security_assessment_result"
                ),
                "recovery_status": result.get("recovery_status"),
                "confidence_status": result.get("confidence_status"),
                "diagnostic_coverage_percent": result.get(
                    "diagnostic_coverage_percent"
                ),
                "evidence_references": result.get("evidence_references", []),
                "cloud_region": os.getenv("CLOUD_REGION", "unspecified"),
                "attack_summary": result.get("attack_summary", {}),
                "probe_summary": result.get("probe_summary", {}),
                "target_summary": result.get("target_summary", {}),
                "baseline_model": result.get("baseline_model", {}),
                "threat_report": {},
                "during_attack": result.get("during_attack", {}),
                "before_attack": result.get("before_attack", {}),
                "after_attack": result.get("after_attack", {}),
                "comparison": result.get("comparison", {}),
                "ota_assurance": result.get("ota_assurance", {}),
            }
        )
        threat_report = _THREAT_EXPLAINER.create_threat_report(record)
        record["threat_report"] = _sanitize_threat_report(threat_report)
        record["ai_summary"] = threat_report.get(
            "executive_summary", record["ai_summary"]
        )
        with closing(sqlite3.connect(history_db_path())) as connection:
            with connection:
                connection.execute(
                    "UPDATE scan_history SET record_json = ? WHERE scan_id = ?",
                    (encrypt_record(record), record["scan_id"]),
                )
        LAST_SCAN.update(record)
        return jsonify(
            {
                "status": "accepted",
                "cloud_app": "cloud-app",
                "scan": record,
                "result": record,
            }
        )
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 503


@app.post("/api/scan/stop")
def stop_scan():
    try:
        response = central_request(
            "post",
            f"{CENTRAL_COMPUTE_URL}/scan/stop",
            timeout=10,
        )
        if response.status_code == 409:
            return jsonify(response.json()), 409
        response.raise_for_status()
        return jsonify(response.json()), response.status_code
    except Exception as exc:
        return jsonify({"status": "error", "message": str(exc)}), 503


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=PORT, debug=os.getenv("FLASK_DEBUG", "0") == "1")
