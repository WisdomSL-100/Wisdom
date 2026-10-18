"""Small local CVE store with import, search, and bounded NVD synchronization."""

from __future__ import annotations

import json
import os
import sqlite3
from contextlib import closing
from datetime import datetime, timezone
from typing import Any, Iterable

import requests


def database_path() -> str:
    data_dir = os.getenv("DATA_DIR", os.path.join(os.path.dirname(__file__), "data"))
    os.makedirs(data_dir, exist_ok=True)
    return os.path.join(data_dir, "cve_catalog.sqlite3")


def ensure_database() -> None:
    with closing(sqlite3.connect(database_path())) as connection:
        with connection:
            connection.execute(
                """CREATE TABLE IF NOT EXISTS cves (
                    cve_id TEXT PRIMARY KEY,
                    description TEXT NOT NULL,
                    severity TEXT,
                    cvss_score REAL,
                    published TEXT,
                    last_modified TEXT,
                    affected_json TEXT NOT NULL,
                    source TEXT NOT NULL,
                    imported_at TEXT NOT NULL
                )"""
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS cves_severity ON cves(severity)"
            )


def _severity_from_metrics(metrics: dict[str, Any]) -> tuple[str | None, float | None]:
    for key in ("cvssMetricV40", "cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if not isinstance(entries, list) or not entries:
            continue
        metric = entries[0]
        if not isinstance(metric, dict):
            continue
        data = metric.get("cvssData", {})
        if not isinstance(data, dict):
            continue
        severity = data.get("baseSeverity") or metric.get("baseSeverity")
        score = data.get("baseScore")
        return (
            str(severity).lower() if isinstance(severity, str) else None,
            float(score) if isinstance(score, (int, float)) else None,
        )
    return None, None


def _normalize_record(raw: dict[str, Any], source: str) -> dict[str, Any] | None:
    cve = raw.get("cve") if isinstance(raw.get("cve"), dict) else raw
    cve_id = cve.get("id") or raw.get("cve_id")
    if not isinstance(cve_id, str) or not cve_id.startswith("CVE-"):
        return None
    descriptions = cve.get("descriptions", [])
    description = next(
        (
            item.get("value")
            for item in descriptions
            if isinstance(item, dict) and item.get("lang") == "en"
        ),
        None,
    )
    description = description or cve.get("description") or "No description provided."
    severity, score = _severity_from_metrics(cve.get("metrics", {}))
    if severity is None:
        severity = raw.get("severity")
    if score is None and isinstance(raw.get("cvss_score"), (int, float)):
        score = float(raw["cvss_score"])
    configurations = cve.get("configurations", raw.get("affected", []))
    return {
        "cve_id": cve_id,
        "description": str(description)[:20000],
        "severity": str(severity).lower() if severity else None,
        "cvss_score": score,
        "published": cve.get("published") or raw.get("published"),
        "last_modified": cve.get("lastModified") or raw.get("last_modified"),
        "affected_json": json.dumps(configurations, separators=(",", ":"))[:200000],
        "source": source,
        "imported_at": datetime.now(timezone.utc).isoformat(),
    }


def import_records(records: Iterable[dict[str, Any]], source: str) -> int:
    ensure_database()
    normalized = [
        record
        for raw in records
        if isinstance(raw, dict)
        for record in [_normalize_record(raw, source)]
        if record is not None
    ]
    with closing(sqlite3.connect(database_path())) as connection:
        with connection:
            connection.executemany(
                """INSERT INTO cves
                (cve_id, description, severity, cvss_score, published, last_modified,
                 affected_json, source, imported_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(cve_id) DO UPDATE SET
                  description=excluded.description,
                  severity=excluded.severity,
                  cvss_score=excluded.cvss_score,
                  published=excluded.published,
                  last_modified=excluded.last_modified,
                  affected_json=excluded.affected_json,
                  source=excluded.source,
                  imported_at=excluded.imported_at""",
                [
                    (
                        item["cve_id"],
                        item["description"],
                        item["severity"],
                        item["cvss_score"],
                        item["published"],
                        item["last_modified"],
                        item["affected_json"],
                        item["source"],
                        item["imported_at"],
                    )
                    for item in normalized
                ],
            )
    return len(normalized)


def list_cves(query: str = "", limit: int = 100) -> list[dict[str, Any]]:
    ensure_database()
    query_like = f"%{query}%"
    with closing(sqlite3.connect(database_path())) as connection:
        connection.row_factory = sqlite3.Row
        rows = connection.execute(
            """SELECT cve_id, description, severity, cvss_score, published,
                      last_modified, source
               FROM cves
               WHERE ? = '' OR cve_id LIKE ? OR description LIKE ? OR affected_json LIKE ?
               ORDER BY COALESCE(published, last_modified) DESC
               LIMIT ?""",
            (query, query_like, query_like, query_like, limit),
        ).fetchall()
    return [dict(row) for row in rows]


def match_components(components: list[dict[str, Any]], limit: int = 200) -> list[dict[str, Any]]:
    matches = []
    for component in components:
        name = component.get("name")
        version = component.get("version")
        if not isinstance(name, str) or not name:
            continue
        query = f"%{name}%"
        ensure_database()
        with closing(sqlite3.connect(database_path())) as connection:
            connection.row_factory = sqlite3.Row
            rows = connection.execute(
                """SELECT cve_id, description, severity, cvss_score, published, source
                   FROM cves
                   WHERE affected_json LIKE ? OR description LIKE ?
                   LIMIT ?""",
                (query, query, limit),
            ).fetchall()
        for row in rows:
            matches.append({"component": component, "cve": dict(row), "version_checked": version})
    return matches[:limit]


def sync_nvd(keyword: str | None = None, limit: int = 50) -> dict[str, Any]:
    limit = min(max(limit, 1), 200)
    params: dict[str, Any] = {"resultsPerPage": limit}
    if keyword:
        params["keywordSearch"] = keyword[:200]
    response = requests.get(
        "https://services.nvd.nist.gov/rest/json/cves/2.0",
        params=params,
        timeout=30,
    )
    response.raise_for_status()
    payload = response.json()
    vulnerabilities = payload.get("vulnerabilities", [])
    imported = import_records(vulnerabilities, "nvd")
    return {
        "source": "nvd",
        "requested": limit,
        "received": len(vulnerabilities),
        "imported": imported,
        "total_results": payload.get("totalResults"),
    }
