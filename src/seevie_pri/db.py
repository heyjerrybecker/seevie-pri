from __future__ import annotations

import logging
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path

import httpx

from seevie_pri.context import Component, RankedFinding

logger = logging.getLogger(__name__)

DEFAULT_DB_PATH = Path.home() / ".seevie-pri" / "seevie.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS sboms (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    ecosystem TEXT NOT NULL DEFAULT '',
    sbom_path TEXT NOT NULL,
    indexed_at TEXT NOT NULL,
    business_value REAL NOT NULL DEFAULT 1000000
);

CREATE TABLE IF NOT EXISTS components (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sbom_id TEXT NOT NULL REFERENCES sboms(id),
    name TEXT NOT NULL,
    version TEXT NOT NULL DEFAULT '',
    ecosystem TEXT NOT NULL DEFAULT '',
    purl TEXT,
    direct BOOLEAN NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    sbom_id TEXT NOT NULL REFERENCES sboms(id),
    cve_id TEXT NOT NULL,
    severity TEXT NOT NULL DEFAULT 'UNKNOWN',
    component TEXT NOT NULL,
    version TEXT NOT NULL DEFAULT '',
    fixed_version TEXT,
    topology_score REAL NOT NULL DEFAULT 0,
    compatibility_score REAL NOT NULL DEFAULT 0,
    combined_score REAL NOT NULL DEFAULT 0,
    upgrade_path TEXT NOT NULL DEFAULT 'unknown',
    action TEXT NOT NULL DEFAULT '',
    epss_score REAL NOT NULL DEFAULT 0,
    financial_risk REAL NOT NULL DEFAULT 0,
    scanned_at TEXT NOT NULL
);
"""


def init_db(db_path: Path = DEFAULT_DB_PATH) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    for col, default in [
        ("business_value", "1000000"),
        ("epss_score", "0"),
        ("financial_risk", "0"),
    ]:
        try:
            table = "sboms" if col == "business_value" else "findings"
            conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} REAL NOT NULL DEFAULT {default}")
        except sqlite3.OperationalError:
            pass
    return conn


def store_sbom(conn: sqlite3.Connection, name: str, ecosystem: str,
               sbom_path: str, business_value: float = 1_000_000) -> str:
    existing = conn.execute(
        "SELECT id FROM sboms WHERE name = ?", (name,)
    ).fetchone()

    now = datetime.now(timezone.utc).isoformat()

    if existing:
        sbom_id = existing["id"]
        conn.execute("DELETE FROM components WHERE sbom_id = ?", (sbom_id,))
        conn.execute("DELETE FROM findings WHERE sbom_id = ?", (sbom_id,))
        conn.execute(
            "UPDATE sboms SET ecosystem = ?, sbom_path = ?, indexed_at = ?, business_value = ? WHERE id = ?",
            (ecosystem, sbom_path, now, business_value, sbom_id),
        )
    else:
        sbom_id = str(uuid.uuid4())
        conn.execute(
            "INSERT INTO sboms (id, name, ecosystem, sbom_path, indexed_at, business_value) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (sbom_id, name, ecosystem, sbom_path, now, business_value),
        )

    conn.commit()
    return sbom_id


def store_components(conn: sqlite3.Connection, sbom_id: str,
                     components: list[Component]) -> None:
    conn.executemany(
        "INSERT INTO components (sbom_id, name, version, ecosystem, purl, direct) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        [(sbom_id, c.name, c.version, c.ecosystem, c.purl, c.direct) for c in components],
    )
    conn.commit()


def list_sboms(conn: sqlite3.Connection) -> list[dict]:
    rows = conn.execute(
        "SELECT s.id, s.name, s.ecosystem, s.sbom_path, s.indexed_at, "
        "COUNT(c.id) as component_count "
        "FROM sboms s LEFT JOIN components c ON s.id = c.sbom_id "
        "GROUP BY s.id ORDER BY s.indexed_at DESC"
    ).fetchall()
    return [dict(r) for r in rows]


def store_findings(conn: sqlite3.Connection, sbom_id: str,
                   findings: list[RankedFinding],
                   epss_scores: dict[str, float] | None = None,
                   business_value: float = 1_000_000) -> None:
    if epss_scores is None:
        epss_scores = {}
    severity_defaults = {"CRITICAL": 0.7, "HIGH": 0.4, "MEDIUM": 0.15, "MODERATE": 0.15, "LOW": 0.05}
    now = datetime.now(timezone.utc).isoformat()
    conn.executemany(
        "INSERT INTO findings (sbom_id, cve_id, severity, component, version, "
        "fixed_version, topology_score, compatibility_score, combined_score, "
        "upgrade_path, action, epss_score, financial_risk, scanned_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        [
            (
                sbom_id,
                f.scored.match.cve_id,
                f.scored.match.severity,
                f.scored.match.affected_component.name,
                f.scored.match.affected_component.version,
                f.scored.match.fixed_version,
                f.scored.topology_score,
                f.scored.compatibility_score,
                f.scored.combined_score,
                f.upgrade_path,
                f.action,
                epss_scores.get(f.scored.match.cve_id,
                                severity_defaults.get(f.scored.match.severity, 0.1)),
                round(epss_scores.get(f.scored.match.cve_id,
                                      severity_defaults.get(f.scored.match.severity, 0.1))
                      * f.scored.combined_score * business_value, 2),
                now,
            )
            for f in findings
        ],
    )
    conn.commit()


def get_findings(conn: sqlite3.Connection, severity: str | None = None,
                 min_score: float | None = None) -> list[dict]:
    query = (
        "SELECT f.*, s.name as sbom_name, "
        "(SELECT COUNT(DISTINCT f2.sbom_id) FROM findings f2 WHERE f2.cve_id = f.cve_id) "
        "as blast_radius "
        "FROM findings f "
        "JOIN sboms s ON f.sbom_id = s.id WHERE 1=1"
    )
    params: list = []
    if severity:
        query += " AND f.severity = ?"
        params.append(severity)
    if min_score is not None:
        query += " AND f.combined_score >= ?"
        params.append(min_score)
    query += " ORDER BY blast_radius DESC, f.combined_score DESC"
    rows = conn.execute(query, params).fetchall()
    return [dict(r) for r in rows]


def get_findings_for_sbom(conn: sqlite3.Connection, sbom_id: str) -> list[dict]:
    rows = conn.execute(
        "SELECT f.*, s.name as sbom_name FROM findings f "
        "JOIN sboms s ON f.sbom_id = s.id "
        "WHERE f.sbom_id = ? ORDER BY f.combined_score DESC",
        (sbom_id,),
    ).fetchall()
    return [dict(r) for r in rows]


def clear_findings(conn: sqlite3.Connection) -> None:
    conn.execute("DELETE FROM findings")
    conn.commit()


def get_summary(conn: sqlite3.Connection) -> dict:
    total = conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
    high_risk = conn.execute(
        "SELECT COUNT(*) FROM findings WHERE severity IN ('HIGH', 'CRITICAL')"
    ).fetchone()[0]
    services = conn.execute("SELECT COUNT(*) FROM sboms").fetchone()[0]
    critical = conn.execute(
        "SELECT COUNT(*) FROM findings WHERE severity = 'CRITICAL'"
    ).fetchone()[0]

    severity_rows = conn.execute(
        "SELECT severity, COUNT(*) as cnt FROM findings GROUP BY severity"
    ).fetchall()
    severity_counts = {row["severity"]: row["cnt"] for row in severity_rows}

    total_exposure = conn.execute(
        "SELECT COALESCE(SUM(financial_risk), 0) FROM findings"
    ).fetchone()[0]

    service_rows = conn.execute(
        "SELECT s.id, s.name, s.ecosystem, s.business_value, "
        "COUNT(f.id) as finding_count, "
        "COALESCE(SUM(f.financial_risk), 0) as exposure, "
        "MAX(CASE f.severity "
        "  WHEN 'CRITICAL' THEN 4 WHEN 'HIGH' THEN 3 "
        "  WHEN 'MEDIUM' THEN 2 WHEN 'LOW' THEN 1 ELSE 0 END) as worst "
        "FROM sboms s LEFT JOIN findings f ON s.id = f.sbom_id "
        "GROUP BY s.id ORDER BY exposure DESC"
    ).fetchall()

    severity_labels = {4: "CRITICAL", 3: "HIGH", 2: "MEDIUM", 1: "LOW", 0: "UNKNOWN"}
    service_findings = [
        {
            "id": r["id"],
            "name": r["name"],
            "ecosystem": r["ecosystem"],
            "business_value": r["business_value"],
            "finding_count": r["finding_count"],
            "exposure": r["exposure"],
            "worst_severity": severity_labels.get(r["worst"] or 0, "UNKNOWN"),
        }
        for r in service_rows
    ]

    return {
        "total_findings": total,
        "high_risk": high_risk,
        "services": services,
        "critical": critical,
        "total_exposure": total_exposure,
        "severity_counts": severity_counts,
        "service_findings": service_findings,
    }


def fetch_epss_scores(cve_ids: list[str]) -> dict[str, float]:
    cve_format = [c for c in cve_ids if c.startswith("CVE-")]
    if not cve_format:
        return {}
    try:
        resp = httpx.get(
            "https://api.first.org/data/v1/epss",
            params={"cve": ",".join(cve_format[:100])},
            timeout=15,
        )
        resp.raise_for_status()
        data = resp.json()
        return {
            entry["cve"]: float(entry["epss"])
            for entry in data.get("data", [])
        }
    except Exception:
        logger.warning("EPSS lookup failed, using severity-based defaults")
        return {}
