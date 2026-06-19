from __future__ import annotations

import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path

from seevie_pri.context import Component, RankedFinding

DEFAULT_DB_PATH = Path.home() / ".seevie-pri" / "seevie.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS sboms (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    ecosystem TEXT NOT NULL DEFAULT '',
    sbom_path TEXT NOT NULL,
    indexed_at TEXT NOT NULL
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
    scanned_at TEXT NOT NULL
);
"""


def init_db(db_path: Path = DEFAULT_DB_PATH) -> sqlite3.Connection:
    db_path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(db_path), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    return conn


def store_sbom(conn: sqlite3.Connection, name: str, ecosystem: str,
               sbom_path: str) -> str:
    sbom_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc).isoformat()
    conn.execute(
        "INSERT INTO sboms (id, name, ecosystem, sbom_path, indexed_at) VALUES (?, ?, ?, ?, ?)",
        (sbom_id, name, ecosystem, sbom_path, now),
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
                   findings: list[RankedFinding]) -> None:
    now = datetime.now(timezone.utc).isoformat()
    conn.executemany(
        "INSERT INTO findings (sbom_id, cve_id, severity, component, version, "
        "fixed_version, topology_score, compatibility_score, combined_score, "
        "upgrade_path, action, scanned_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
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
                now,
            )
            for f in findings
        ],
    )
    conn.commit()


def get_findings(conn: sqlite3.Connection, severity: str | None = None,
                 min_score: float | None = None) -> list[dict]:
    query = (
        "SELECT f.*, s.name as sbom_name FROM findings f "
        "JOIN sboms s ON f.sbom_id = s.id WHERE 1=1"
    )
    params: list = []
    if severity:
        query += " AND f.severity = ?"
        params.append(severity)
    if min_score is not None:
        query += " AND f.combined_score >= ?"
        params.append(min_score)
    query += " ORDER BY f.combined_score DESC"
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
