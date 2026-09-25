"""
Janus Backend — SQLite Audit History & Compliance Trends
=========================================================
Persistent audit ledger for evaluated PCAP captures and compliance scores.
Enables historical tracking, trend visualization, and compliance auditing.
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
import sqlite3
from typing import Any, Optional

log = logging.getLogger("janus.database")

DEFAULT_DB_PATH = Path(__file__).resolve().parent.parent / "captures" / "janus_audit_history.db"


def get_db_path(custom_path: Optional[str | Path] = None) -> Path:
    """Resolve database path from argument, environment variable, or default location."""
    if custom_path:
        p = Path(custom_path)
    elif "JANUS_DB_PATH" in os.environ:
        p = Path(os.environ["JANUS_DB_PATH"])
    else:
        p = DEFAULT_DB_PATH
    p.parent.mkdir(parents=True, exist_ok=True)
    return p


def get_connection(db_path: Optional[str | Path] = None) -> sqlite3.Connection:
    """Create a new SQLite connection with row factory configured."""
    path = get_db_path(db_path)
    conn = sqlite3.connect(str(path), timeout=30.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    return conn


def init_db(db_path: Optional[str | Path] = None) -> None:
    """Initialize database schema with tables and indexes."""
    with get_connection(db_path) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS audit_records (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                capture_id TEXT UNIQUE NOT NULL,
                filename TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                overall_score REAL,
                grade TEXT,
                status TEXT,
                pqc_status TEXT,
                total_flows INTEGER,
                findings_count INTEGER,
                traffic_breakdown_json TEXT,
                results_json TEXT
            );
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_audit_created_at 
            ON audit_records(created_at DESC);
        """)
        conn.commit()


def record_audit(
    capture_id: str,
    filename: str,
    results: dict[str, Any],
    db_path: Optional[str | Path] = None,
) -> int:
    """
    Record or update an audit entry in SQLite.
    Returns the primary key row id.
    """
    try:
        init_db(db_path)

        # Extract high-level summary fields
        compliance = results.get("compliance") or {}
        score = compliance.get("overall_score")
        if score is not None:
            try:
                score = float(score)
            except (ValueError, TypeError):
                score = None

        grade = compliance.get("grade") or "N/A"
        status = results.get("status") or ("INDETERMINATE" if score is None else "DONE")
        pqc_status = compliance.get("pqc_status") or "CRQC_VULNERABLE"
        total_flows = int(results.get("total_flows") or len(results.get("flows") or []))
        findings_count = len(compliance.get("findings") or [])
        traffic_distribution = results.get("traffic_distribution") or {}

        traffic_json = json.dumps(traffic_distribution)
        results_json = json.dumps(results)

        with get_connection(db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO audit_records (
                    capture_id, filename, overall_score, grade, status,
                    pqc_status, total_flows, findings_count,
                    traffic_breakdown_json, results_json
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(capture_id) DO UPDATE SET
                    filename=excluded.filename,
                    overall_score=excluded.overall_score,
                    grade=excluded.grade,
                    status=excluded.status,
                    pqc_status=excluded.pqc_status,
                    total_flows=excluded.total_flows,
                    findings_count=excluded.findings_count,
                    traffic_breakdown_json=excluded.traffic_breakdown_json,
                    results_json=excluded.results_json,
                    created_at=CURRENT_TIMESTAMP
                """,
                (
                    capture_id,
                    filename,
                    score,
                    grade,
                    status,
                    pqc_status,
                    total_flows,
                    findings_count,
                    traffic_json,
                    results_json,
                ),
            )
            conn.commit()
            return cursor.lastrowid or 0
    except Exception as exc:
        log.warning("Failed to record audit in SQLite database: %s", exc)
        return 0


def get_audit_history(
    limit: int = 50,
    offset: int = 0,
    db_path: Optional[str | Path] = None,
) -> list[dict[str, Any]]:
    """Retrieve paginated audit history records (newest first)."""
    init_db(db_path)
    with get_connection(db_path) as conn:
        rows = conn.execute(
            """
            SELECT id, capture_id, filename, created_at, overall_score,
                   grade, status, pqc_status, total_flows, findings_count,
                   traffic_breakdown_json
            FROM audit_records
            ORDER BY created_at DESC, id DESC
            LIMIT ? OFFSET ?
            """,
            (limit, offset),
        ).fetchall()

        records = []
        for r in rows:
            rec = dict(r)
            try:
                rec["traffic_breakdown"] = json.loads(rec.pop("traffic_breakdown_json") or "{}")
            except Exception:
                rec["traffic_breakdown"] = {}
            records.append(rec)
        return records


def get_compliance_trend(db_path: Optional[str | Path] = None) -> list[dict[str, Any]]:
    """Retrieve chronological compliance score trend for visualization (oldest to newest)."""
    init_db(db_path)
    with get_connection(db_path) as conn:
        rows = conn.execute(
            """
            SELECT capture_id, filename, created_at, overall_score, grade, status, pqc_status
            FROM audit_records
            ORDER BY created_at ASC, id ASC
            """
        ).fetchall()
        return [dict(r) for r in rows]


def get_audit_by_id(
    capture_id: str,
    db_path: Optional[str | Path] = None,
) -> Optional[dict[str, Any]]:
    """Retrieve single full audit record by capture_id including results_json."""
    init_db(db_path)
    with get_connection(db_path) as conn:
        row = conn.execute(
            """
            SELECT id, capture_id, filename, created_at, overall_score,
                   grade, status, pqc_status, total_flows, findings_count,
                   traffic_breakdown_json, results_json
            FROM audit_records
            WHERE capture_id = ?
            """,
            (capture_id,),
        ).fetchone()

        if not row:
            return None

        rec = dict(row)
        try:
            rec["traffic_breakdown"] = json.loads(rec.pop("traffic_breakdown_json") or "{}")
        except Exception:
            rec["traffic_breakdown"] = {}

        try:
            rec["results"] = json.loads(rec.pop("results_json") or "{}")
        except Exception:
            rec["results"] = {}

        return rec


def delete_audit_record(
    capture_id: str,
    db_path: Optional[str | Path] = None,
) -> bool:
    """Delete an audit record by capture_id. Returns True if deleted."""
    init_db(db_path)
    with get_connection(db_path) as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM audit_records WHERE capture_id = ?", (capture_id,))
        conn.commit()
        return cursor.rowcount > 0
