"""
SQLite database manager for VulnScan Pro.

Handles all persistence for scan history, port results, and vulnerabilities.
Thread-safe via per-call connections to avoid sharing sqlite3 connections
across threads.
"""
from __future__ import annotations

import json
import sqlite3
import uuid
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Generator, List, Optional

from utils.logger import logger

DB_PATH = Path(__file__).resolve().parent.parent / "vulnscan.db"


@contextmanager
def _get_conn() -> Generator[sqlite3.Connection, None, None]:
    """Yield a database connection and commit/rollback automatically."""
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db() -> None:
    """Create all tables if they do not already exist."""
    with _get_conn() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS scans (
                id          TEXT    PRIMARY KEY,
                name        TEXT    NOT NULL,
                target      TEXT    NOT NULL,
                scan_date   TEXT    NOT NULL,
                status      TEXT    NOT NULL DEFAULT 'running',
                total_hosts INTEGER NOT NULL DEFAULT 0,
                open_ports  INTEGER NOT NULL DEFAULT 0,
                total_vulns INTEGER NOT NULL DEFAULT 0,
                risk_score  REAL    NOT NULL DEFAULT 0.0,
                config_json TEXT    NOT NULL DEFAULT '{}'
            );

            CREATE TABLE IF NOT EXISTS port_results (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id     TEXT    NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                host        TEXT    NOT NULL,
                port        INTEGER NOT NULL,
                status      TEXT    NOT NULL,
                service     TEXT    NOT NULL DEFAULT '',
                product     TEXT    NOT NULL DEFAULT '',
                version     TEXT    NOT NULL DEFAULT '',
                banner      TEXT    NOT NULL DEFAULT ''
            );

            CREATE TABLE IF NOT EXISTS vulnerabilities (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id          TEXT    NOT NULL REFERENCES scans(id) ON DELETE CASCADE,
                host             TEXT    NOT NULL,
                port             INTEGER NOT NULL,
                service          TEXT    NOT NULL DEFAULT '',
                cve_id           TEXT    NOT NULL DEFAULT '',
                name             TEXT    NOT NULL,
                severity         TEXT    NOT NULL,
                cvss_score       REAL    NOT NULL DEFAULT 0.0,
                description      TEXT    NOT NULL DEFAULT '',
                remediation      TEXT    NOT NULL DEFAULT '',
                detected_version TEXT    NOT NULL DEFAULT ''
            );

            CREATE INDEX IF NOT EXISTS idx_ports_scan ON port_results(scan_id);
            CREATE INDEX IF NOT EXISTS idx_vulns_scan  ON vulnerabilities(scan_id);
            CREATE INDEX IF NOT EXISTS idx_vulns_sev   ON vulnerabilities(severity);
        """)
    logger.info("Database initialised at %s", DB_PATH)


# ── Scans ──────────────────────────────────────────────────────────────────────

def create_scan(target: str, config: dict, name: str = "") -> str:
    """Insert a new scan record and return its UUID."""
    scan_id = str(uuid.uuid4())
    if not name:
        name = f"Scan {datetime.now().strftime('%Y-%m-%d %H:%M')}"
    with _get_conn() as conn:
        conn.execute(
            """INSERT INTO scans (id, name, target, scan_date, status, config_json)
               VALUES (?, ?, ?, ?, 'running', ?)""",
            (scan_id, name, target, datetime.now().isoformat(), json.dumps(config)),
        )
    logger.debug("Created scan %s for target %s", scan_id, target)
    return scan_id


def finish_scan(
    scan_id: str,
    total_hosts: int,
    open_ports: int,
    total_vulns: int,
    risk_score: float,
) -> None:
    """Mark a scan as completed and write summary statistics."""
    with _get_conn() as conn:
        conn.execute(
            """UPDATE scans
               SET status='completed', total_hosts=?, open_ports=?, total_vulns=?, risk_score=?
               WHERE id=?""",
            (total_hosts, open_ports, total_vulns, round(risk_score, 1), scan_id),
        )


def fail_scan(scan_id: str, reason: str) -> None:
    """Mark a scan as failed."""
    with _get_conn() as conn:
        conn.execute(
            "UPDATE scans SET status='failed' WHERE id=?", (scan_id,)
        )
    logger.warning("Scan %s failed: %s", scan_id, reason)


def get_all_scans() -> List[dict]:
    """Return all scans ordered by most recent first."""
    with _get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM scans ORDER BY scan_date DESC"
        ).fetchall()
    return [dict(r) for r in rows]


def get_scan(scan_id: str) -> Optional[dict]:
    """Return a single scan record or None."""
    with _get_conn() as conn:
        row = conn.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
    return dict(row) if row else None


def delete_scan(scan_id: str) -> None:
    """Delete a scan and all related records (cascades)."""
    with _get_conn() as conn:
        conn.execute("DELETE FROM scans WHERE id=?", (scan_id,))
    logger.info("Deleted scan %s", scan_id)


# ── Port results ───────────────────────────────────────────────────────────────

def save_port_results(scan_id: str, results: List[dict]) -> None:
    """Bulk-insert port scan results for a scan."""
    rows = [
        (
            scan_id,
            r["host"],
            r["port"],
            r["status"],
            r.get("service", ""),
            r.get("product", ""),
            r.get("version", ""),
            r.get("banner", ""),
        )
        for r in results
    ]
    with _get_conn() as conn:
        conn.executemany(
            """INSERT INTO port_results
               (scan_id, host, port, status, service, product, version, banner)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            rows,
        )


def get_port_results(scan_id: str) -> List[dict]:
    """Return all port results for a scan."""
    with _get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM port_results WHERE scan_id=? ORDER BY host, port",
            (scan_id,),
        ).fetchall()
    return [dict(r) for r in rows]


# ── Vulnerabilities ────────────────────────────────────────────────────────────

def save_vulnerabilities(scan_id: str, vulns: List[dict]) -> None:
    """Bulk-insert vulnerability findings for a scan."""
    rows = [
        (
            scan_id,
            v["host"],
            v.get("port", 0),
            v.get("service", ""),
            v.get("cve_id", ""),
            v["name"],
            v["severity"],
            v.get("cvss_score", 0.0),
            v.get("description", ""),
            v.get("remediation", ""),
            v.get("detected_version", ""),
        )
        for v in vulns
    ]
    with _get_conn() as conn:
        conn.executemany(
            """INSERT INTO vulnerabilities
               (scan_id, host, port, service, cve_id, name, severity,
                cvss_score, description, remediation, detected_version)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            rows,
        )


def get_vulnerabilities(scan_id: str) -> List[dict]:
    """Return all vulnerabilities for a scan."""
    with _get_conn() as conn:
        rows = conn.execute(
            """SELECT * FROM vulnerabilities
               WHERE scan_id=?
               ORDER BY cvss_score DESC, severity, host, port""",
            (scan_id,),
        ).fetchall()
    return [dict(r) for r in rows]


def get_dashboard_stats() -> dict:
    """Return aggregate statistics for the dashboard."""
    with _get_conn() as conn:
        total_scans = conn.execute(
            "SELECT COUNT(*) FROM scans WHERE status='completed'"
        ).fetchone()[0]

        total_open_ports = conn.execute(
            "SELECT COALESCE(SUM(open_ports),0) FROM scans WHERE status='completed'"
        ).fetchone()[0]

        total_vulns = conn.execute(
            "SELECT COALESCE(SUM(total_vulns),0) FROM scans WHERE status='completed'"
        ).fetchone()[0]

        avg_risk = conn.execute(
            "SELECT COALESCE(AVG(risk_score),0) FROM scans WHERE status='completed'"
        ).fetchone()[0]

        severity_counts = {}
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"):
            count = conn.execute(
                "SELECT COUNT(*) FROM vulnerabilities WHERE severity=?", (sev,)
            ).fetchone()[0]
            severity_counts[sev] = count

        recent_scans = conn.execute(
            """SELECT id, name, target, scan_date, total_hosts, open_ports,
                      total_vulns, risk_score, status
               FROM scans ORDER BY scan_date DESC LIMIT 5"""
        ).fetchall()

    return {
        "total_scans": total_scans,
        "total_open_ports": total_open_ports,
        "total_vulns": total_vulns,
        "avg_risk_score": round(avg_risk, 1),
        "severity_counts": severity_counts,
        "recent_scans": [dict(r) for r in recent_scans],
    }
