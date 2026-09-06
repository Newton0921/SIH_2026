"""
modules/compliance.py -- Stage 8: Privacy, Legal, and Compliance Safeguards

Three components:
  1. Masked view: redacts PII from reports/dashboard for sharing outside investigation team
  2. Audit log: append-only SQLite table recording every view/export action
  3. Retention purge: callable function that nulls raw email bodies after N days
"""

import hashlib
import logging
import re
import sqlite3
from datetime import datetime, timezone
from typing import Any

from config import DB_PATH, DEFAULT_RETENTION_DAYS

log = logging.getLogger(__name__)

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")


# ---------------------------------------------------------------------------
# 1. Masked view helpers
# ---------------------------------------------------------------------------
def mask_email_address(addr: str) -> str:
    """
    Redact the local part of an email address, keeping only the domain.
    Example: john.doe@example.com -> [REDACTED]@example.com
    """
    if not addr:
        return addr
    if "@" in addr:
        local, domain = addr.rsplit("@", 1)
        return f"[REDACTED]@{domain}"
    return "[REDACTED]"


def mask_body(body: str, max_chars: int = 50) -> str:
    """Return first max_chars of body followed by redaction marker."""
    if not body:
        return ""
    return body[:max_chars].strip() + " [... BODY REDACTED FOR SHARING ...]"


def apply_masked_view(data: dict[str, Any]) -> dict[str, Any]:
    """
    Apply masked view to an email analysis record dict.
    Redacts full email addresses and body text; retains domain-level and
    signal/indicator data for investigation purposes.

    Used when sharing reports outside the immediate investigation team.
    """
    masked = dict(data)

    # Mask sender/recipient addresses
    for field in ("from_addr", "reply_to", "return_path"):
        if masked.get(field):
            masked[field] = mask_email_address(masked[field])

    # Mask To list
    if isinstance(masked.get("to"), list):
        masked["to"] = [mask_email_address(a) for a in masked["to"]]

    # Mask body
    for field in ("body_plain", "body_stored", "body_html"):
        if masked.get(field):
            masked[field] = mask_body(masked[field])

    # Mask email addresses embedded in indicator strings
    for field in ("indicators", "anomalies", "infrastructure_flags"):
        if isinstance(masked.get(field), list):
            masked[field] = [
                _EMAIL_RE.sub(lambda m: mask_email_address(m.group()), item)
                for item in masked[field]
            ]

    masked["_masked"] = True
    return masked


# ---------------------------------------------------------------------------
# 2. Audit log (append-only)
# ---------------------------------------------------------------------------
def _get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def log_action(action: str, record_id: int | None = None, actor: str = "system") -> None:
    """
    Record an action in the append-only audit_log table.
    Used for chain-of-custody support.

    Actions: "view_detail", "export_pdf", "view_dashboard",
             "upload_email", "purge_body"
    """
    now = datetime.now(timezone.utc).isoformat()
    try:
        with _get_db() as conn:
            conn.execute(
                """CREATE TABLE IF NOT EXISTS audit_log (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    action      TEXT NOT NULL,
                    record_id   INTEGER,
                    actor       TEXT DEFAULT 'system',
                    timestamp   TEXT NOT NULL
                )"""
            )
            conn.execute(
                "INSERT INTO audit_log (action, record_id, actor, timestamp) VALUES (?, ?, ?, ?)",
                (action, record_id, actor, now),
            )
            conn.commit()
    except Exception as exc:
        log.error("Audit log write failed: %s", exc)


def get_audit_log(limit: int = 100) -> list[dict]:
    """Return the most recent audit log entries."""
    try:
        with _get_db() as conn:
            conn.execute(
                """CREATE TABLE IF NOT EXISTS audit_log (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    action TEXT NOT NULL, record_id INTEGER,
                    actor TEXT DEFAULT 'system', timestamp TEXT NOT NULL
                )"""
            )
            rows = conn.execute(
                "SELECT * FROM audit_log ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
            return [dict(r) for r in rows]
    except Exception as exc:
        log.error("Audit log read failed: %s", exc)
        return []


# ---------------------------------------------------------------------------
# 3. Retention purge
# ---------------------------------------------------------------------------
def purge_old_bodies(days: int = DEFAULT_RETENTION_DAYS) -> int:
    """
    Purge raw email bodies from the database for records older than `days` days.
    The analysis record (score, outcome, signals, campaign) is RETAINED.
    Only body_stored is set to NULL.

    This is a callable function -- does not need to be a scheduled job for the demo.
    Returns the number of records purged.

    Chain-of-custody: the purge action is logged to audit_log.
    """
    cutoff = datetime.now(timezone.utc).isoformat()

    try:
        with _get_db() as conn:
            # Find records older than `days` days that still have body stored
            rows = conn.execute(
                """SELECT id FROM emails
                   WHERE body_stored IS NOT NULL
                   AND analyzed_at < datetime('now', ?)""",
                (f"-{days} days",),
            ).fetchall()

            if not rows:
                log.info("Retention purge: no records older than %d days found", days)
                return 0

            ids = [r["id"] for r in rows]
            conn.execute(
                f"UPDATE emails SET body_stored = NULL WHERE id IN ({','.join('?' * len(ids))})",
                ids,
            )
            conn.commit()

        # Log the purge action
        log_action("purge_body", record_id=None, actor="system-retention-policy")
        log.info("Retention purge: %d email bodies purged (older than %d days)", len(ids), days)
        return len(ids)

    except Exception as exc:
        log.error("Retention purge failed: %s", exc)
        return 0
