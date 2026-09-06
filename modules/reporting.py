"""
modules/reporting.py -- Stage 7: Alerting, Dashboard, and Forensic Reporting

Utility functions for:
  - Fetching dashboard data from SQLite
  - Fetching per-email detail records
  - Generating PDF forensic reports via xhtml2pdf
"""

import json
import logging
import sqlite3
from datetime import datetime, timezone
from io import BytesIO
from pathlib import Path
from typing import Any

from config import DB_PATH

log = logging.getLogger(__name__)


def _get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


# ---------------------------------------------------------------------------
# Dashboard data
# ---------------------------------------------------------------------------
def get_dashboard_emails(
    outcome_filter: str | None = None,
    domain_filter: str | None = None,
    campaign_filter: int | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
    limit: int = 200,
) -> list[dict]:
    """
    Fetch analyzed emails for the dashboard with optional filters.
    Returns list of dicts ordered by score DESC (highest risk first),
    with quarantine emails always at the top.
    """
    query = """
        SELECT e.id, e.filename, e.from_addr, e.from_domain, e.subject,
               e.date_received, e.analyzed_at, e.score, e.outcome,
               e.campaign_id, e.signals_json,
               c.member_count as campaign_size, c.label as campaign_label
        FROM emails e
        LEFT JOIN campaigns c ON e.campaign_id = c.id
        WHERE 1=1
    """
    params: list = []

    if outcome_filter:
        query += " AND e.outcome = ?"
        params.append(outcome_filter)
    if domain_filter:
        query += " AND e.from_domain LIKE ?"
        params.append(f"%{domain_filter}%")
    if campaign_filter is not None:
        query += " AND e.campaign_id = ?"
        params.append(campaign_filter)
    if date_from:
        query += " AND e.analyzed_at >= ?"
        params.append(date_from)
    if date_to:
        query += " AND e.analyzed_at <= ?"
        params.append(date_to)

    query += """
        ORDER BY
            CASE e.outcome WHEN 'quarantine' THEN 0
                           WHEN 'flag-for-manual-review' THEN 1
                           ELSE 2 END ASC,
            e.score DESC
        LIMIT ?
    """
    params.append(limit)

    try:
        with _get_db() as conn:
            rows = conn.execute(query, params).fetchall()
            result = []
            for row in rows:
                d = dict(row)
                try:
                    d["signals"] = json.loads(d.pop("signals_json", "{}") or "{}")
                except (json.JSONDecodeError, TypeError):
                    d["signals"] = {}
                result.append(d)
            return result
    except Exception as exc:
        log.error("Dashboard query failed: %s", exc)
        return []


def get_email_detail(email_id: int) -> dict | None:
    """Fetch full detail record for one email by ID."""
    try:
        with _get_db() as conn:
            row = conn.execute(
                """SELECT e.*, c.member_count as campaign_size,
                          c.first_seen as campaign_first_seen,
                          c.last_seen as campaign_last_seen,
                          c.common_domain as campaign_domain,
                          c.common_ip as campaign_ip
                   FROM emails e
                   LEFT JOIN campaigns c ON e.campaign_id = c.id
                   WHERE e.id = ?""",
                (email_id,),
            ).fetchone()

            if not row:
                return None

            d = dict(row)
            try:
                d["signals"] = json.loads(d.pop("signals_json", "{}") or "{}")
            except (json.JSONDecodeError, TypeError):
                d["signals"] = {}
            return d
    except Exception as exc:
        log.error("Detail query failed for email %d: %s", email_id, exc)
        return None


def get_campaign_members(campaign_id: int) -> list[dict]:
    """Get all emails in a campaign for display on the detail page."""
    try:
        with _get_db() as conn:
            rows = conn.execute(
                """SELECT id, filename, from_addr, subject, score, outcome, analyzed_at
                   FROM emails WHERE campaign_id = ? ORDER BY analyzed_at DESC""",
                (campaign_id,),
            ).fetchall()
            return [dict(r) for r in rows]
    except Exception as exc:
        log.error("Campaign member query failed: %s", exc)
        return []


def get_stats() -> dict:
    """Get summary statistics for the dashboard header."""
    try:
        with _get_db() as conn:
            total     = conn.execute("SELECT COUNT(*) FROM emails").fetchone()[0]
            quarantine= conn.execute("SELECT COUNT(*) FROM emails WHERE outcome='quarantine'").fetchone()[0]
            review    = conn.execute("SELECT COUNT(*) FROM emails WHERE outcome='flag-for-manual-review'").fetchone()[0]
            campaigns = conn.execute("SELECT COUNT(*) FROM campaigns").fetchone()[0]
            return {
                "total": total,
                "quarantine": quarantine,
                "review": review,
                "deliver": total - quarantine - review,
                "campaigns": campaigns,
            }
    except Exception:
        return {"total": 0, "quarantine": 0, "review": 0, "deliver": 0, "campaigns": 0}


# ---------------------------------------------------------------------------
# PDF report generation (xhtml2pdf)
# ---------------------------------------------------------------------------
def generate_pdf(email_id: int, detail: dict, masked: bool = False) -> bytes | None:
    """
    Generate a PDF forensic report for one email using xhtml2pdf.

    xhtml2pdf limitations:
      - Limited CSS support: no flexbox, no CSS grid
      - Use tables, inline styles, and simple block elements only
      - Embeds content from the Jinja2 report_pdf.html template

    Returns raw PDF bytes, or None on failure.
    """
    try:
        from xhtml2pdf import pisa
        from flask import render_template, current_app

        html_content = render_template(
            "report_pdf.html",
            email=detail,
            signals=detail.get("signals", {}),
            masked=masked,
            generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        )

        pdf_buffer = BytesIO()
        result = pisa.CreatePDF(html_content, dest=pdf_buffer)

        if result.err:
            log.error("xhtml2pdf error generating report for email %d: %s", email_id, result.err)
            return None

        return pdf_buffer.getvalue()

    except Exception as exc:
        log.error("PDF generation failed for email %d: %s", email_id, exc)
        return None
