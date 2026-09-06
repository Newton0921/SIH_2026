"""
modules/correlation.py -- Stage 5: Identity Correlation and Attribution Support

Builds a NetworkX graph linking emails, domains, IPs, reply-to addresses, and
attachment hashes across ALL previously analyzed emails in the SQLite database.

Campaign clustering uses TF-IDF cosine similarity (rationale: scales better than
difflib for large corpora and reuses the vectorizer already present in Stage 2).
Threshold: 0.85 (configurable in config.py as CAMPAIGN_SIMILARITY_THRESHOLD).

Attribution flag rules (RULE-BASED -- not ML, not a named-actor claim):
  Rules are defined as explicit if/elif chains and documented in comments.
  Output is a categorical flag + confidence percentage, never a person/org name.

Possible attribution flags:
  - likely-spoofed-domain
  - likely-compromised-legitimate-account
  - likely-anonymized-infrastructure
  - insufficient-data
"""

import json
import logging
import sqlite3
from pathlib import Path
from typing import Any

import networkx as nx
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity
import numpy as np

from config import DB_PATH, CAMPAIGN_SIMILARITY_THRESHOLD

log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# SQLite schema helpers
# ---------------------------------------------------------------------------
def _get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def _ensure_schema(conn: sqlite3.Connection) -> None:
    """Create all required tables if they don't exist."""
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS emails (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            filename        TEXT,
            sha256          TEXT,
            from_addr       TEXT,
            from_domain     TEXT,
            subject         TEXT,
            date_received   TEXT,
            analyzed_at     TEXT,
            body_stored     TEXT,
            score           REAL,
            outcome         TEXT,
            campaign_id     INTEGER,
            signals_json    TEXT
        );

        CREATE TABLE IF NOT EXISTS campaigns (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            first_seen      TEXT,
            last_seen       TEXT,
            member_count    INTEGER DEFAULT 1,
            common_domain   TEXT,
            common_ip       TEXT,
            label           TEXT
        );

        CREATE TABLE IF NOT EXISTS cache_lookups (
            key             TEXT NOT NULL,
            source          TEXT NOT NULL,
            response_json   TEXT,
            fetched_at      REAL NOT NULL,
            PRIMARY KEY (key, source)
        );

        CREATE TABLE IF NOT EXISTS audit_log (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            action      TEXT NOT NULL,
            record_id   INTEGER,
            actor       TEXT DEFAULT 'system',
            timestamp   TEXT NOT NULL
        );
    """)
    conn.commit()


def init_db() -> None:
    """Initialize the database schema. Call at app startup."""
    with _get_db() as conn:
        _ensure_schema(conn)
    log.info("Database initialized at %s", DB_PATH)


# ---------------------------------------------------------------------------
# Graph construction
# ---------------------------------------------------------------------------
def _build_graph(email_records: list[dict]) -> nx.DiGraph:
    """
    Build a directed graph linking email nodes to their associated entities.

    Node types:
      - email:  email_id (int)
      - domain: "domain:example.com"
      - ip:     "ip:1.2.3.4"
      - reply:  "reply:addr@domain.com"
      - hash:   "hash:sha256..."

    Edges: email_id --> entity_node
    """
    G = nx.DiGraph()

    for rec in email_records:
        eid = rec["id"]
        G.add_node(eid, type="email", label=rec.get("subject", "")[:40])

        domain = rec.get("from_domain", "")
        if domain:
            d_node = f"domain:{domain}"
            G.add_node(d_node, type="domain")
            G.add_edge(eid, d_node)

        signals = {}
        try:
            signals = json.loads(rec.get("signals_json", "{}") or "{}")
        except (json.JSONDecodeError, TypeError):
            pass

        ip = signals.get("origin_ip")
        if ip:
            ip_node = f"ip:{ip}"
            G.add_node(ip_node, type="ip")
            G.add_edge(eid, ip_node)

        reply = signals.get("reply_to") or signals.get("reply_to_addr")
        if reply:
            r_node = f"reply:{reply}"
            G.add_node(r_node, type="reply_to")
            G.add_edge(eid, r_node)

        for sha in signals.get("attachment_sha256s", []):
            h_node = f"hash:{sha}"
            G.add_node(h_node, type="attachment_hash")
            G.add_edge(eid, h_node)

    return G


# ---------------------------------------------------------------------------
# Campaign clustering (TF-IDF cosine similarity)
# ---------------------------------------------------------------------------
def _find_campaign_by_hard_link(
    email_id: int,
    from_domain: str,
    origin_ip: str | None,
    attachment_hashes: list[str],
    conn: sqlite3.Connection,
) -> int | None:
    """
    Hard-link campaign matching: email shares a domain, IP, or attachment hash
    with an existing campaign member. Returns campaign_id or None.

    Hard links are definitive -- any shared infra means same campaign.
    """
    rows = conn.execute(
        "SELECT id, campaign_id, signals_json, from_domain FROM emails "
        "WHERE campaign_id IS NOT NULL AND id != ?",
        (email_id,),
    ).fetchall()

    for row in rows:
        cid = row["campaign_id"]
        try:
            signals = json.loads(row["signals_json"] or "{}")
        except (json.JSONDecodeError, TypeError):
            signals = {}

        # Domain match
        if from_domain and from_domain == row["from_domain"]:
            return cid

        # IP match
        row_ip = signals.get("origin_ip")
        if origin_ip and row_ip and origin_ip == row_ip:
            return cid

        # Attachment hash match
        row_hashes = set(signals.get("attachment_sha256s", []))
        if row_hashes and any(h in row_hashes for h in attachment_hashes):
            return cid

    return None


def _find_campaign_by_similarity(
    email_id: int,
    subject: str,
    body: str,
    conn: sqlite3.Connection,
) -> int | None:
    """
    Soft-link campaign matching: TF-IDF cosine similarity on subject+body.
    Returns campaign_id of most similar email if above threshold.

    Rationale for TF-IDF cosine over difflib:
      - Handles large corpora efficiently (vectorization is O(n*features))
      - Scale-invariant to document length
      - Reuses the same vectorization approach as Stage 2 classifier
      - difflib's SequenceMatcher is O(n*m) per pair -- too slow for cross-email comparison
    """
    threshold = CAMPAIGN_SIMILARITY_THRESHOLD

    # Pull all existing emails with bodies for comparison
    rows = conn.execute(
        "SELECT id, campaign_id, subject, body_stored FROM emails "
        "WHERE campaign_id IS NOT NULL AND id != ? AND body_stored IS NOT NULL",
        (email_id,),
    ).fetchall()

    if not rows:
        return None

    candidate_texts = [
        f"{r['subject'] or ''} {r['body_stored'] or ''}" for r in rows
    ]
    current_text = f"{subject or ''} {body or ''}"

    if not any(candidate_texts) or not current_text.strip():
        return None

    try:
        vectorizer = TfidfVectorizer(max_features=5000, sublinear_tf=True)
        all_texts  = candidate_texts + [current_text]
        tfidf_mat  = vectorizer.fit_transform(all_texts)

        current_vec    = tfidf_mat[-1]
        candidate_vecs = tfidf_mat[:-1]

        sims = cosine_similarity(current_vec, candidate_vecs)[0]
        best_idx = int(np.argmax(sims))
        best_score = float(sims[best_idx])

        if best_score >= threshold:
            cid = rows[best_idx]["campaign_id"]
            log.debug(
                "Email %d soft-linked to campaign %d (cosine similarity: %.3f)",
                email_id, cid, best_score,
            )
            return cid
    except Exception as exc:
        log.warning("TF-IDF similarity clustering failed: %s", exc)

    return None


def assign_campaign(
    email_id: int,
    from_domain: str,
    origin_ip: str | None,
    attachment_hashes: list[str],
    subject: str,
    body: str,
    conn: sqlite3.Connection,
) -> int | None:
    """
    Try to assign this email to an existing campaign (hard link first, then soft).
    If no match, create a new single-member campaign.
    Returns the campaign_id.
    """
    # Hard links take priority
    cid = _find_campaign_by_hard_link(
        email_id, from_domain, origin_ip, attachment_hashes, conn
    )

    # Soft links if no hard match
    if cid is None:
        cid = _find_campaign_by_similarity(email_id, subject, body, conn)

    from datetime import datetime, timezone
    now = datetime.now(timezone.utc).isoformat()

    if cid is not None:
        # Update existing campaign
        conn.execute(
            """UPDATE campaigns SET
                last_seen    = ?,
                member_count = member_count + 1
               WHERE id = ?""",
            (now, cid),
        )
        conn.commit()
        log.info("Email %d joined existing campaign %d", email_id, cid)
    else:
        # Create new campaign
        cursor = conn.execute(
            """INSERT INTO campaigns (first_seen, last_seen, member_count, common_domain, common_ip)
               VALUES (?, ?, 1, ?, ?)""",
            (now, now, from_domain or None, origin_ip or None),
        )
        conn.commit()
        cid = cursor.lastrowid
        log.info("Email %d started new campaign %d", email_id, cid)

    # Update the email's campaign_id
    conn.execute("UPDATE emails SET campaign_id = ? WHERE id = ?", (cid, email_id))
    conn.commit()

    return cid


# ---------------------------------------------------------------------------
# Attribution flag (rule-based -- see rules documented below)
# ---------------------------------------------------------------------------
def _attribution_flag(
    stage3: dict,   # header_forensics output
    stage4: dict,   # origin_intel output
) -> tuple[str, float]:
    """
    Produce a categorical attribution indicator with confidence score.

    RULES (explicit, rule-based -- NOT ML -- documented per spec):

    Rule A: likely-compromised-legitimate-account
      Condition: SPF=pass AND DKIM=pass AND DMARC=pass (from Authentication-Results header)
                 BUT content was classified as phishing
      Rationale: All auth checks passed, meaning the email came from an authorized sender,
                 but the content is malicious. Most likely the sending account is compromised.
      Confidence: 70% (auth checks passing is strong signal but not conclusive)

    Rule B: likely-spoofed-domain
      Condition: Reply-To mismatch OR Return-Path mismatch OR homograph hit >= 80%
                 OR display-name brand mismatch detected
      Rationale: Structural indicators of domain impersonation without necessarily
                 failing auth checks (e.g. newly registered lookalike domain with valid SPF).
      Confidence: 65% base, +10% per additional signal, capped at 85%

    Rule C: likely-anonymized-infrastructure
      Condition: TOR exit node OR known botnet C2 OR (cloud hosting + new domain)
      Rationale: Deliberate anonymization/obfuscation of sending infrastructure.
      Confidence: 80% for TOR/botnet, 55% for cloud+new-domain only

    Rule D: insufficient-data
      Condition: Fewer than 2 independent signals available
                 (catches synthetic .eml files with no Received chain)
      Confidence: 0%

    IMPORTANT: This function never claims a named actor. These are indicator categories only.
    """
    spf   = stage3.get("spf", "unknown")
    dkim  = stage3.get("dkim", "unknown")
    dmarc = stage3.get("dmarc", "unknown")
    anomalies      = stage3.get("anomalies", [])
    auth_source    = stage3.get("auth_source", "")

    is_tor         = stage4.get("is_tor", False)
    is_botnet      = stage4.get("is_botnet_c2", False)
    is_cloud       = stage4.get("is_cloud_host", False)
    domain_status  = stage4.get("domain_age_status", "")
    homo_match     = stage4.get("homograph_match")
    infra_flags    = stage4.get("infrastructure_flags", [])

    signals_available = sum([
        spf != "unknown",
        dkim != "unknown",
        bool(anomalies),
        bool(stage4.get("origin_ip")),
        bool(infra_flags),
    ])

    # Rule D: Insufficient data
    if signals_available < 2:
        return "insufficient-data", 0.0

    # Rule A: Compromised legitimate account
    if (auth_source == "header" and
            spf == "pass" and dkim == "pass" and dmarc == "pass"):
        return "likely-compromised-legitimate-account", 0.70

    # Rule C: Anonymized infrastructure (strongest indicator first)
    if is_tor:
        return "likely-anonymized-infrastructure", 0.80
    if is_botnet:
        return "likely-anonymized-infrastructure", 0.80
    if is_cloud and domain_status == "new":
        return "likely-anonymized-infrastructure", 0.55

    # Rule B: Spoofed domain
    spoof_signals = 0
    if any("Reply-To domain mismatch" in a for a in anomalies):
        spoof_signals += 1
    if any("Return-Path domain mismatch" in a for a in anomalies):
        spoof_signals += 1
    if homo_match:
        spoof_signals += 1
    if any("Message-ID domain mismatch" in a for a in anomalies):
        spoof_signals += 1
    if spf in ("fail", "softfail"):
        spoof_signals += 1
    if dmarc in ("fail",):
        spoof_signals += 1

    if spoof_signals >= 1:
        confidence = min(0.65 + (spoof_signals - 1) * 0.10, 0.85)
        return "likely-spoofed-domain", round(confidence, 2)

    # Fallback when signals exist but don't fit above categories
    return "insufficient-data", 0.20


# ---------------------------------------------------------------------------
# Main Stage 5 entry point
# ---------------------------------------------------------------------------
def analyze(
    email_id: int,
    parsed_email: dict[str, Any],
    stage3: dict[str, Any],
    stage4: dict[str, Any],
) -> dict[str, Any]:
    """
    Run campaign clustering and attribution analysis.

    Args:
        email_id:     ID of this email in the emails table
        parsed_email: dict from parser.parse_eml()
        stage3:       dict from header_forensics.analyze()
        stage4:       dict from origin_intel.analyze()

    Returns:
        {
          "campaign_id":          int | None,
          "attribution_flag":     str,
          "attribution_confidence": float,
          "attribution_note":     str,
          "graph_node_count":     int,
          "graph_edge_count":     int,
        }
    """
    from_domain = parsed_email.get("from_domain", "") or ""
    subject     = parsed_email.get("subject", "") or ""
    body        = parsed_email.get("body_plain", "") or ""
    origin_ip   = stage4.get("origin_ip")
    att_hashes  = [a["sha256"] for a in (parsed_email.get("attachments") or [])]

    with _get_db() as conn:
        _ensure_schema(conn)
        campaign_id = assign_campaign(
            email_id, from_domain, origin_ip, att_hashes, subject, body, conn
        )

        # Build graph from all stored emails for reporting
        all_rows = conn.execute(
            "SELECT id, from_domain, subject, signals_json FROM emails"
        ).fetchall()

    G = _build_graph([dict(r) for r in all_rows])

    flag, confidence = _attribution_flag(stage3, stage4)

    _NOTES = {
        "likely-compromised-legitimate-account": (
            "All authentication checks passed (SPF/DKIM/DMARC), indicating the email "
            "originated from an authorized sender. However, the content was classified "
            "as phishing. The most probable explanation is a compromised legitimate account. "
            "This is an indicator only -- manual investigation required."
        ),
        "likely-spoofed-domain": (
            "Structural indicators suggest the sending domain or display identity has "
            "been spoofed. This includes header mismatches, lookalike domains, or "
            "authentication failures. This is a probability indicator, not a certainty."
        ),
        "likely-anonymized-infrastructure": (
            "The sending infrastructure shows deliberate anonymization signals (TOR exit node, "
            "known botnet C2, or cloud hosting with a newly registered domain). "
            "This does not identify a specific actor -- only that obfuscation is present."
        ),
        "insufficient-data": (
            "Fewer than 2 independent signals are available for attribution assessment. "
            "This is common for synthetic test emails with no real routing data. "
            "Supply a real .eml file with a complete Received chain for a meaningful result."
        ),
    }

    return {
        "campaign_id":            campaign_id,
        "attribution_flag":       flag,
        "attribution_confidence": confidence,
        "attribution_note":       _NOTES.get(flag, ""),
        "graph_node_count":       G.number_of_nodes(),
        "graph_edge_count":       G.number_of_edges(),
    }
