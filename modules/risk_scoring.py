"""
modules/risk_scoring.py -- Stage 6: Risk/Fraud Scoring

Combines signals from all prior stages into a single 0-100 risk score.
All weight constants are defined at the top of this file and imported from config.py.
Three-tier outcome: deliver / flag-for-manual-review / quarantine.

Every email's complete signal record is stored in SQLite on first analysis.
"""

import json
import logging
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from config import (
    DB_PATH,
    W_ML, W_SPF, W_DKIM, W_DMARC, W_ANOM, W_GEO, W_DOM, W_CAMP, W_ATTR,
    THRESHOLD_DELIVER, THRESHOLD_REVIEW,
)

log = logging.getLogger(__name__)

# Outcome labels
OUTCOME_DELIVER  = "deliver"
OUTCOME_REVIEW   = "flag-for-manual-review"
OUTCOME_QUARANTINE = "quarantine"


# ---------------------------------------------------------------------------
# Auth result penalty conversion
# ---------------------------------------------------------------------------
def _auth_penalty(result: str) -> float:
    """
    Convert an SPF/DKIM/DMARC result string to a 0.0-1.0 penalty score.
    Higher = more suspicious.
    """
    return {
        "fail":              1.0,
        "permerror":         0.9,
        "temperror":         0.7,
        "softfail":          0.5,
        "neutral":           0.3,
        "none":              0.4,   # no record published -- suspicious for a claimed domain
        "record_exists":     0.0,   # SPF/DMARC record exists (DNS fallback mode -- no pass/fail)
        "unknown":           0.2,   # unknown is mildly suspicious but not conclusive
        "lookup_failed":     0.3,
        "pass":              0.0,
    }.get(result.split("_policy_")[0] if "_policy_" in result else result, 0.2)


# ---------------------------------------------------------------------------
# Score computation
# ---------------------------------------------------------------------------
def compute_score(
    stage2: dict[str, Any],
    stage3: dict[str, Any],
    stage4: dict[str, Any],
    stage5: dict[str, Any],
) -> dict[str, Any]:
    """
    Compute 0-100 fraud risk score from all stage outputs.

    Formula:
      score = (
        W_ML    * ml_confidence                          +  [Stage 2]
        W_SPF   * spf_penalty                            +  [Stage 3]
        W_DKIM  * dkim_penalty                           +  [Stage 3]
        W_DMARC * dmarc_penalty                          +  [Stage 3]
        W_ANOM  * min(anomaly_count / 4, 1.0)           +  [Stage 3]
        W_GEO   * geo_score                              +  [Stage 4]
        W_DOM   * domain_score                           +  [Stage 4]
        W_CAMP  * campaign_bonus                         +  [Stage 5]
        W_ATTR  * attribution_confidence                 )  [Stage 5]
      ) normalized to 0-100

    All weights defined in config.py and adjustable without touching this code.
    """
    total_weight = W_ML + W_SPF + W_DKIM + W_DMARC + W_ANOM + W_GEO + W_DOM + W_CAMP + W_ATTR

    # Stage 2 contribution
    ml_confidence = float(stage2.get("ml_confidence", 0.0))

    # Stage 3 contributions
    spf_penalty   = _auth_penalty(stage3.get("spf", "unknown"))
    dkim_penalty  = _auth_penalty(stage3.get("dkim", "unknown"))
    dmarc_penalty = _auth_penalty(stage3.get("dmarc", "unknown"))
    anomaly_count = len(stage3.get("anomalies", []))
    anom_score    = min(anomaly_count / 4.0, 1.0)   # 4 anomalies = full weight

    # Stage 4 contributions
    is_tor       = float(stage4.get("is_tor", False))
    is_botnet    = float(stage4.get("is_botnet_c2", False))
    is_cloud     = float(stage4.get("is_cloud_host", False)) * 0.4   # partial weight
    geo_score    = min(is_tor + is_botnet + is_cloud, 1.0)

    domain_status = stage4.get("domain_age_status", "age_unknown")
    domain_score  = {"new": 1.0, "age_unknown": 0.5, "established": 0.0}.get(domain_status, 0.3)

    # Extra domain signals (homograph, mx, urlhaus)
    if stage4.get("homograph_match"):
        domain_score = min(domain_score + 0.3, 1.0)
    if stage4.get("mx_suspicious"):
        domain_score = min(domain_score + 0.2, 1.0)
    if stage4.get("urlhaus_hits"):
        geo_score    = min(geo_score + 0.5, 1.0)

    # Stage 5 contributions
    attr_flag       = stage5.get("attribution_flag", "insufficient-data")
    attr_confidence = float(stage5.get("attribution_confidence", 0.0))

    # Campaign bonus: being part of any campaign is itself a signal
    # (isolated phishing is less likely to be a systematic attack)
    campaign_id    = stage5.get("campaign_id")
    campaign_bonus = 0.3 if campaign_id else 0.0

    # Weighted sum
    raw = (
        W_ML    * ml_confidence    +
        W_SPF   * spf_penalty      +
        W_DKIM  * dkim_penalty     +
        W_DMARC * dmarc_penalty    +
        W_ANOM  * anom_score       +
        W_GEO   * geo_score        +
        W_DOM   * domain_score     +
        W_CAMP  * campaign_bonus   +
        W_ATTR  * attr_confidence
    )

    score = round((raw / total_weight) * 100, 1)
    score = max(0.0, min(100.0, score))   # clamp to [0, 100]

    # Outcome tier
    if score >= THRESHOLD_REVIEW:
        outcome = OUTCOME_QUARANTINE
    elif score >= THRESHOLD_DELIVER:
        outcome = OUTCOME_REVIEW
    else:
        outcome = OUTCOME_DELIVER

    # Score breakdown for transparency / dashboard display
    breakdown = {
        "ml_contribution":    round(W_ML    * ml_confidence,  2),
        "spf_contribution":   round(W_SPF   * spf_penalty,    2),
        "dkim_contribution":  round(W_DKIM  * dkim_penalty,   2),
        "dmarc_contribution": round(W_DMARC * dmarc_penalty,  2),
        "anom_contribution":  round(W_ANOM  * anom_score,     2),
        "geo_contribution":   round(W_GEO   * geo_score,      2),
        "dom_contribution":   round(W_DOM   * domain_score,   2),
        "camp_contribution":  round(W_CAMP  * campaign_bonus, 2),
        "attr_contribution":  round(W_ATTR  * attr_confidence,2),
    }

    return {
        "score":     score,
        "outcome":   outcome,
        "breakdown": breakdown,
        "is_alert":  outcome == OUTCOME_QUARANTINE,
    }


# ---------------------------------------------------------------------------
# SQLite storage
# ---------------------------------------------------------------------------
def _get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def store_result(
    filename: str,
    sha256: str,
    parsed_email: dict[str, Any],
    stage2: dict[str, Any],
    stage3: dict[str, Any],
    stage4: dict[str, Any],
    stage5: dict[str, Any],
    score_result: dict[str, Any],
) -> int:
    """
    Store complete analysis record in SQLite. Returns the new email.id.
    """
    now = datetime.now(timezone.utc).isoformat()

    # Build signals dict with all raw signal data
    signals = {
        # Stage 2
        "final_label":       stage2.get("final_label"),
        "ml_confidence":     stage2.get("ml_confidence"),
        "heuristic_subtype": stage2.get("heuristic_subtype"),
        "indicators":        stage2.get("indicators", []),
        # Stage 3
        "spf":               stage3.get("spf"),
        "dkim":              stage3.get("dkim"),
        "dmarc":             stage3.get("dmarc"),
        "auth_source":       stage3.get("auth_source"),
        "anomalies":         stage3.get("anomalies", []),
        # Stage 4
        "origin_ip":         stage4.get("origin_ip"),
        "city":              stage4.get("city"),
        "country":           stage4.get("country"),
        "lat":               stage4.get("lat"),
        "lon":               stage4.get("lon"),
        "asn_org":           stage4.get("asn_org"),
        "is_tor":            stage4.get("is_tor"),
        "is_botnet_c2":      stage4.get("is_botnet_c2"),
        "is_cloud_host":     stage4.get("is_cloud_host"),
        "domain_age_days":   stage4.get("domain_age_days"),
        "domain_age_status": stage4.get("domain_age_status"),
        "mx_suspicious":     stage4.get("mx_suspicious"),
        "mx_host":           stage4.get("mx_host"),
        "homograph_match":   stage4.get("homograph_match"),
        "homograph_score":   stage4.get("homograph_score"),
        "urlhaus_hits":      stage4.get("urlhaus_hits", []),
        "infrastructure_flags": stage4.get("infrastructure_flags", []),
        "vt_ip":             stage4.get("vt_ip"),
        "abuseipdb":         stage4.get("abuseipdb"),
        # Stage 5
        "attribution_flag":        stage5.get("attribution_flag"),
        "attribution_confidence":  stage5.get("attribution_confidence"),
        "attribution_note":        stage5.get("attribution_note"),
        # Score
        "score":             score_result.get("score"),
        "breakdown":         score_result.get("breakdown"),
        # Attachment hashes
        "attachment_sha256s": [a["sha256"] for a in (parsed_email.get("attachments") or [])],
        "reply_to":          parsed_email.get("reply_to"),
        "urls":              parsed_email.get("urls", [])[:50],  # cap to 50
    }

    with _get_db() as conn:
        from modules.correlation import _ensure_schema
        _ensure_schema(conn)

        cursor = conn.execute(
            """INSERT INTO emails
               (filename, sha256, from_addr, from_domain, subject,
                date_received, analyzed_at, body_stored, score, outcome,
                campaign_id, signals_json)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (
                filename,
                sha256,
                parsed_email.get("from_addr", ""),
                parsed_email.get("from_domain", ""),
                parsed_email.get("subject", ""),
                parsed_email.get("date", ""),
                now,
                parsed_email.get("body_plain", "")[:50_000],   # cap body storage
                score_result["score"],
                score_result["outcome"],
                stage5.get("campaign_id"),
                json.dumps(signals, default=str),
            ),
        )
        conn.commit()
        email_id = cursor.lastrowid

    log.info(
        "Stored email %d: score=%.1f outcome=%s campaign=%s",
        email_id, score_result["score"], score_result["outcome"], stage5.get("campaign_id"),
    )
    return email_id
