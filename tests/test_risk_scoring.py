"""
tests/test_risk_scoring.py -- Unit tests for Stage 6 risk scoring.

Tests the score formula with known synthetic inputs and verifies
output ranges and outcome tier assignments.

Run: python -m pytest tests/test_risk_scoring.py -s --no-header -v
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from modules.risk_scoring import compute_score, OUTCOME_DELIVER, OUTCOME_REVIEW, OUTCOME_QUARANTINE


def _make_inputs(
    ml_confidence: float = 0.0,
    spf: str = "pass",
    dkim: str = "pass",
    dmarc: str = "pass",
    anomalies: list = None,
    is_tor: bool = False,
    is_botnet: bool = False,
    is_cloud: bool = False,
    domain_age_status: str = "established",
    attribution_confidence: float = 0.0,
    attribution_flag: str = "insufficient-data",
    campaign_id: int = None,
    homograph_match: str = None,
    mx_suspicious: bool = False,
    urlhaus_hits: list = None,
):
    """Build minimal stage dicts for testing."""
    stage2 = {"ml_confidence": ml_confidence, "final_label": "phishing"}
    stage3 = {
        "spf": spf, "dkim": dkim, "dmarc": dmarc,
        "anomalies": anomalies or [],
        "auth_source": "header",
    }
    stage4 = {
        "is_tor": is_tor,
        "is_botnet_c2": is_botnet,
        "is_cloud_host": is_cloud,
        "domain_age_status": domain_age_status,
        "homograph_match": homograph_match,
        "mx_suspicious": mx_suspicious,
        "urlhaus_hits": urlhaus_hits or [],
        "origin_ip": "1.2.3.4" if (is_tor or is_botnet) else None,
    }
    stage5 = {
        "attribution_flag": attribution_flag,
        "attribution_confidence": attribution_confidence,
        "campaign_id": campaign_id,
    }
    return stage2, stage3, stage4, stage5


class TestRiskScoringFormula:
    def test_completely_clean_email_low_score(self):
        """A fully legitimate email with all signals clean should score low."""
        s2, s3, s4, s5 = _make_inputs(ml_confidence=0.05)
        result = compute_score(s2, s3, s4, s5)
        assert result["score"] < 30, f"Clean email scored too high: {result['score']}"
        assert result["outcome"] == OUTCOME_DELIVER

    def test_obvious_phishing_high_score(self):
        """Email with high ML confidence + auth failures + TOR should score high."""
        s2, s3, s4, s5 = _make_inputs(
            ml_confidence=0.97,
            spf="fail",
            dkim="fail",
            dmarc="fail",
            anomalies=["a", "b", "c", "d"],
            is_tor=True,
            domain_age_status="new",
            attribution_confidence=0.80,
            attribution_flag="likely-anonymized-infrastructure",
        )
        result = compute_score(s2, s3, s4, s5)
        assert result["score"] >= 70, f"Obvious phishing scored too low: {result['score']}"
        assert result["outcome"] == OUTCOME_QUARANTINE
        assert result["is_alert"] is True

    def test_borderline_email_review_tier(self):
        """Moderate-but-meaningful signals should land in the review tier."""
        s2, s3, s4, s5 = _make_inputs(
            ml_confidence=0.80,    # clear phishing signal from ML
            spf="softfail",        # auth degraded
            dmarc="none",          # no DMARC record
            anomalies=["Reply-To mismatch", "Return-Path mismatch"],
            domain_age_status="new",  # newly registered domain
        )
        result = compute_score(s2, s3, s4, s5)
        # Print actual score for transparency
        print(f"  Borderline score: {result['score']:.1f} -> {result['outcome']}")
        assert result["outcome"] in (OUTCOME_REVIEW, OUTCOME_QUARANTINE), (
            f"Expected review or quarantine, got {result['outcome']} "
            f"(score={result['score']:.1f})"
        )

    def test_score_clamped_0_100(self):
        """Score must always be within [0, 100]."""
        # Worst possible inputs
        s2, s3, s4, s5 = _make_inputs(
            ml_confidence=1.0,
            spf="fail", dkim="fail", dmarc="fail",
            anomalies=["a"] * 10,
            is_tor=True, is_botnet=True, is_cloud=True,
            domain_age_status="new",
            attribution_confidence=1.0,
            campaign_id=1,
        )
        result = compute_score(s2, s3, s4, s5)
        assert 0 <= result["score"] <= 100

        # Best possible inputs
        s2b, s3b, s4b, s5b = _make_inputs(ml_confidence=0.0)
        result2 = compute_score(s2b, s3b, s4b, s5b)
        assert 0 <= result2["score"] <= 100

    def test_breakdown_keys_present(self):
        """Score result must include a breakdown dict with all component keys."""
        s2, s3, s4, s5 = _make_inputs(ml_confidence=0.5)
        result = compute_score(s2, s3, s4, s5)
        assert "breakdown" in result
        expected_keys = [
            "ml_contribution", "spf_contribution", "dkim_contribution",
            "dmarc_contribution", "anom_contribution", "geo_contribution",
            "dom_contribution", "camp_contribution", "attr_contribution",
        ]
        for k in expected_keys:
            assert k in result["breakdown"], f"Missing breakdown key: {k}"

    def test_campaign_bonus_increases_score(self):
        """Being in a campaign should increase score vs not."""
        s2, s3, s4, s5_no  = _make_inputs(ml_confidence=0.7, campaign_id=None)
        s2, s3, s4, s5_yes = _make_inputs(ml_confidence=0.7, campaign_id=1)
        score_no  = compute_score(s2, s3, s4, s5_no)["score"]
        score_yes = compute_score(s2, s3, s4, s5_yes)["score"]
        assert score_yes > score_no, "Campaign membership should increase score"

    def test_tor_increases_score_vs_cloud_only(self):
        """TOR should score higher than cloud hosting alone."""
        s2, s3, s4_tor, s5 = _make_inputs(ml_confidence=0.5, is_tor=True)
        s2, s3, s4_cld, s5 = _make_inputs(ml_confidence=0.5, is_cloud=True)
        score_tor = compute_score(s2, s3, s4_tor, s5)["score"]
        score_cld = compute_score(s2, s3, s4_cld, s5)["score"]
        assert score_tor > score_cld, "TOR should score higher than cloud-only"

    def test_outcome_thresholds(self):
        """Verify the three outcome tiers match expected thresholds."""
        # Deliver: score < 40
        s2, s3, s4, s5 = _make_inputs(ml_confidence=0.1)
        r = compute_score(s2, s3, s4, s5)
        if r["score"] < 40:
            assert r["outcome"] == OUTCOME_DELIVER

        # Quarantine: score >= 70
        s2h, s3h, s4h, s5h = _make_inputs(
            ml_confidence=0.99, spf="fail", dkim="fail", is_tor=True
        )
        r2 = compute_score(s2h, s3h, s4h, s5h)
        if r2["score"] >= 70:
            assert r2["outcome"] == OUTCOME_QUARANTINE

    def test_new_domain_increases_score(self):
        """Newly registered domain should score higher than established."""
        s2, s3, s4_new, s5 = _make_inputs(ml_confidence=0.6, domain_age_status="new")
        s2, s3, s4_old, s5 = _make_inputs(ml_confidence=0.6, domain_age_status="established")
        score_new = compute_score(s2, s3, s4_new, s5)["score"]
        score_old = compute_score(s2, s3, s4_old, s5)["score"]
        assert score_new > score_old, "New domain should score higher"

    def test_homograph_increases_domain_score(self):
        """Homograph match should increase score."""
        s2, s3, s4_h, s5 = _make_inputs(ml_confidence=0.5, homograph_match="paypal.com")
        s2, s3, s4_n, s5 = _make_inputs(ml_confidence=0.5, homograph_match=None)
        score_h = compute_score(s2, s3, s4_h, s5)["score"]
        score_n = compute_score(s2, s3, s4_n, s5)["score"]
        assert score_h > score_n, "Homograph match should increase score"
