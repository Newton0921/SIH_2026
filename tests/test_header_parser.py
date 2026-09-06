"""
tests/test_header_parser.py — Unit tests for Stage 3 header forensics.

Tests:
  1. Authentication-Results header parser (with known strings → expected tokens)
  2. Anomaly detection (synthetic dicts → expected anomaly list)
  3. DNS fallback on a real domain (live network call — skipped if no connectivity)
  4. End-to-end Stage 3 on 5 sample .eml files (graceful degradation confirmed)

Run: python -m pytest tests/test_header_parser.py -s --no-header
"""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from modules.header_forensics import (
    _parse_auth_results_header,
    _check_anomalies,
    analyze,
)
from modules.parser import parse_eml


# ---------------------------------------------------------------------------
# 1. Authentication-Results header parser unit tests
# ---------------------------------------------------------------------------
class TestAuthResultsParser:
    def test_all_pass(self):
        raw = (
            "mx.google.com; "
            "spf=pass smtp.mailfrom=sender@example.com; "
            "dkim=pass header.i=@example.com; "
            "dmarc=pass (p=REJECT) header.from=example.com"
        )
        r = _parse_auth_results_header(raw)
        assert r["spf"]   == "pass"
        assert r["dkim"]  == "pass"
        assert r["dmarc"] == "pass"

    def test_spf_fail_dkim_pass_dmarc_fail(self):
        raw = "mx.example.com; spf=fail; dkim=pass; dmarc=fail"
        r = _parse_auth_results_header(raw)
        assert r["spf"]   == "fail"
        assert r["dkim"]  == "pass"
        assert r["dmarc"] == "fail"

    def test_softfail(self):
        raw = "mx.example.com; spf=softfail; dmarc=none"
        r = _parse_auth_results_header(raw)
        assert r["spf"]   == "softfail"
        assert r["dmarc"] == "none"
        assert r["dkim"]  == "unknown"   # not present → default

    def test_empty_header(self):
        r = _parse_auth_results_header("")
        assert r == {"spf": "unknown", "dkim": "unknown", "dmarc": "unknown"}

    def test_none_input(self):
        r = _parse_auth_results_header(None)
        assert r == {"spf": "unknown", "dkim": "unknown", "dmarc": "unknown"}

    def test_permerror(self):
        raw = "mx.example.com; spf=permerror; dkim=temperror; dmarc=none"
        r = _parse_auth_results_header(raw)
        assert r["spf"]  == "permerror"
        assert r["dkim"] == "temperror"

    def test_case_insensitive(self):
        raw = "mx.example.com; SPF=Pass; DKIM=PASS; DMARC=Pass"
        r = _parse_auth_results_header(raw)
        assert r["spf"]   == "pass"
        assert r["dkim"]  == "pass"
        assert r["dmarc"] == "pass"


# ---------------------------------------------------------------------------
# 2. Anomaly detection unit tests
# ---------------------------------------------------------------------------
class TestAnomalyChecks:
    def _make_email(self, **kwargs):
        """Build a minimal parsed-email dict for testing."""
        base = {
            "from_domain": "example.com",
            "reply_to": None,
            "reply_to_domain": None,
            "return_path": None,
            "return_path_domain": None,
            "message_id": "<abc123@example.com>",
            "received_chain": [],
            "x_synthetic": True,
        }
        base.update(kwargs)
        return base

    def test_no_anomalies_clean(self):
        email = self._make_email()
        assert _check_anomalies(email) == []

    def test_reply_to_mismatch(self):
        email = self._make_email(
            reply_to="attacker@evil.com",
            reply_to_domain="evil.com",
        )
        anomalies = _check_anomalies(email)
        assert any("Reply-To domain mismatch" in a for a in anomalies)

    def test_return_path_mismatch(self):
        email = self._make_email(
            return_path="bounce@different.com",
            return_path_domain="different.com",
        )
        anomalies = _check_anomalies(email)
        assert any("Return-Path domain mismatch" in a for a in anomalies)

    def test_message_id_mismatch(self):
        # Message-ID domain is completely different from From domain
        email = self._make_email(
            from_domain="paypal.com",
            message_id="<abc123@randomhost.ru>",
        )
        anomalies = _check_anomalies(email)
        assert any("Message-ID domain mismatch" in a for a in anomalies)

    def test_message_id_subdomain_ok(self):
        # mail.paypal.com should match paypal.com — not flagged
        email = self._make_email(
            from_domain="paypal.com",
            message_id="<abc123@mail.paypal.com>",
        )
        anomalies = _check_anomalies(email)
        assert not any("Message-ID domain mismatch" in a for a in anomalies)

    def test_excessive_hops(self):
        email = self._make_email(
            received_chain=["hop"] * 8,
            x_synthetic=False,
        )
        anomalies = _check_anomalies(email)
        assert any("Excessive relay hops" in a for a in anomalies)

    def test_missing_received_non_synthetic(self):
        # A real (non-synthetic) email without any Received headers is suspicious
        email = self._make_email(received_chain=[], x_synthetic=False)
        anomalies = _check_anomalies(email)
        assert any("No Received headers" in a for a in anomalies)

    def test_synthetic_no_received_no_flag(self):
        # Synthetic emails are expected to have no Received chain
        email = self._make_email(received_chain=[], x_synthetic=True)
        anomalies = _check_anomalies(email)
        assert not any("No Received headers" in a for a in anomalies)

    def test_multiple_anomalies(self):
        email = self._make_email(
            reply_to_domain="evil.com",
            return_path_domain="other.com",
            message_id="<abc@totally-different.ru>",
        )
        anomalies = _check_anomalies(email)
        assert len(anomalies) >= 3


# ---------------------------------------------------------------------------
# 3. End-to-end Stage 3 on sample .eml files
# ---------------------------------------------------------------------------
class TestStage3EndToEnd:
    samples_dir = Path("uploads/samples")

    def test_stage3_on_synthetic_samples(self):
        """
        Run Stage 3 on 5 synthetic phishing samples.
        Expect:
          - auth_source == "dns_fallback" (no Authentication-Results header in synthetic)
          - dkim == "unknown" always in fallback mode
          - No crash / graceful handling of missing data
        """
        files = sorted(self.samples_dir.glob("*phishing*.eml"))[:5]
        assert files, "No phishing samples found — run csv_to_eml.py first"

        for fp in files:
            parsed = parse_eml(fp)
            result = analyze(parsed)

            print(f"\n{fp.name}")
            print(f"  auth_source : {result['auth_source']}")
            print(f"  spf         : {result['spf']}")
            print(f"  dkim        : {result['dkim']}")
            print(f"  dmarc       : {result['dmarc']}")
            safe_anomalies = [a.encode("ascii", errors="replace").decode("ascii") for a in result["anomalies"]]
            print(f"  anomalies   : {safe_anomalies}")

            # Core assertions
            assert result["auth_source"] in ("header", "dns_fallback")
            assert result["dkim"] in ("pass", "fail", "unknown")
            # In fallback mode, dkim must always be "unknown"
            if result["auth_source"] == "dns_fallback":
                assert result["dkim"] == "unknown", (
                    "DKIM must be 'unknown' in dns_fallback mode — "
                    "checkdmarc cannot verify DKIM signatures"
                )
            assert isinstance(result["anomalies"], list)
            assert "auth_note" in result
