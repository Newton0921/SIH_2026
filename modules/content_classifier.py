"""
modules/content_classifier.py — Stage 2: Fraudulent Email Detection Engine

ARCHITECTURE — TWO CLEARLY SEPARATED LAYERS:
============================================================

LAYER 1 — ML BINARY CLASSIFIER (scikit-learn, data-driven)
  Trained on Nazario_5.csv real binary labels (0=legitimate, 1=phishing).
  Optionally augmented with email_text.csv body text for a larger corpus.
  Features: TF-IDF on (subject + " " + body).
  Model: Logistic Regression with class_weight='balanced'.
  Output: ml_label (0/1), ml_confidence (float 0–1).

  What this layer CAN claim: a probability that the email content resembles
  phishing or legitimate emails in the training set.
  What it CANNOT claim: impersonation, BEC, or credential-harvesting sub-types
  — those labels do NOT exist in the dataset and are NOT ML-derived.

LAYER 2 — HEURISTIC SUB-CLASSIFIER (rule-based, NOT ML)
  Applied ONLY when Layer 1 flags an email as phishing (ml_label == 1).
  Uses keyword patterns and structural signal rules to sub-classify into:
    - impersonated     : display name ≠ sending domain (brand impersonation)
    - fraud-related    : BEC / payment-diversion patterns
    - phishing         : credential-harvesting patterns (default if above don't fire)
  Every heuristic rule is documented as a code comment and labeled in output.

ADDITIONAL SIGNALS (independent of ML label, always run):
  - Lookalike/homograph domain detection (via rapidfuzz)
  - URL shortener detection (list-based)
  - Suspicious attachment type detection
  - Display-name spoofing heuristic

OUTPUT LABEL SET: {legitimate, suspicious, impersonated, phishing, fraud-related}
  - "suspicious"  : ML confidence in phishing range 0.40–0.60 (uncertain zone)
  - "legitimate"  : ML confidence < 0.40
  - others        : ML confidence ≥ 0.60, then heuristic sub-type applied
"""

import logging
import re
from pathlib import Path
from typing import Any

import joblib

from config import (
    MODELS_DIR,
    TFIDF_MAX_FEATURES,
    TFIDF_NGRAM_RANGE,
    URL_SHORTENERS,
    SUSPICIOUS_EXTENSIONS,
    TRUSTED_DOMAINS,
    HOMOGRAPH_FLAG_THRESHOLD,
)

log = logging.getLogger(__name__)

# Path to serialized model pipeline (trained by train_classifier.py)
MODEL_PATH = MODELS_DIR / "classifier.pkl"

# ---------------------------------------------------------------------------
# Confidence thresholds for final label assignment
# ---------------------------------------------------------------------------
PHISHING_CONFIDENT_THRESHOLD  = 0.60   # >= this → apply heuristic sub-classifier
SUSPICIOUS_THRESHOLD          = 0.40   # >= this and < PHISHING_CONFIDENT → "suspicious"
# below SUSPICIOUS_THRESHOLD → "legitimate"


# ---------------------------------------------------------------------------
# Heuristic keyword patterns (LAYER 2 — rule-based, NOT ML)
# ---------------------------------------------------------------------------
# BEC / payment-diversion indicators
# Rule: body or subject contains financial-action keywords + authority/urgency language
_BEC_KEYWORDS = re.compile(
    r"\b(wire\s*transfer|wiring\s*funds?|bank\s*(account|details|routing)|"
    r"invoice\s*(change|update|revised|new)|payment\s*(details?|instructions?|urgent)|"
    r"accounts?\s*payable|remittance|ach\s*transfer|swift\s*code|routing\s*number|"
    r"ceo|cfo|president|urgent(ly)?|immediately|as\s*soon\s*as\s*possible|asap|"
    r"strictly\s*confidential|do\s*not\s*discuss)\b",
    re.IGNORECASE,
)

# Credential-harvesting indicators
# Rule: login/verify/password action language present
_CRED_KEYWORDS = re.compile(
    r"\b(verify(\s*your)?|confirm(\s*your)?|validate|login|log\s*in|sign\s*in|"
    r"account\s*(suspended|locked|limited|access|security)|password\s*(reset|expired?|update)|"
    r"click\s*here\s*to|update\s*your\s*(account|information|details?)|"
    r"unusual\s*activity|suspicious\s*sign\s*in|security\s*alert|"
    r"webmail|helpdesk|it\s*service|upgrade|re\s*confirm)\b",
    re.IGNORECASE,
)

# Known brand names used in display-name impersonation
# Rule: from_display contains these strings but from_domain ≠ brand's canonical domain
_BRAND_DOMAINS: dict[str, list[str]] = {
    "paypal":      ["paypal.com"],
    "amazon":      ["amazon.com", "amazon.co.uk", "amazon.in"],
    "apple":       ["apple.com", "icloud.com"],
    "microsoft":   ["microsoft.com", "outlook.com", "live.com", "office.com"],
    "google":      ["google.com", "gmail.com"],
    "netflix":     ["netflix.com"],
    "facebook":    ["facebook.com", "meta.com"],
    "instagram":   ["instagram.com"],
    "chase":       ["chase.com"],
    "wells fargo": ["wellsfargo.com"],
    "bank of america": ["bankofamerica.com"],
    "usaa":        ["usaa.com"],
    "irs":         ["irs.gov"],
    "dhl":         ["dhl.com"],
    "fedex":       ["fedex.com"],
    "ups":         ["ups.com"],
    "usps":        ["usps.com"],
    "cpanel":      ["cpanel.com", "cpanel.net"],
    "docusign":    ["docusign.com"],
    "dropbox":     ["dropbox.com"],
    "linkedin":    ["linkedin.com"],
}


# ---------------------------------------------------------------------------
# Model loading (lazy singleton — loaded once at first classify call)
# ---------------------------------------------------------------------------
_model_pipeline = None   # sklearn Pipeline(TfidfVectorizer, LogisticRegression)


def _load_model() -> Any:
    """Load the serialized classifier pipeline from disk. Returns None if not found."""
    global _model_pipeline
    if _model_pipeline is not None:
        return _model_pipeline

    if not MODEL_PATH.exists():
        log.warning(
            "Classifier model not found at %s. Run train_classifier.py first. "
            "All emails will be labeled 'suspicious' until the model is loaded.",
            MODEL_PATH,
        )
        return None

    try:
        _model_pipeline = joblib.load(MODEL_PATH)
        log.info("Classifier model loaded from %s", MODEL_PATH)
        return _model_pipeline
    except Exception as exc:
        log.error("Failed to load classifier model: %s", exc)
        return None


# ---------------------------------------------------------------------------
# LAYER 1 — ML classification
# ---------------------------------------------------------------------------
def _ml_classify(text: str) -> tuple[int, float]:
    """
    Run the TF-IDF + Logistic Regression classifier on email text.

    Returns:
        (ml_label, ml_confidence)  where ml_label ∈ {0, 1} and confidence ∈ [0, 1].
        If model unavailable: returns (1, 0.50) — treated as "suspicious" downstream.
    """
    pipeline = _load_model()
    if pipeline is None:
        return 1, 0.50   # model not available — treated as uncertain/suspicious

    try:
        proba = pipeline.predict_proba([text])[0]
        # proba[1] = probability of class 1 (phishing)
        phishing_prob = float(proba[1])
        ml_label = 1 if phishing_prob >= 0.50 else 0
        return ml_label, phishing_prob
    except Exception as exc:
        log.error("ML classifier prediction failed: %s", exc)
        return 1, 0.50


# ---------------------------------------------------------------------------
# LAYER 2 — Heuristic sub-classifier (NOT ML)
# ---------------------------------------------------------------------------
def _heuristic_subtype(
    body: str,
    subject: str,
    from_display: str,
    from_domain: str,
    urls: list[str],
) -> tuple[str, list[str]]:
    """
    Rule-based sub-classifier applied when ML flags phishing (confidence >= threshold).
    Returns (subtype_label, list_of_fired_indicator_strings).

    Labels returned: "impersonated" | "fraud-related" | "phishing"
    These are HEURISTIC outputs — not ML predictions. Documented explicitly.

    Rules (in priority order):
      1. IMPERSONATED: from_display contains a known brand name but from_domain
         is not that brand's canonical domain.
      2. FRAUD-RELATED (BEC): body+subject match BEC/payment-diversion keywords.
      3. PHISHING (credential-harvest): body+subject match login/verify keywords.
      4. PHISHING (generic): fallback — none of the above matched.
    """
    indicators: list[str] = []
    combined = f"{subject} {body}".lower()

    # --- Rule 1: Brand impersonation (display name vs sending domain) ---
    # [HEURISTIC] Not ML-derived. Checks if display name claims a known brand
    # but the actual From domain is not that brand's canonical domain.
    detected_brand = None
    display_lower = from_display.lower()
    for brand, canonical_domains in _BRAND_DOMAINS.items():
        if brand in display_lower:
            if not any(from_domain.endswith(cd) for cd in canonical_domains):
                detected_brand = brand
                indicators.append(
                    f"[HEURISTIC] Display name claims '{brand}' but sending domain "
                    f"'{from_domain}' does not match canonical domain(s): {canonical_domains}"
                )
                break

    if detected_brand:
        return "impersonated", indicators

    # --- Rule 2: BEC / payment-diversion ---
    # [HEURISTIC] Not ML-derived. Pattern-matches financial action + authority keywords.
    bec_matches = _BEC_KEYWORDS.findall(combined)
    if bec_matches:
        unique_matches = list({m[0] if isinstance(m, tuple) else m for m in bec_matches})[:5]
        indicators.append(
            f"[HEURISTIC] BEC/payment-diversion keywords detected: {unique_matches}"
        )
        return "fraud-related", indicators

    # --- Rule 3: Credential-harvesting ---
    # [HEURISTIC] Not ML-derived. Pattern-matches login/verify action language.
    cred_matches = _CRED_KEYWORDS.findall(combined)
    if cred_matches:
        unique_matches = list({m[0] if isinstance(m, tuple) else m for m in cred_matches})[:5]
        indicators.append(
            f"[HEURISTIC] Credential-harvesting keywords detected: {unique_matches}"
        )
        return "phishing", indicators

    # --- Rule 4: Generic phishing fallback ---
    indicators.append("[HEURISTIC] Generic phishing — no specific sub-type pattern matched")
    return "phishing", indicators


# ---------------------------------------------------------------------------
# Additional signals (always run, independent of ML label)
# ---------------------------------------------------------------------------
def _check_url_shorteners(urls: list[str]) -> list[str]:
    """
    Detect URLs using known link-shortening services.
    Flagged but NOT resolved (no live HTTP calls here — avoids timeouts + rate limits).
    """
    flagged = []
    for url in urls:
        for shortener in URL_SHORTENERS:
            if shortener in url.lower():
                flagged.append(f"URL shortener detected: {url[:80]}")
                break
    return flagged


def _check_suspicious_attachments(attachments: list[dict]) -> list[str]:
    """Flag attachments with high-risk file extensions."""
    flagged = []
    for att in attachments:
        fname = att.get("filename", "")
        suffix = Path(fname).suffix.lower()
        if suffix in SUSPICIOUS_EXTENSIONS:
            flagged.append(
                f"Suspicious attachment: '{fname}' "
                f"(type: {att.get('content_type', 'unknown')}, "
                f"sha256: {att.get('sha256', '')[:16]}...)"
            )
    return flagged


def _check_homograph(from_domain: str, urls: list[str]) -> list[str]:
    """
    Check from_domain and URL domains against trusted domain list using rapidfuzz.
    Returns list of indicator strings for matches above the threshold but not exact.

    This is a standalone check — also callable from origin_intel.py for domain intel.
    """
    try:
        from rapidfuzz import fuzz
        import unicodedata
    except ImportError:
        log.warning("rapidfuzz not available — homograph check skipped")
        return []

    indicators = []

    def _check_one_domain(domain: str, source_label: str) -> None:
        if not domain:
            return
        # Punycode-decode (e.g. xn--pypal-4ve.com → pypаl.com)
        try:
            decoded = domain.encode("ascii").decode("idna")
        except (UnicodeError, UnicodeDecodeError):
            decoded = domain

        for trusted in TRUSTED_DOMAINS:
            score = fuzz.ratio(decoded.lower(), trusted.lower())
            if HOMOGRAPH_FLAG_THRESHOLD < score < 100:
                indicators.append(
                    f"Homograph/lookalike domain ({source_label}): "
                    f"'{decoded}' resembles '{trusted}' "
                    f"(similarity: {score:.0f}%)"
                )

    _check_one_domain(from_domain, "sender domain")

    # Also check domains in extracted URLs
    url_domain_re = re.compile(r"https?://([^/?\s]+)", re.IGNORECASE)
    seen_url_domains: set[str] = set()
    for url in urls[:20]:   # cap at 20 to avoid slow loops on spammy emails
        m = url_domain_re.match(url)
        if m:
            d = m.group(1).lower().lstrip("www.")
            if d not in seen_url_domains:
                seen_url_domains.add(d)
                _check_one_domain(d, f"URL domain ({d})")

    return indicators


def _check_display_name_spoof(from_display: str, from_domain: str) -> list[str]:
    """
    Generic display-name spoof check beyond the hardcoded brand list.
    Flags cases where the display name looks like an email address that differs
    from the actual sending domain (common phishing trick).
    """
    indicators = []
    # Display name that contains an @ sign (e.g. "security@paypal.com" as the display name)
    if "@" in from_display:
        display_domain = from_display.split("@")[-1].strip(">).\" ").lower()
        if display_domain and display_domain != from_domain:
            indicators.append(
                f"Display-name spoofing: display name contains address "
                f"'{from_display}' but actual From domain is '{from_domain}'"
            )
    return indicators


# ---------------------------------------------------------------------------
# Main classify function
# ---------------------------------------------------------------------------
def classify(parsed_email: dict[str, Any]) -> dict[str, Any]:
    """
    Run the full two-layer classification pipeline on a parsed email dict
    (as returned by modules/parser.py parse_eml()).

    Args:
        parsed_email: dict from parse_eml()

    Returns:
        {
          "final_label":       str,    # legitimate/suspicious/impersonated/phishing/fraud-related
          "ml_label":          int,    # 0 or 1 (raw ML output)
          "ml_confidence":     float,  # 0.0–1.0, probability of phishing from ML model
          "heuristic_subtype": str | None,  # sub-type from Layer 2, or None
          "indicators":        [str],  # all fired signals (ML + heuristic + additional)
        }
    """
    subject      = parsed_email.get("subject", "") or ""
    body         = parsed_email.get("body_plain", "") or ""
    from_display = parsed_email.get("from_display", "") or ""
    from_domain  = parsed_email.get("from_domain", "") or ""
    urls         = parsed_email.get("urls", []) or []
    attachments  = parsed_email.get("attachments", []) or []

    # Combine subject + body for ML features (same as training)
    ml_text = f"{subject} {body}"

    # ------------------------------------------------------------------
    # LAYER 1: ML binary classification
    # ------------------------------------------------------------------
    ml_label, ml_confidence = _ml_classify(ml_text)

    indicators: list[str] = [
        f"[ML] Binary classifier confidence: {ml_confidence:.1%} "
        f"({'phishing' if ml_label == 1 else 'legitimate'})"
    ]

    # ------------------------------------------------------------------
    # LAYER 2: Heuristic sub-classifier (only when ML is confident phishing)
    # ------------------------------------------------------------------
    heuristic_subtype: str | None = None
    final_label: str

    if ml_confidence >= PHISHING_CONFIDENT_THRESHOLD:
        heuristic_subtype, h_indicators = _heuristic_subtype(
            body, subject, from_display, from_domain, urls
        )
        indicators.extend(h_indicators)
        final_label = heuristic_subtype

    elif ml_confidence >= SUSPICIOUS_THRESHOLD:
        # Uncertain zone — not confident enough to sub-classify
        final_label = "suspicious"
        indicators.append(
            f"[ML] Confidence in uncertain zone ({ml_confidence:.1%}) — "
            f"labeled 'suspicious', manual review recommended"
        )

    else:
        final_label = "legitimate"

    # ------------------------------------------------------------------
    # Additional signals (always run, independent of ML label)
    # ------------------------------------------------------------------
    shortener_flags  = _check_url_shorteners(urls)
    attachment_flags = _check_suspicious_attachments(attachments)
    homograph_flags  = _check_homograph(from_domain, urls)
    spoof_flags      = _check_display_name_spoof(from_display, from_domain)

    indicators.extend(shortener_flags)
    indicators.extend(attachment_flags)
    indicators.extend(homograph_flags)
    indicators.extend(spoof_flags)

    # If ML said legitimate but additional signals fired, upgrade to suspicious
    if final_label == "legitimate" and (
        shortener_flags or attachment_flags or homograph_flags or spoof_flags
    ):
        final_label = "suspicious"
        indicators.append(
            "[SIGNAL] Label upgraded from 'legitimate' to 'suspicious' "
            "due to additional structural indicators"
        )

    return {
        "final_label":       final_label,
        "ml_label":          ml_label,
        "ml_confidence":     round(ml_confidence, 4),
        "heuristic_subtype": heuristic_subtype,
        "indicators":        indicators,
    }
