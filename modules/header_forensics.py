"""
modules/header_forensics.py -- Stage 3: Email Header and Protocol Analysis

TWO AUTH PATHS:
  PRIMARY (real .eml with Authentication-Results header):
    - Parse the "Authentication-Results:" header stamped by the receiving mail server
    - Extract spf=, dkim=, dmarc= result tokens as-is (pass/fail/softfail/none/permerror/neutral)
    - This is ground truth from the receiving MTA -- most reliable path

  FALLBACK (synthetic .eml or any email without Authentication-Results):
    - Use checkdmarc (DNS queries) to fetch the sender domain's published SPF and DMARC policies
    - checkdmarc does NOT perform DKIM signature verification (it only checks policy records)
    - dkim is always recorded as "unknown" in fallback mode -- never fabricated
    - If DNS lookup fails (NXDOMAIN, timeout, no record), record as "none" with a note

ANOMALY CHECKS (always run, independent of auth path):
  1. Reply-To domain != From domain
  2. Return-Path domain != From domain
  3. Message-ID @domain != From domain
  4. Received chain relay anomaly (excessive hops, internal IP appearing unexpectedly)

This stage NEVER blocks the pipeline -- it records findings and passes them downstream
regardless of outcome, because a domain can pass all auth checks and still be a
lookalike, and a legitimate account can be compromised.
"""

import logging
import re
from typing import Any

log = logging.getLogger(__name__)

# Regex to extract Message-ID domain (the part after @)
_MSGID_DOMAIN_RE = re.compile(r"@([A-Za-z0-9.\-]+)>?\s*$")

# Authentication-Results token parser
# Matches: spf=pass, dkim=fail, dmarc=none, etc.
_AUTH_TOKEN_RE = re.compile(
    r"\b(spf|dkim|dmarc)\s*=\s*([a-zA-Z]+)",
    re.IGNORECASE,
)

# Private/reserved IP ranges for Received chain analysis
import ipaddress

_PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]

# IP extraction from Received header lines
_RECEIVED_IP_RE = re.compile(
    r"\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]"
    r"|from\s+\S+\s+\(.*?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})",
    re.IGNORECASE,
)


def _is_private_ip(ip_str: str) -> bool:
    """Return True if the IP address is in a private/reserved range."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return any(ip in net for net in _PRIVATE_NETWORKS)
    except ValueError:
        return False


def _extract_domain(address: str) -> str:
    """Extract lowercase domain from an email address string."""
    if not address:
        return ""
    # Strip angle brackets and whitespace
    addr = address.strip().strip("<>").lower()
    if "@" in addr:
        return addr.split("@")[-1].strip()
    return ""


# ---------------------------------------------------------------------------
# AUTH PATH 1: Parse Authentication-Results header
# ---------------------------------------------------------------------------
def _parse_auth_results_header(auth_results_raw: str) -> dict[str, str]:
    """
    Parse an Authentication-Results header value for spf/dkim/dmarc tokens.

    The header is stamped by the receiving MTA and looks like:
      mx.google.com;
        spf=pass smtp.mailfrom=sender@example.com;
        dkim=pass header.i=@example.com;
        dmarc=pass (p=REJECT) header.from=example.com

    Returns dict with keys: spf, dkim, dmarc -- values are the raw result strings
    (pass/fail/softfail/none/neutral/temperror/permerror).
    Missing tokens default to "unknown".
    """
    results = {"spf": "unknown", "dkim": "unknown", "dmarc": "unknown"}
    if not auth_results_raw:
        return results

    for match in _AUTH_TOKEN_RE.finditer(auth_results_raw):
        proto  = match.group(1).lower()
        result = match.group(2).lower()
        if proto in results:
            results[proto] = result

    return results


# ---------------------------------------------------------------------------
# AUTH PATH 2: DNS fallback via checkdmarc
# ---------------------------------------------------------------------------
# Public DNS resolvers -- used by checkdmarc to bypass potentially broken local resolvers.
# Confirmed working on this machine: local resolver times out, 8.8.8.8 resolves correctly.
_PUBLIC_NAMESERVERS = ["8.8.8.8", "1.1.1.1"]


def _dns_fallback_auth(domain: str) -> dict[str, str]:
    """
    Query the sender domain's published SPF and DMARC DNS records using checkdmarc.
    Uses public resolvers (8.8.8.8, 1.1.1.1) -- confirmed working; local resolver times out.

    Returns dict with spf, dkim, dmarc values.

    Real checkdmarc return schema (confirmed via live test 2026-09-06):
      check_spf() -> dict with keys: record, valid (bool), dns_lookups, void_dns_lookups,
                     warnings, parsed, [error] (only present on failure)
      check_dmarc() -> dict with keys: record, location, valid (bool), warnings, tags
                       tags['p']['value'] = policy string (e.g. 'reject', 'none', 'quarantine')

    IMPORTANT:
    - SPF result = "record_exists" if domain has a valid published SPF record
      (does NOT mean this specific email passed SPF -- no envelope sender available)
    - dkim is ALWAYS "unknown" -- checkdmarc cannot verify DKIM without the email signature
    - DMARC result = "record_exists_policy_{p}" if domain has valid DMARC record
    """
    results = {"spf": "unknown", "dkim": "unknown", "dmarc": "unknown"}

    if not domain:
        log.warning("DNS fallback: no domain provided -- returning all unknown")
        return results

    ns = _PUBLIC_NAMESERVERS

    # --- SPF ---
    try:
        import checkdmarc
        spf_raw = checkdmarc.check_spf(domain, nameservers=ns, timeout=5, retries=1)
        # Confirmed schema: dict with 'valid' (bool) and optional 'error' key
        if spf_raw.get("valid") is True:
            results["spf"] = "record_exists"
        elif spf_raw.get("error"):
            results["spf"] = "none"
            log.debug("SPF DNS fallback for %s: %s", domain, str(spf_raw.get("error"))[:100])
        else:
            results["spf"] = "none"
    except Exception as exc:
        log.warning("checkdmarc SPF lookup failed for %s: %s", domain, exc)
        results["spf"] = "lookup_failed"

    # --- DMARC ---
    try:
        import checkdmarc
        dmarc_raw = checkdmarc.check_dmarc(domain, nameservers=ns, timeout=5, retries=1)
        # Confirmed schema: dict with 'valid' (bool) and 'tags' dict
        if dmarc_raw.get("valid") is True:
            tags   = dmarc_raw.get("tags", {})
            policy = tags.get("p", {}).get("value", "unknown") if isinstance(tags, dict) else "unknown"
            results["dmarc"] = f"record_exists_policy_{policy}"
        elif dmarc_raw.get("error"):
            results["dmarc"] = "none"
            log.debug("DMARC DNS fallback for %s: %s", domain, str(dmarc_raw.get("error"))[:100])
        else:
            results["dmarc"] = "none"
    except Exception as exc:
        log.warning("checkdmarc DMARC lookup failed for %s: %s", domain, exc)
        results["dmarc"] = "lookup_failed"

    # --- DKIM: always unknown in DNS fallback mode (per spec) ---
    results["dkim"] = "unknown"
    log.debug(
        "DNS fallback for %s: SPF=%s DKIM=%s(always-unknown) DMARC=%s",
        domain, results["spf"], results["dkim"], results["dmarc"],
    )
    return results


# ---------------------------------------------------------------------------
# Anomaly checks
# ---------------------------------------------------------------------------
def _check_anomalies(parsed_email: dict[str, Any]) -> list[str]:
    """
    Check for structural header anomalies that are common phishing indicators.
    Returns a list of human-readable anomaly description strings.
    Each anomaly is a finding -- NOT a proof of malice on its own.
    """
    anomalies: list[str] = []

    from_domain        = parsed_email.get("from_domain", "") or ""
    reply_to_domain    = parsed_email.get("reply_to_domain") or ""
    return_path_domain = parsed_email.get("return_path_domain") or ""
    message_id         = parsed_email.get("message_id", "") or ""
    received_chain     = parsed_email.get("received_chain", []) or []

    # --- Anomaly 1: Reply-To domain != From domain ---
    # Common in phishing: sender appears to be support@bank.com but replies go
    # to a different address the attacker controls.
    if reply_to_domain and from_domain and reply_to_domain != from_domain:
        anomalies.append(
            f"Reply-To domain mismatch: Reply-To domain '{reply_to_domain}' "
            f"!= From domain '{from_domain}'"
        )

    # --- Anomaly 2: Return-Path domain != From domain ---
    # Legitimate bulk senders use separate Return-Path (bounce) addresses, so
    # this is a soft signal. Flag it but don't over-weight it.
    if return_path_domain and from_domain and return_path_domain != from_domain:
        anomalies.append(
            f"Return-Path domain mismatch: Return-Path domain '{return_path_domain}' "
            f"!= From domain '{from_domain}'"
        )

    # --- Anomaly 3: Message-ID @domain != From domain ---
    # A Message-ID claiming to come from paypal.com but with @randomhost.ru
    # is suspicious. Allow a one-level parent domain match (e.g. mail.paypal.com OK).
    msgid_match = _MSGID_DOMAIN_RE.search(message_id)
    if msgid_match:
        msgid_domain = msgid_match.group(1).lower()
        # Normalize: strip leading subdomain for comparison (mail.example.com → example.com)
        def _base(d: str) -> str:
            parts = d.split(".")
            return ".".join(parts[-2:]) if len(parts) >= 2 else d
        if from_domain and msgid_domain and _base(msgid_domain) != _base(from_domain):
            anomalies.append(
                f"Message-ID domain mismatch: Message-ID @{msgid_domain} "
                f"!= From domain '{from_domain}'"
            )

    # --- Anomaly 4: Received chain relay anomalies ---
    if received_chain:
        hop_count = len(received_chain)

        # Flag very long chains (> 6 hops is unusual for normal mail)
        if hop_count > 6:
            anomalies.append(
                f"Excessive relay hops: {hop_count} Received headers "
                f"(>6 is unusual -- possible obfuscation)"
            )

        # Extract IPs from each Received header and flag if a private IP appears
        # at an unexpected position (late in the chain = closer to recipient)
        # The FIRST Received header (index 0 in chain, oldest) should be external.
        external_ips_in_chain = []
        for i, rcvd in enumerate(received_chain):
            ip_matches = _RECEIVED_IP_RE.findall(rcvd)
            for grp1, grp2 in ip_matches:
                ip_str = grp1 or grp2
                if ip_str and not _is_private_ip(ip_str):
                    external_ips_in_chain.append((i, ip_str))

        # If no external IPs at all and chain is non-empty → likely synthetic or pure internal
        if received_chain and not external_ips_in_chain:
            # Don't flag synthetic samples (they're expected to have no IPs)
            if not parsed_email.get("x_synthetic"):
                anomalies.append(
                    "No external IP found in Received chain -- "
                    "may indicate internal-only relay or header manipulation"
                )
    else:
        # No Received chain -- expected for synthetic CSV-derived samples.
        # Real emails always have at least one Received header.
        if not parsed_email.get("x_synthetic"):
            anomalies.append(
                "No Received headers found -- real emails always have at least one. "
                "Possible header stripping."
            )

    return anomalies


# ---------------------------------------------------------------------------
# Main forensics function
# ---------------------------------------------------------------------------
def analyze(parsed_email: dict[str, Any]) -> dict[str, Any]:
    """
    Run full header and protocol analysis on a parsed email dict.

    Args:
        parsed_email: dict from modules.parser.parse_eml()

    Returns:
        {
          "spf":         str,   # "pass"/"fail"/"softfail"/"none"/"unknown"/
                                # "record_exists"/"lookup_failed"
          "dkim":        str,   # "pass"/"fail"/"unknown" (never fabricated in fallback)
          "dmarc":       str,   # "pass"/"fail"/"none"/"unknown"/"record_exists_policy_X"
          "auth_source": str,   # "header" (parsed from Authentication-Results)
                                # or "dns_fallback" (checkdmarc DNS lookup)
          "auth_note":   str,   # human-readable explanation of what the result means
          "anomalies":   [str], # list of fired anomaly descriptions
        }
    """
    auth_results_raw = parsed_email.get("auth_results_raw")
    from_domain      = parsed_email.get("from_domain", "") or ""

    # ------------------------------------------------------------------
    # Choose auth path
    # ------------------------------------------------------------------
    if auth_results_raw:
        # PRIMARY: Parse existing Authentication-Results header
        auth = _parse_auth_results_header(auth_results_raw)
        auth_source = "header"
        auth_note = (
            "Authentication results parsed from the Authentication-Results header "
            "stamped by the receiving mail server. These are actual pass/fail outcomes "
            "for this specific email."
        )
        log.debug("Stage 3: Using Authentication-Results header for %s", from_domain)
    else:
        # FALLBACK: DNS-based policy lookup (no actual auth outcome available)
        auth = _dns_fallback_auth(from_domain)
        auth_source = "dns_fallback"
        auth_note = (
            f"No Authentication-Results header found (expected for synthetic .eml files). "
            f"DNS fallback via checkdmarc checked domain '{from_domain}' for published "
            f"SPF/DMARC policy records. DKIM is always 'unknown' in this mode -- "
            f"checkdmarc cannot verify DKIM without the actual email signature."
        )
        log.debug("Stage 3: DNS fallback for domain '%s'", from_domain)

    # ------------------------------------------------------------------
    # Anomaly checks (always run)
    # ------------------------------------------------------------------
    anomalies = _check_anomalies(parsed_email)

    return {
        "spf":         auth["spf"],
        "dkim":        auth["dkim"],
        "dmarc":       auth["dmarc"],
        "auth_source": auth_source,
        "auth_note":   auth_note,
        "anomalies":   anomalies,
    }
