"""
modules/origin_intel.py -- Stage 4: Origin Traceability, Location and Domain Intelligence

Sub-stages run concurrently via ThreadPoolExecutor where independent:
  4a: IP/URL threat reputation (VirusTotal, AbuseIPDB, Feodo, URLhaus, TOR)
  4b: Geolocation + cloud/hosting infrastructure heuristic (GeoLite2-City.mmdb)
  4c: Domain intelligence (WHOIS, DNS/MX, homograph)

Key design principles:
  - Every external call is cached in SQLite (forensics.db) keyed by IP/URL/domain
  - If any service fails (rate-limited, no key, timeout): log warning, return None, continue
  - Feodo, URLhaus, TOR are bulk feeds loaded into memory sets at module startup
  - GeoLite2-ASN.mmdb is optional -- checked at runtime, skipped gracefully if missing
  - DKIM verification NOT performed here (see Stage 3 notes)
"""

import hashlib
import ipaddress
import json
import logging
import os
import re
import sqlite3
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import requests
from dotenv import load_dotenv

load_dotenv()

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Config (imported from config.py)
# ---------------------------------------------------------------------------
from config import (
    DATA_DIR,
    DB_PATH,
    FEODO_CACHE,
    FEODO_URL,
    URLHAUS_CACHE,
    URLHAUS_URL,
    TOR_CACHE,
    TOR_URL,
    FEED_CACHE_TTL_SECONDS,
    GEOIP_CITY_DB,
    GEOIP_ASN_DB,
    TRUSTED_DOMAINS,
    HOMOGRAPH_FLAG_THRESHOLD,
    CLOUD_HOSTING_KEYWORDS,
    NEW_DOMAIN_AGE_DAYS,
)

# ---------------------------------------------------------------------------
# API keys (from environment -- never hardcoded, never logged)
# ---------------------------------------------------------------------------
VT_API_KEY        = os.getenv("VT_API_KEY")
ABUSEIPDB_API_KEY = os.getenv("ABUSEIPDB_API_KEY")

# VirusTotal rate limit: 4 requests/minute on free tier
_VT_RATE_LIMIT_DELAY = 15.0   # seconds between VT requests (60s / 4 = 15s)
_last_vt_call = 0.0

# ---------------------------------------------------------------------------
# Private IP ranges for filtering Received chain IPs
# ---------------------------------------------------------------------------
_PRIVATE_NETS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("::1/128"),
]

_IP_RE = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")


def _is_private(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
        return any(ip in net for net in _PRIVATE_NETS)
    except ValueError:
        return False


# ---------------------------------------------------------------------------
# SQLite cache helpers
# ---------------------------------------------------------------------------
def _get_db() -> sqlite3.Connection:
    conn = sqlite3.connect(str(DB_PATH))
    conn.row_factory = sqlite3.Row
    return conn


def _ensure_cache_table(conn: sqlite3.Connection) -> None:
    conn.execute("""
        CREATE TABLE IF NOT EXISTS cache_lookups (
            key         TEXT NOT NULL,
            source      TEXT NOT NULL,
            response_json TEXT,
            fetched_at  REAL NOT NULL,
            PRIMARY KEY (key, source)
        )
    """)
    conn.commit()


def _cache_get(key: str, source: str, ttl_seconds: float = FEED_CACHE_TTL_SECONDS) -> Any | None:
    """Return cached JSON-decoded value if not expired, else None."""
    try:
        with _get_db() as conn:
            _ensure_cache_table(conn)
            row = conn.execute(
                "SELECT response_json, fetched_at FROM cache_lookups WHERE key=? AND source=?",
                (key, source),
            ).fetchone()
            if row:
                age = time.time() - row["fetched_at"]
                if age < ttl_seconds:
                    return json.loads(row["response_json"])
    except Exception as exc:
        log.warning("Cache read failed for %s/%s: %s", source, key, exc)
    return None


def _cache_set(key: str, source: str, value: Any) -> None:
    """Store a JSON-serializable value in the cache."""
    try:
        with _get_db() as conn:
            _ensure_cache_table(conn)
            conn.execute(
                """INSERT OR REPLACE INTO cache_lookups (key, source, response_json, fetched_at)
                   VALUES (?, ?, ?, ?)""",
                (key, source, json.dumps(value, default=str), time.time()),
            )
            conn.commit()
    except Exception as exc:
        log.warning("Cache write failed for %s/%s: %s", source, key, exc)


# ---------------------------------------------------------------------------
# Bulk threat feed loaders (cached on disk, loaded into memory sets at startup)
# ---------------------------------------------------------------------------
_feodo_ips:   set[str] = set()
_urlhaus_urls: set[str] = set()
_tor_exits:   set[str] = set()
_feeds_loaded = False


def _refresh_feed(url: str, cache_path: Path, label: str) -> bytes | None:
    """Download a threat feed if cache is stale (>TTL hours old)."""
    if cache_path.exists():
        age = time.time() - cache_path.stat().st_mtime
        if age < FEED_CACHE_TTL_SECONDS:
            log.debug("%s feed cache is fresh (%.1fh old)", label, age / 3600)
            return cache_path.read_bytes()

    log.info("Refreshing %s feed from %s ...", label, url)
    try:
        resp = requests.get(url, timeout=15)
        resp.raise_for_status()
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        cache_path.write_bytes(resp.content)
        log.info("%s feed cached to %s (%d bytes)", label, cache_path, len(resp.content))
        return resp.content
    except Exception as exc:
        log.warning("Failed to refresh %s feed: %s -- using stale cache if available", label, exc)
        if cache_path.exists():
            return cache_path.read_bytes()
        return None


def load_threat_feeds() -> None:
    """Load Feodo, URLhaus, and TOR feeds into memory. Call once at app startup."""
    global _feodo_ips, _urlhaus_urls, _tor_exits, _feeds_loaded

    # -- Feodo Tracker (JSON list of botnet C2 IPs) --
    raw = _refresh_feed(FEODO_URL, FEODO_CACHE, "Feodo")
    if raw:
        try:
            data = json.loads(raw)
            _feodo_ips = {entry["ip_address"] for entry in data if "ip_address" in entry}
            log.info("Feodo: %d botnet C2 IPs loaded", len(_feodo_ips))
        except Exception as exc:
            log.warning("Feodo feed parse failed: %s", exc)

    # -- URLhaus (plain text, one URL per line, lines starting with # are comments) --
    raw = _refresh_feed(URLHAUS_URL, URLHAUS_CACHE, "URLhaus")
    if raw:
        try:
            lines = raw.decode("utf-8", errors="replace").splitlines()
            _urlhaus_urls = {
                line.strip() for line in lines
                if line.strip() and not line.startswith("#")
            }
            log.info("URLhaus: %d malware URLs loaded", len(_urlhaus_urls))
        except Exception as exc:
            log.warning("URLhaus feed parse failed: %s", exc)

    # -- TOR exit node list (plain text, one IP per line) --
    raw = _refresh_feed(TOR_URL, TOR_CACHE, "TOR exit nodes")
    if raw:
        try:
            lines = raw.decode("utf-8", errors="replace").splitlines()
            _tor_exits = {
                line.strip() for line in lines
                if line.strip() and not line.startswith("#")
            }
            log.info("TOR: %d exit nodes loaded", len(_tor_exits))
        except Exception as exc:
            log.warning("TOR feed parse failed: %s", exc)

    _feeds_loaded = True


def _ensure_feeds_loaded() -> None:
    if not _feeds_loaded:
        load_threat_feeds()


# ---------------------------------------------------------------------------
# 4a: IP extraction and threat/reputation correlation
# ---------------------------------------------------------------------------
def _extract_ips_from_received(received_chain: list[str]) -> list[str]:
    """Extract external IPs from the Received header chain (oldest hop first)."""
    ips = []
    for header in received_chain:
        for ip in _IP_RE.findall(header):
            if not _is_private(ip) and ip not in ips:
                ips.append(ip)
    return ips


def _vt_lookup_ip(ip: str) -> dict | None:
    """Query VirusTotal for an IP address reputation. Cached 24h."""
    global _last_vt_call
    if not VT_API_KEY:
        log.debug("VT_API_KEY not set -- skipping VirusTotal IP lookup")
        return None

    cached = _cache_get(ip, "virustotal_ip")
    if cached is not None:
        return cached

    # Rate limiting: wait if needed
    elapsed = time.time() - _last_vt_call
    if elapsed < _VT_RATE_LIMIT_DELAY:
        time.sleep(_VT_RATE_LIMIT_DELAY - elapsed)

    try:
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={"x-apikey": VT_API_KEY},
            timeout=10,
        )
        _last_vt_call = time.time()
        if resp.status_code == 429:
            log.warning("VirusTotal rate limit hit for IP %s -- skipping", ip)
            return None
        resp.raise_for_status()
        data = resp.json()
        # Extract summary: malicious/suspicious vote counts
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        result = {
            "malicious":   stats.get("malicious", 0),
            "suspicious":  stats.get("suspicious", 0),
            "harmless":    stats.get("harmless", 0),
            "undetected":  stats.get("undetected", 0),
            "country":     data.get("data", {}).get("attributes", {}).get("country", ""),
            "as_owner":    data.get("data", {}).get("attributes", {}).get("as_owner", ""),
        }
        _cache_set(ip, "virustotal_ip", result)
        return result
    except Exception as exc:
        log.warning("VirusTotal IP lookup failed for %s: %s", ip, exc)
        return None


def _vt_lookup_url(url: str) -> dict | None:
    """Query VirusTotal for a URL reputation. Cached 24h."""
    global _last_vt_call
    if not VT_API_KEY:
        return None

    # VT URL identifier = base64url(url) without padding
    import base64
    url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")

    cached = _cache_get(url_id, "virustotal_url")
    if cached is not None:
        return cached

    elapsed = time.time() - _last_vt_call
    if elapsed < _VT_RATE_LIMIT_DELAY:
        time.sleep(_VT_RATE_LIMIT_DELAY - elapsed)

    try:
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/urls/{url_id}",
            headers={"x-apikey": VT_API_KEY},
            timeout=10,
        )
        _last_vt_call = time.time()
        if resp.status_code in (404, 429):
            log.warning("VT URL lookup returned %s for %s", resp.status_code, url[:60])
            return None
        resp.raise_for_status()
        data = resp.json()
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        result = {
            "malicious":  stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "harmless":   stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
        }
        _cache_set(url_id, "virustotal_url", result)
        return result
    except Exception as exc:
        log.warning("VirusTotal URL lookup failed for %s: %s", url[:60], exc)
        return None


def _abuseipdb_lookup(ip: str) -> dict | None:
    """Query AbuseIPDB for an IP's confidence score and usage type. Cached 24h."""
    if not ABUSEIPDB_API_KEY:
        log.debug("ABUSEIPDB_API_KEY not set -- skipping AbuseIPDB lookup")
        return None

    cached = _cache_get(ip, "abuseipdb")
    if cached is not None:
        return cached

    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": ABUSEIPDB_API_KEY, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": False},
            timeout=10,
        )
        if resp.status_code == 429:
            log.warning("AbuseIPDB rate limit hit for %s", ip)
            return None
        resp.raise_for_status()
        data = resp.json().get("data", {})
        result = {
            "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
            "usage_type":             data.get("usageType", ""),
            "isp":                    data.get("isp", ""),
            "country_code":           data.get("countryCode", ""),
            "total_reports":          data.get("totalReports", 0),
        }
        _cache_set(ip, "abuseipdb", result)
        return result
    except Exception as exc:
        log.warning("AbuseIPDB lookup failed for %s: %s", ip, exc)
        return None


def _check_feeds(ip: str, urls: list[str]) -> dict:
    """Check an IP and URL list against locally cached bulk threat feeds."""
    _ensure_feeds_loaded()
    return {
        "feodo_hit":   ip in _feodo_ips,
        "tor_hit":     ip in _tor_exits,
        "urlhaus_hits": [u for u in urls if u in _urlhaus_urls],
    }


def analyze_reputation(
    received_chain: list[str],
    urls: list[str],
    attachment_sha256s: list[str],
) -> dict[str, Any]:
    """
    Sub-stage 4a: IP extraction + threat/reputation correlation.
    Returns dict of all reputation signals.
    """
    _ensure_feeds_loaded()

    ips = _extract_ips_from_received(received_chain)
    origin_ip = ips[0] if ips else None   # earliest external IP = likely original sender

    feed_hits = _check_feeds(origin_ip or "", urls)

    vt_ip_result  = _vt_lookup_ip(origin_ip) if origin_ip else None
    abuse_result  = _abuseipdb_lookup(origin_ip) if origin_ip else None

    # Check up to 3 URLs with VT (cap to preserve rate limit)
    vt_url_results = {}
    for url in urls[:3]:
        res = _vt_lookup_url(url)
        if res:
            vt_url_results[url[:60]] = res

    return {
        "ips_found":           ips,
        "origin_ip":           origin_ip,
        "is_tor":              feed_hits["tor_hit"],
        "is_botnet_c2":        feed_hits["feodo_hit"],
        "urlhaus_hits":        feed_hits["urlhaus_hits"],
        "vt_ip":               vt_ip_result,
        "vt_urls":             vt_url_results,
        "abuseipdb":           abuse_result,
    }


# ---------------------------------------------------------------------------
# 4b: Geolocation and infrastructure profiling
# ---------------------------------------------------------------------------
def analyze_geolocation(origin_ip: str | None) -> dict[str, Any]:
    """
    Sub-stage 4b: GeoIP lookup + cloud/hosting heuristic.
    Returns geo dict. All fields default to None if data unavailable.
    """
    base = {
        "city":         None,
        "country":      None,
        "lat":          None,
        "lon":          None,
        "asn_org":      None,
        "is_cloud_host": False,
    }

    if not origin_ip:
        return base

    if not GEOIP_CITY_DB.exists():
        log.warning("GeoLite2-City.mmdb not found at %s -- geolocation unavailable", GEOIP_CITY_DB)
        return base

    try:
        import geoip2.database
        with geoip2.database.Reader(str(GEOIP_CITY_DB)) as reader:
            record = reader.city(origin_ip)
            base["city"]    = record.city.name
            base["country"] = record.country.iso_code
            loc = record.location
            base["lat"] = loc.latitude
            base["lon"] = loc.longitude
    except Exception as exc:
        log.debug("GeoIP city lookup failed for %s: %s", origin_ip, exc)

    # ASN enrichment (optional -- GeoLite2-ASN.mmdb may not exist)
    if GEOIP_ASN_DB.exists():
        try:
            import geoip2.database
            with geoip2.database.Reader(str(GEOIP_ASN_DB)) as reader:
                asn_record = reader.asn(origin_ip)
                base["asn_org"] = asn_record.autonomous_system_organization
        except Exception as exc:
            log.debug("GeoIP ASN lookup failed for %s: %s", origin_ip, exc)
    else:
        log.warning(
            "GeoLite2-ASN.mmdb not found -- ASN/cloud-host enrichment disabled. "
            "Download from MaxMind to enable this feature."
        )

    # Cloud/hosting heuristic
    # [HEURISTIC] Not ML-derived. If ASN org name contains a known cloud/hosting keyword,
    # flag as 'likely hosting/cloud infrastructure'. Most legitimate personal/business mail
    # does not originate directly from cloud IP ranges -- this is a genuine phishing signal.
    if base["asn_org"]:
        org_lower = base["asn_org"].lower()
        for keyword in CLOUD_HOSTING_KEYWORDS:
            if keyword.lower() in org_lower:
                base["is_cloud_host"] = True
                log.debug("Cloud host detected for %s: ASN org '%s'", origin_ip, base["asn_org"])
                break

    return base


# ---------------------------------------------------------------------------
# 4c: Domain intelligence (WHOIS + DNS/MX + homograph)
# ---------------------------------------------------------------------------
def _whois_age(domain: str) -> tuple[int | None, str]:
    """
    Query WHOIS for domain creation date.
    Returns (age_in_days or None, status_string).
    status_string: "new" / "established" / "age_unknown"
    """
    cached = _cache_get(domain, "whois_age")
    if cached is not None:
        return cached["age_days"], cached["status"]

    try:
        import whois as python_whois
        w = python_whois.whois(domain)
        creation = w.creation_date
        if creation is None:
            # Privacy-protected or unavailable -- record as distinct state
            _cache_set(domain, "whois_age", {"age_days": None, "status": "age_unknown"})
            return None, "age_unknown"

        if isinstance(creation, list):
            creation = creation[0]

        if hasattr(creation, "tzinfo") and creation.tzinfo is None:
            creation = creation.replace(tzinfo=timezone.utc)

        age_days = (datetime.now(timezone.utc) - creation).days
        status   = "new" if age_days < NEW_DOMAIN_AGE_DAYS else "established"
        _cache_set(domain, "whois_age", {"age_days": age_days, "status": status})
        return age_days, status
    except Exception as exc:
        log.warning("WHOIS lookup failed for %s: %s", domain, exc)
        _cache_set(domain, "whois_age", {"age_days": None, "status": "age_unknown"})
        return None, "age_unknown"


def _mx_suspicious(domain: str) -> tuple[bool, str]:
    """
    Check if the domain's MX record points to a known free/generic webmail provider.
    Returns (is_suspicious, mx_host_or_note).
    """
    _FREE_MAIL_PROVIDERS = {
        "gmail.com", "googlemail.com",
        "yahoo.com", "yahoo.co.in", "yahoo.co.uk",
        "outlook.com", "hotmail.com", "live.com",
        "mail.com", "gmx.com", "gmx.net",
        "protonmail.com", "proton.me",
        "zoho.com",
        "icloud.com", "me.com", "mac.com",
        "aol.com",
    }

    cached = _cache_get(domain, "mx_check")
    if cached is not None:
        return cached["suspicious"], cached["mx_host"]

    try:
        import dns.resolver
        resolver = dns.resolver.Resolver()
        resolver.nameservers = ["8.8.8.8", "1.1.1.1"]
        resolver.timeout = 5
        resolver.lifetime = 8

        answers = resolver.resolve(domain, "MX")
        if not answers:
            _cache_set(domain, "mx_check", {"suspicious": False, "mx_host": "no_mx_record"})
            return False, "no_mx_record"

        # Take the lowest-priority (most preferred) MX
        best_mx = min(answers, key=lambda r: r.preference)
        mx_host = str(best_mx.exchange).rstrip(".").lower()

        # Check if MX host is a generic free mail provider
        suspicious = any(mx_host.endswith(p) for p in _FREE_MAIL_PROVIDERS)
        _cache_set(domain, "mx_check", {"suspicious": suspicious, "mx_host": mx_host})
        return suspicious, mx_host
    except Exception as exc:
        log.warning("MX lookup failed for %s: %s", domain, exc)
        _cache_set(domain, "mx_check", {"suspicious": False, "mx_host": f"lookup_failed: {exc}"})
        return False, "lookup_failed"


def homograph_check(domain: str) -> tuple[str | None, float | None]:
    """
    Check a domain against the trusted domain list using rapidfuzz similarity.
    Punycode-decodes the domain first (catches IDN homograph attacks).

    Returns (closest_match_domain, similarity_score) if above threshold but not exact,
    else (None, None).

    This function is also called by content_classifier.py.
    """
    if not domain:
        return None, None

    try:
        from rapidfuzz import fuzz

        # Punycode decode (e.g. xn--pypal-4ve.com -> pypаl.com in IDN)
        try:
            decoded = domain.encode("ascii").decode("idna")
        except (UnicodeError, UnicodeDecodeError):
            decoded = domain

        best_match = None
        best_score = 0.0

        for trusted in TRUSTED_DOMAINS:
            score = fuzz.ratio(decoded.lower(), trusted.lower())
            if score > best_score:
                best_score = score
                best_match = trusted

        if best_score > HOMOGRAPH_FLAG_THRESHOLD and best_score < 100:
            return best_match, round(best_score, 1)
        return None, None
    except ImportError:
        log.warning("rapidfuzz not available -- homograph check skipped")
        return None, None
    except Exception as exc:
        log.warning("Homograph check failed for %s: %s", domain, exc)
        return None, None


def analyze_domain_intel(domain: str) -> dict[str, Any]:
    """
    Sub-stage 4c: WHOIS + DNS/MX + homograph analysis for the sender domain.
    """
    if not domain:
        return {
            "domain_age_days":   None,
            "domain_age_status": "age_unknown",
            "mx_suspicious":     False,
            "mx_host":           None,
            "homograph_match":   None,
            "homograph_score":   None,
        }

    age_days, age_status = _whois_age(domain)
    mx_susp, mx_host     = _mx_suspicious(domain)
    homo_match, homo_score = homograph_check(domain)

    return {
        "domain_age_days":   age_days,
        "domain_age_status": age_status,
        "mx_suspicious":     mx_susp,
        "mx_host":           mx_host,
        "homograph_match":   homo_match,
        "homograph_score":   homo_score,
    }


# ---------------------------------------------------------------------------
# Main Stage 4 entry point -- runs 4a, 4b, 4c concurrently
# ---------------------------------------------------------------------------
def analyze(parsed_email: dict[str, Any]) -> dict[str, Any]:
    """
    Run all three sub-stages concurrently and merge results.

    Args:
        parsed_email: dict from modules.parser.parse_eml()

    Returns:
        Merged dict with keys from 4a, 4b, 4c plus a combined infrastructure profile.
    """
    received_chain = parsed_email.get("received_chain", []) or []
    urls           = parsed_email.get("urls", []) or []
    attachments    = parsed_email.get("attachments", []) or []
    from_domain    = parsed_email.get("from_domain", "") or ""

    sha256s = [a["sha256"] for a in attachments if a.get("sha256")]

    # ------------------------------------------------------------------
    # Run 4a, 4b (needs origin_ip from 4a), 4c concurrently
    # 4b depends on origin_ip from 4a, so we run 4a first, then 4b+4c together
    # ------------------------------------------------------------------
    reputation: dict = {}
    geo:        dict = {}
    domain_intel: dict = {}

    with ThreadPoolExecutor(max_workers=3) as pool:
        # 4a runs first (origin_ip needed by 4b)
        fut_4a = pool.submit(analyze_reputation, received_chain, urls, sha256s)

        try:
            reputation = fut_4a.result(timeout=30)
        except Exception as exc:
            log.warning("Stage 4a (reputation) failed: %s", exc)
            reputation = {
                "ips_found": [], "origin_ip": None,
                "is_tor": False, "is_botnet_c2": False,
                "urlhaus_hits": [], "vt_ip": None, "vt_urls": {}, "abuseipdb": None,
            }

        origin_ip = reputation.get("origin_ip")

        # 4b and 4c can now run concurrently
        fut_4b = pool.submit(analyze_geolocation, origin_ip)
        fut_4c = pool.submit(analyze_domain_intel, from_domain)

        try:
            geo = fut_4b.result(timeout=15)
        except Exception as exc:
            log.warning("Stage 4b (geolocation) failed: %s", exc)
            geo = {"city": None, "country": None, "lat": None, "lon": None,
                   "asn_org": None, "is_cloud_host": False}

        try:
            domain_intel = fut_4c.result(timeout=30)
        except Exception as exc:
            log.warning("Stage 4c (domain intel) failed: %s", exc)
            domain_intel = {
                "domain_age_days": None, "domain_age_status": "age_unknown",
                "mx_suspicious": False, "mx_host": None,
                "homograph_match": None, "homograph_score": None,
            }

    # ------------------------------------------------------------------
    # Combine into infrastructure profile
    # ------------------------------------------------------------------
    infra_flags = []
    if reputation.get("is_tor"):
        infra_flags.append("TOR exit node")
    if reputation.get("is_botnet_c2"):
        infra_flags.append("known botnet C2 (Feodo Tracker)")
    if geo.get("is_cloud_host") and geo.get("asn_org"):
        infra_flags.append(
            f"cloud/hosting infrastructure ({geo['asn_org']}) -- "
            "most legitimate personal/business mail does not originate from cloud IP ranges"
        )
    if reputation.get("urlhaus_hits"):
        infra_flags.append(f"URLhaus malware URL hits: {len(reputation['urlhaus_hits'])}")
    if domain_intel.get("domain_age_status") == "new":
        infra_flags.append(
            f"newly registered domain ({domain_intel['domain_age_days']} days old)"
        )
    if domain_intel.get("mx_suspicious"):
        infra_flags.append(
            f"suspicious MX record: domain '{from_domain}' routes mail through "
            f"'{domain_intel['mx_host']}' (free/generic provider)"
        )
    if domain_intel.get("homograph_match"):
        infra_flags.append(
            f"homograph/lookalike domain: '{from_domain}' resembles "
            f"'{domain_intel['homograph_match']}' "
            f"({domain_intel['homograph_score']:.0f}% similarity)"
        )

    return {
        # 4a: reputation
        **reputation,
        # 4b: geo
        **geo,
        # 4c: domain intel
        **domain_intel,
        # Combined
        "infrastructure_flags": infra_flags,
    }
