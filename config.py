"""
config.py — Central configuration for the Email Threat Detection Platform.

All adjustable thresholds, weight constants, and settings live here so that
judges/reviewers can tune the system without touching pipeline code.
"""

from pathlib import Path

# ---------------------------------------------------------------------------
# Paths (always use pathlib.Path — never plain backslash strings)
# ---------------------------------------------------------------------------
PROJECT_ROOT = Path(__file__).parent
DATA_DIR     = PROJECT_ROOT / "data"
MODELS_DIR   = PROJECT_ROOT / "models"
UPLOADS_DIR  = PROJECT_ROOT / "uploads"
SAMPLES_DIR  = UPLOADS_DIR / "samples"
DB_PATH      = PROJECT_ROOT / "forensics.db"

# GeoIP databases (offline)
GEOIP_CITY_DB = DATA_DIR / "GeoLite2-City.mmdb"
GEOIP_ASN_DB  = DATA_DIR / "GeoLite2-ASN.mmdb"   # may not exist — checked at runtime

# Threat feed cache files
FEODO_CACHE    = DATA_DIR / "feodo_cache.json"
URLHAUS_CACHE  = DATA_DIR / "urlhaus_cache.txt"
TOR_CACHE      = DATA_DIR / "tor_exit_nodes.txt"

# Threat feed URLs (verified live 2026-09-06)
FEODO_URL   = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"
URLHAUS_URL = "https://urlhaus.abuse.ch/downloads/text/"
TOR_URL     = "https://check.torproject.org/torbulkexitlist"

# Threat feed cache TTL in seconds (24 hours)
FEED_CACHE_TTL_SECONDS = 86_400

# ---------------------------------------------------------------------------
# Risk Scoring — Weight Constants
# Adjust these to tune sensitivity. All weights sum to 100.
# ---------------------------------------------------------------------------
W_ML    = 35   # Stage 2: ML phishing probability (0–1 → contributes 0–35 pts)
W_SPF   = 8    # Stage 3: SPF fail penalty
W_DKIM  = 7    # Stage 3: DKIM fail penalty
W_DMARC = 10   # Stage 3: DMARC fail penalty
W_ANOM  = 8    # Stage 3: header anomaly count (up to 4 anomalies → full weight)
W_GEO   = 12   # Stage 4: TOR / botnet C2 / cloud-host infrastructure signals
W_DOM   = 10   # Stage 4: domain age ("new" < 90 days / "age_unknown" / "established")
W_CAMP  = 5    # Stage 5: email belongs to a known phishing campaign
W_ATTR  = 5    # Stage 5: attribution confidence score
# Total = 100

# ---------------------------------------------------------------------------
# Risk Score Outcome Thresholds
# ---------------------------------------------------------------------------
THRESHOLD_DELIVER  = 40   # 0–39   → deliver
THRESHOLD_REVIEW   = 70   # 40–69  → flag-for-manual-review
                           # 70–100 → quarantine

# ---------------------------------------------------------------------------
# Domain Intelligence
# ---------------------------------------------------------------------------
# Flag newly registered domains (under this many days) as suspicious
NEW_DOMAIN_AGE_DAYS = 90

# Homograph similarity threshold (rapidfuzz ratio, 0–100)
# > HOMOGRAPH_FLAG_THRESHOLD and < 100 → flag as lookalike
HOMOGRAPH_FLAG_THRESHOLD = 80

# Trusted domains used for homograph comparison
# This list is hardcoded and intentionally conservative — adding a domain here
# means close-but-not-exact matches against it will be flagged.
TRUSTED_DOMAINS = [
    "google.com", "gmail.com", "youtube.com",
    "paypal.com", "paypal.me",
    "amazon.com", "amazonaws.com",
    "microsoft.com", "outlook.com", "live.com", "office.com",
    "apple.com", "icloud.com",
    "facebook.com", "instagram.com", "meta.com",
    "netflix.com",
    "twitter.com", "x.com",
    "linkedin.com",
    "chase.com", "wellsfargo.com", "bankofamerica.com", "citibank.com",
    "irs.gov", "ssa.gov", "medicare.gov",
    "dropbox.com", "box.com",
    "docusign.com",
    "dhl.com", "fedex.com", "ups.com", "usps.com",
]

# ASN organization keywords that indicate cloud/hosting infrastructure
CLOUD_HOSTING_KEYWORDS = [
    "amazon", "aws", "digitalocean", "ovh", "hetzner", "google cloud",
    "microsoft azure", "azure", "linode", "vultr", "cloudflare",
    "fastly", "akamai", "rackspace", "leaseweb", "contabo",
    "serverius", "choopa", "choopa llc", "constant contact",
    "godaddy", "bluehost", "hostgator", "namecheap",
]

# ---------------------------------------------------------------------------
# Content Classifier
# ---------------------------------------------------------------------------
# TF-IDF settings
TFIDF_MAX_FEATURES = 10_000
TFIDF_NGRAM_RANGE  = (1, 2)

# Shortener domains — URLs matching these are flagged (not resolved)
URL_SHORTENERS = [
    "bit.ly", "tinyurl.com", "t.co", "ow.ly", "is.gd", "buff.ly",
    "adf.ly", "goo.gl", "tiny.cc", "rb.gy", "cutt.ly", "shorturl.at",
    "clck.ru", "qps.ru",
]

# Suspicious attachment extensions
SUSPICIOUS_EXTENSIONS = {
    ".exe", ".js", ".vbs", ".bat", ".ps1", ".hta", ".scr",
    ".jar", ".cmd", ".msi", ".dll", ".com", ".pif", ".reg",
    ".docm", ".xlsm", ".pptm",   # macro-enabled Office formats
}

# ---------------------------------------------------------------------------
# Campaign Clustering
# ---------------------------------------------------------------------------
# TF-IDF cosine similarity threshold for soft-linking emails into campaigns
# (chosen over difflib because it scales to a large corpus efficiently)
CAMPAIGN_SIMILARITY_THRESHOLD = 0.85

# ---------------------------------------------------------------------------
# Compliance / Retention
# ---------------------------------------------------------------------------
# After this many days, raw email bodies are purged; analysis records are kept
DEFAULT_RETENTION_DAYS = 90
