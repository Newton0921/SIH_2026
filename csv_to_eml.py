"""
csv_to_eml.py — Step 0: Data Preparation

PURPOSE:
  1. Print confirmed schemas for both CSVs (run this first to validate before building parsers).
  2. Copy GeoLite2-City.mmdb from the source folder into /data/ (one-time setup).
  3. Convert valid rows from Nazario_5.csv into RFC 5322 .eml files in /uploads/samples/.

IMPORTANT NOTES ON SYNTHETIC .EML FILES:
  - These files are reconstructed from CSV data. They do NOT have a real multi-hop
    "Received:" header chain — that data does not exist in the CSV.
  - The X-Synthetic-Origin header is added to every generated file to clearly mark it
    as a reconstructed sample, not a real captured email.
  - Stage 3 (header_forensics) and Stage 4 (origin_intel) are designed to degrade
    gracefully ("no routing data available") when the Received chain is absent.
  - Real .eml files with authentic headers should be supplied separately to demo
    the origin traceability module.
"""

import shutil
import ast
import hashlib
import logging
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formatdate, make_msgid
from pathlib import Path

import pandas as pd

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Paths — always use pathlib.Path, never plain backslash strings
# ---------------------------------------------------------------------------
# Source data folder (absolute OneDrive path — used ONLY in this setup script)
SOURCE_DIR   = Path(r"C:\Users\JHANI\OneDrive\Documents\SIH\New folder")

PROJECT_ROOT = Path(__file__).parent
DATA_DIR     = PROJECT_ROOT / "data"
SAMPLES_DIR  = PROJECT_ROOT / "uploads" / "samples"

NAZARIO_CSV  = SOURCE_DIR / "Nazario_5.csv"
EMAIL_TEXT_CSV = SOURCE_DIR / "email_text.csv"

GEOIP_CITY_SRC = SOURCE_DIR / "GeoLite2-City.mmdb"
GEOIP_ASN_SRC  = SOURCE_DIR / "GeoLite2-ASN.mmdb"   # may not exist

TARGET_EML_COUNT = 30   # generate at least this many .eml files


# ---------------------------------------------------------------------------
# Step 0a — Print CSV Schemas
# ---------------------------------------------------------------------------
def print_schemas() -> None:
    """Print column names, dtypes, head(3), and null counts for both datasets."""
    print("\n" + "=" * 70)
    print("SCHEMA REPORT — Nazario_5.csv")
    print("=" * 70)
    df_n = pd.read_csv(NAZARIO_CSV)
    print(f"Rows: {len(df_n):,}    Columns: {len(df_n.columns)}")
    print(f"Columns: {list(df_n.columns)}")
    print("\nDtypes:")
    print(df_n.dtypes.to_string())
    print("\nLabel distribution:")
    print(df_n["label"].value_counts().to_string())
    print("\nNull counts:")
    print(df_n.isnull().sum().to_string())
    print("\nhead(3):")
    for _, row in df_n.head(3).iterrows():
        for col in df_n.columns:
            val = str(row[col])
            print(f"  [{col}]: {val[:120]}")
        print()

    print("\n" + "=" * 70)
    print("SCHEMA REPORT — email_text.csv")
    print("=" * 70)
    # NOTE: The spec described 9 columns, but the actual file has 2 columns:
    #   label (int, 0=legitimate / 1=phishing/spam), text (str, body only).
    # There is no sender, subject, or URL metadata — it is structurally different
    # from Nazario_5.csv and cannot be directly merged or substituted.
    # Decision: use its 'text' column to augment TF-IDF training corpus.
    df_e = pd.read_csv(EMAIL_TEXT_CSV, nrows=5)
    df_e_sample = pd.read_csv(EMAIL_TEXT_CSV, nrows=2000)
    print(f"Rows (approx, line count): ~53,667    Columns: {len(df_e.columns)}")
    print(f"Columns: {list(df_e.columns)}")
    print("\nDtypes:")
    print(df_e.dtypes.to_string())
    print("\nLabel distribution (first 2000 rows):")
    print(df_e_sample["label"].value_counts().to_string())
    print("\nNull counts (first 2000 rows):")
    print(df_e_sample.isnull().sum().to_string())
    print("\nSample text (first row, first 200 chars):")
    print(repr(str(df_e["text"].iloc[0])[:200]))
    print()


# ---------------------------------------------------------------------------
# Step 0b — Copy GeoIP databases into /data/
# ---------------------------------------------------------------------------
def copy_geoip_databases() -> None:
    """Copy GeoLite2 .mmdb files from the source folder to /data/.
    Uses the absolute OneDrive path only in this setup script.
    All runtime code references DATA_DIR (relative), never the OneDrive path.
    """
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    # City database (required)
    dest_city = DATA_DIR / "GeoLite2-City.mmdb"
    if not dest_city.exists():
        if GEOIP_CITY_SRC.exists():
            shutil.copy2(GEOIP_CITY_SRC, dest_city)
            log.info("Copied GeoLite2-City.mmdb → data/")
        else:
            log.error("GeoLite2-City.mmdb not found at source path — geolocation will be unavailable")
    else:
        log.info("GeoLite2-City.mmdb already present in data/ — skipping copy")

    # ASN database (optional — may not exist)
    dest_asn = DATA_DIR / "GeoLite2-ASN.mmdb"
    if not dest_asn.exists():
        if GEOIP_ASN_SRC.exists():
            shutil.copy2(GEOIP_ASN_SRC, dest_asn)
            log.info("Copied GeoLite2-ASN.mmdb → data/")
        else:
            # This is expected — the spec notes it may not be present.
            # ASN enrichment will be skipped gracefully at runtime.
            log.warning(
                "GeoLite2-ASN.mmdb not found — ASN/network-owner enrichment will be "
                "disabled. This is expected if you haven't downloaded it yet."
            )
    else:
        log.info("GeoLite2-ASN.mmdb already present in data/ — skipping copy")


# ---------------------------------------------------------------------------
# Step 0c — Convert Nazario_5.csv rows to .eml files
# ---------------------------------------------------------------------------
def _safe_str(val, default: str = "") -> str:
    """Return stripped string or default if val is NaN/None."""
    if pd.isna(val):
        return default
    return str(val).strip()


def _extract_urls(url_cell: str) -> list[str]:
    """Parse the 'urls' column — stored as a stringified Python list."""
    if not url_cell or url_cell.strip() in ("", "[]", "nan"):
        return []
    try:
        result = ast.literal_eval(url_cell)
        if isinstance(result, list):
            return [str(u) for u in result if u]
    except (ValueError, SyntaxError):
        pass
    return []


def row_to_eml(row: pd.Series, index: int) -> MIMEMultipart | None:
    """
    Convert one Nazario_5.csv row to an RFC 5322 email message object.
    Returns None if the row lacks required fields (sender or body).

    LIMITATION: These files have no real Received: chain — that data was not
    captured in the CSV. The X-Synthetic-Origin header marks them accordingly.
    """
    sender = _safe_str(row.get("sender"))
    body   = _safe_str(row.get("body"))

    # Skip rows missing required fields per spec
    if not sender or not body:
        return None

    receiver = _safe_str(row.get("receiver"), default="unknown@example.com")
    date_str = _safe_str(row.get("date"),     default=formatdate(localtime=True))
    subject  = _safe_str(row.get("subject"),  default="(no subject)")
    label    = str(row.get("label", "0"))

    # Build RFC 5322 message
    msg = MIMEMultipart("mixed")
    msg["From"]    = sender
    msg["To"]      = receiver
    msg["Date"]    = date_str
    msg["Subject"] = subject

    # Stable Message-ID derived from row content (reproducible across runs)
    content_hash = hashlib.sha256(f"{sender}{body}".encode()).hexdigest()[:16]
    msg["Message-ID"] = f"<{content_hash}.nazario.{index}@synthetic.local>"

    # Custom headers to mark this as a reconstructed synthetic sample
    msg["X-Synthetic-Origin"] = "Reconstructed from Nazario_5.csv — no real Received chain"
    msg["X-Dataset-Label"]    = label  # "0" = legitimate, "1" = phishing

    # Plain text body
    msg.attach(MIMEText(body, "plain", "utf-8"))

    # Append URL list as a footer in the body (informational only)
    urls = _extract_urls(str(row.get("urls", "")))
    if urls:
        url_footer = "\n\n-- URLs extracted from dataset --\n" + "\n".join(urls)
        msg.attach(MIMEText(url_footer, "plain", "utf-8"))

    return msg


def generate_eml_samples(target_count: int = TARGET_EML_COUNT) -> int:
    """
    Convert Nazario_5.csv rows to .eml files in SAMPLES_DIR.
    Generates at least `target_count` valid files.
    Returns the number of files successfully written.
    """
    SAMPLES_DIR.mkdir(parents=True, exist_ok=True)

    df = pd.read_csv(NAZARIO_CSV)
    log.info(f"Loaded Nazario_5.csv: {len(df):,} rows")

    # Stratify: aim for a roughly balanced phishing / legit split in the samples
    phishing   = df[df["label"] == 1].copy()
    legitimate = df[df["label"] == 0].copy()

    half = target_count // 2
    sample_rows = pd.concat([
        phishing.head(half + 5),     # slight extra in case some rows are skipped
        legitimate.head(half + 5),
    ]).reset_index(drop=True)

    written = 0
    skipped = 0

    for idx, row in sample_rows.iterrows():
        msg = row_to_eml(row, idx)
        if msg is None:
            skipped += 1
            continue

        label_str = "phishing" if str(row.get("label")) == "1" else "legit"
        filename  = SAMPLES_DIR / f"sample_{idx:04d}_{label_str}.eml"

        with open(filename, "w", encoding="utf-8") as f:
            f.write(msg.as_string())

        written += 1
        if written >= target_count:
            break

    log.info(f"Generated {written} .eml files in {SAMPLES_DIR} ({skipped} rows skipped — null sender/body)")
    return written


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    print_schemas()
    copy_geoip_databases()
    count = generate_eml_samples()
    print(f"\n[OK] Step 0 complete: {count} sample .eml files written to uploads/samples/")
    print("Next: run Stage 1 parser against 3-5 of these files to validate output.")
