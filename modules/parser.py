"""
modules/parser.py — Stage 1: Email Intake and Parsing

Accepts a path to an .eml file and returns one structured dict consumed by all
downstream stages. This module uses only Python's stdlib `email` package — no
third-party dependencies — so it is always safe to import even before the venv
is fully set up.

Output dict schema (all fields always present, nullable fields documented):
{
  "message_id":      str,          # Message-ID header value, or generated fallback
  "from_raw":        str,          # Raw From: header string
  "from_addr":       str,          # Parsed email address portion only
  "from_display":    str,          # Display name portion (may be empty)
  "from_domain":     str,          # Domain part of from_addr (lowercase)
  "to":              [str],        # List of To: addresses
  "reply_to":        str | None,   # Reply-To address, or None
  "reply_to_domain": str | None,   # Domain of Reply-To, or None
  "return_path":     str | None,   # Return-Path address, or None
  "return_path_domain": str | None,
  "date":            str,          # Raw Date header value
  "subject":         str,
  "body_plain":      str,          # Decoded plain-text body (may be empty)
  "body_html":       str,          # Decoded HTML body (may be empty)
  "received_chain":  [str],        # List of raw Received: header values (oldest last)
  "auth_results_raw": str | None,  # Raw Authentication-Results header, or None
  "x_synthetic":     bool,         # True if this is a reconstructed synthetic sample
  "dataset_label":   str | None,   # "0" or "1" if X-Dataset-Label header present
  "attachments": [
    {
      "filename":      str,
      "content_type":  str,
      "sha256":        str,        # hex digest
      "size_bytes":    int,
    }
  ],
  "urls": [str],                   # Unique URLs extracted from body text + HTML hrefs
  "raw_headers": dict[str, list[str]],  # All headers, lowercased key → list of values
}
"""

import email
import email.policy
import hashlib
import logging
import re
from email.headerregistry import Address
from email.utils import parseaddr, getaddresses
from pathlib import Path
from typing import Any

from bs4 import BeautifulSoup

log = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# URL extraction patterns
# ---------------------------------------------------------------------------
# Matches http / https / ftp URLs in plain text
_URL_PATTERN = re.compile(
    r"https?://[^\s<>\"')\]]+|ftp://[^\s<>\"')\]]+",
    re.IGNORECASE,
)


def _extract_domain(address: str) -> str:
    """Return the lowercase domain portion of an email address, or empty string."""
    if not address:
        return ""
    parts = address.strip().lower().split("@")
    if len(parts) == 2:
        return parts[1].strip(">").strip()
    return ""


def _parse_address(raw: str) -> tuple[str, str]:
    """Return (display_name, email_address) from a raw From/Reply-To/Return-Path string."""
    if not raw:
        return "", ""
    display, addr = parseaddr(raw)
    return (display or ""), (addr or "").lower().strip()


def _get_all_header_values(msg: email.message.EmailMessage, name: str) -> list[str]:
    """Return all values for a given header name (handles multiple occurrences)."""
    return [str(v) for v in msg.get_all(name, [])]


def _extract_urls_from_text(text: str) -> list[str]:
    """Extract all URLs from a plain-text string."""
    return _URL_PATTERN.findall(text)


def _extract_urls_from_html(html: str) -> list[str]:
    """Extract URLs from HTML href and src attributes."""
    urls: list[str] = []
    try:
        soup = BeautifulSoup(html, "lxml")
        for tag in soup.find_all(True):
            for attr in ("href", "src", "action"):
                val = tag.get(attr, "")
                if val and (val.startswith("http") or val.startswith("ftp")):
                    urls.append(val)
    except Exception as exc:
        log.warning("HTML URL extraction failed: %s", exc)
    return urls


def _decode_payload(part: email.message.Message) -> str:
    """Safely decode a message part payload to a UTF-8 string."""
    charset = part.get_content_charset() or "utf-8"
    raw = part.get_payload(decode=True)
    if raw is None:
        return ""
    # Try declared charset first, fall back to latin-1 which never raises
    for enc in (charset, "utf-8", "latin-1"):
        try:
            return raw.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return raw.decode("latin-1", errors="replace")


def parse_eml(filepath: Path) -> dict[str, Any]:
    """
    Parse an .eml file and return a structured analysis dict.

    Args:
        filepath: pathlib.Path to the .eml file.

    Returns:
        Structured dict as documented in the module docstring.

    Raises:
        FileNotFoundError: if the path does not exist.
        ValueError: if the file cannot be parsed as an email message.
    """
    filepath = Path(filepath)
    if not filepath.exists():
        raise FileNotFoundError(f"File not found: {filepath}")

    with open(filepath, "rb") as f:
        raw_bytes = f.read()

    try:
        msg = email.message_from_bytes(raw_bytes, policy=email.policy.compat32)
    except Exception as exc:
        raise ValueError(f"Failed to parse {filepath.name}: {exc}") from exc

    # ------------------------------------------------------------------
    # Headers
    # ------------------------------------------------------------------
    raw_headers: dict[str, list[str]] = {}
    for key in set(k.lower() for k in msg.keys()):
        raw_headers[key] = _get_all_header_values(msg, key)

    # From
    from_raw                 = str(msg.get("From", ""))
    from_display, from_addr  = _parse_address(from_raw)
    from_domain              = _extract_domain(from_addr)

    # To
    to_raw = _get_all_header_values(msg, "To")
    to_addrs = [addr for _, addr in getaddresses(to_raw) if addr]

    # Reply-To
    reply_to_raw            = str(msg.get("Reply-To", ""))
    _, reply_to_addr        = _parse_address(reply_to_raw)
    reply_to                = reply_to_addr or None
    reply_to_domain         = _extract_domain(reply_to_addr) or None

    # Return-Path
    return_path_raw         = str(msg.get("Return-Path", ""))
    _, return_path_addr     = _parse_address(return_path_raw)
    return_path             = return_path_addr or None
    return_path_domain      = _extract_domain(return_path_addr) or None

    # Message-ID
    message_id = str(msg.get("Message-ID", "")).strip() or f"<missing@{from_domain or 'unknown'}>"

    # Received chain (in order oldest→newest, reversed from header order)
    received_chain = list(reversed(_get_all_header_values(msg, "Received")))

    # Authentication-Results (may be absent in synthetic samples)
    auth_results_raw = msg.get("Authentication-Results") or None

    # Synthetic origin markers (added by csv_to_eml.py)
    x_synthetic   = bool(msg.get("X-Synthetic-Origin"))
    dataset_label = msg.get("X-Dataset-Label") or None

    # ------------------------------------------------------------------
    # Body extraction
    # ------------------------------------------------------------------
    body_plain = ""
    body_html  = ""
    attachments: list[dict[str, Any]] = []

    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            disposition  = str(part.get("Content-Disposition", "")).lower()

            if "attachment" in disposition or part.get_filename():
                # It's an attachment
                payload = part.get_payload(decode=True) or b""
                filename = part.get_filename() or "unnamed"
                sha256   = hashlib.sha256(payload).hexdigest()
                attachments.append({
                    "filename":     filename,
                    "content_type": content_type,
                    "sha256":       sha256,
                    "size_bytes":   len(payload),
                })
            elif content_type == "text/plain" and not body_plain:
                body_plain = _decode_payload(part)
            elif content_type == "text/html" and not body_html:
                body_html = _decode_payload(part)
    else:
        # Single-part message
        content_type = msg.get_content_type()
        if content_type == "text/plain":
            body_plain = _decode_payload(msg)
        elif content_type == "text/html":
            body_html = _decode_payload(msg)

    # ------------------------------------------------------------------
    # URL extraction
    # ------------------------------------------------------------------
    urls: set[str] = set()
    urls.update(_extract_urls_from_text(body_plain))
    urls.update(_extract_urls_from_html(body_html))
    # Also scan raw headers for URLs (e.g., in List-Unsubscribe)
    for header_values in raw_headers.values():
        for val in header_values:
            urls.update(_extract_urls_from_text(val))

    # ------------------------------------------------------------------
    # Assemble output
    # ------------------------------------------------------------------
    return {
        "message_id":          message_id,
        "from_raw":            from_raw,
        "from_addr":           from_addr,
        "from_display":        from_display,
        "from_domain":         from_domain,
        "to":                  to_addrs,
        "reply_to":            reply_to,
        "reply_to_domain":     reply_to_domain,
        "return_path":         return_path,
        "return_path_domain":  return_path_domain,
        "date":                str(msg.get("Date", "")),
        "subject":             str(msg.get("Subject", "")),
        "body_plain":          body_plain,
        "body_html":           body_html,
        "received_chain":      received_chain,
        "auth_results_raw":    auth_results_raw,
        "x_synthetic":         x_synthetic,
        "dataset_label":       dataset_label,
        "attachments":         attachments,
        "urls":                sorted(urls),
        "raw_headers":         raw_headers,
    }
