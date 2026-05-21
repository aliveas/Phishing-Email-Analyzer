"""
extractors/url_extractor.py
============================
Extracts all URLs from an email's HTML body and plain text body.

Two extraction methods:
  1. BeautifulSoup — parses HTML and finds every <a href="..."> tag
  2. Regex         — finds raw URLs in plain text (http://... https://...)

Also flags:
  - URL shorteners (bit.ly, tinyurl, etc.) used to hide real destinations
  - Suspicious keywords in URLs (login, secure, verify, account, etc.)
"""

import re
from urllib.parse import urlparse

from bs4 import BeautifulSoup


# ─────────────────────────────────────────────
# Known URL shortener domains
# ─────────────────────────────────────────────
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "ow.ly", "buff.ly",
    "goo.gl", "short.link", "rb.gy", "cutt.ly", "is.gd",
    "tiny.cc", "shorte.st", "adf.ly", "bc.vc", "clck.ru",
}

# ─────────────────────────────────────────────
# Keywords in URLs that suggest phishing
# ─────────────────────────────────────────────
SUSPICIOUS_KEYWORDS = [
    "login", "signin", "sign-in", "verify", "verification",
    "secure", "security", "update", "confirm", "account",
    "password", "credential", "billing", "payment", "invoice",
    "click-here", "urgent", "limited-time", "suspended",
]

# ─────────────────────────────────────────────
# Regex pattern to find raw URLs in plain text
# ─────────────────────────────────────────────
URL_REGEX = re.compile(
    r'https?://'                   # must start with http:// or https://
    r'[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]+'  # followed by URL characters
)


def extract_urls(email_data: dict) -> list[dict]:
    """
    Extracts all URLs from the email body (HTML + plain text).

    Parameters
    ----------
    email_data : dict — output from eml_reader.read_eml()

    Returns
    -------
    list of URL dicts, each with:
      {
        "url"         : str   — the full URL
        "source"      : str   — "html" or "text"
        "display_text": str   — the clickable link text (HTML only)
        "domain"      : str   — extracted domain
        "is_shortener": bool  — is it a URL shortener?
        "is_suspicious": bool — does it contain suspicious keywords?
      }
    """
    found_urls = {}   # use dict to deduplicate by URL

    html_body  = email_data.get("html_body",  "")
    plain_text = email_data.get("plain_text", "")

    # ── Method 1: Parse HTML with BeautifulSoup ───────────────────────
    if html_body:
        soup = BeautifulSoup(html_body, "html.parser")

        for anchor in soup.find_all("a", href=True):
            url = anchor["href"].strip()

            # Skip mailto: and javascript: links — not HTTP URLs
            if not url.startswith(("http://", "https://")):
                continue

            # The clickable text the user sees
            display_text = anchor.get_text(strip=True)[:100]

            if url not in found_urls:
                found_urls[url] = _build_url_entry(url, "html", display_text)

    # ── Method 2: Regex on plain text body ───────────────────────────
    if plain_text:
        for match in URL_REGEX.finditer(plain_text):
            url = match.group(0).rstrip(".,);\"'")  # strip trailing punctuation
            if url not in found_urls:
                found_urls[url] = _build_url_entry(url, "text", "")

    # Also run regex on HTML source to catch obfuscated URLs
    if html_body:
        for match in URL_REGEX.finditer(html_body):
            url = match.group(0).rstrip(".,);\"'\"")
            if url not in found_urls:
                found_urls[url] = _build_url_entry(url, "html-source", "")

    return list(found_urls.values())


def _build_url_entry(url: str, source: str, display_text: str) -> dict:
    """Builds a structured URL record with analysis flags."""
    parsed     = urlparse(url)
    domain     = parsed.netloc.lower().lstrip("www.")
    url_lower  = url.lower()

    is_shortener  = domain in URL_SHORTENERS
    is_suspicious = any(kw in url_lower for kw in SUSPICIOUS_KEYWORDS)

    return {
        "url"          : url,
        "source"       : source,
        "display_text" : display_text,
        "domain"       : domain,
        "is_shortener" : is_shortener,
        "is_suspicious": is_suspicious,
    }
