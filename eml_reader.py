"""
parser/eml_reader.py
====================
Reads a raw .eml file and parses it into a structured Python dictionary
using Python's built-in `email` library (no pip install needed).

What we extract:
  - Subject, From, To, Date, Reply-To, Message-ID headers
  - Plain text body
  - HTML body
  - All MIME parts (for the attachment extractor to use)
  - Sender domain (used for WHOIS lookup)
  - All raw headers (used for header analysis)
"""

import email
import email.utils
from email import policy


def read_eml(file_path: str) -> dict | None:
    """
    Opens and parses a .eml file.

    Parameters
    ----------
    file_path : str  — path to the .eml file

    Returns
    -------
    dict with all extracted email data, or None if parsing failed
    """
    try:
        # Open the file in binary mode — email files can contain
        # non-UTF-8 characters (attachments are base64-encoded binary)
        with open(file_path, "rb") as f:
            raw_bytes = f.read()

        # email.message_from_bytes() parses the raw bytes into a
        # structured Message object. policy=policy.default gives us
        # modern Python email handling.
        msg = email.message_from_bytes(raw_bytes, policy=policy.compat32)

        # ── Extract basic headers ──────────────────────────────────
        # msg['Header-Name'] returns the raw value or None if missing
        subject  = _decode_header(msg.get("Subject", ""))
        from_    = msg.get("From", "")
        to_      = msg.get("To", "")
        date_    = msg.get("Date", "")
        reply_to = msg.get("Reply-To", "")
        msg_id   = msg.get("Message-ID", "")
        x_mailer = msg.get("X-Mailer", "")
        x_origin = msg.get("X-Originating-IP", "")

        # ── Extract all raw headers as a list of (name, value) pairs ─
        # We keep ALL headers so the header_analyzer can inspect them
        all_headers = [(k, v) for k, v in msg.items()]

        # ── Extract plain text and HTML body ──────────────────────────
        plain_text = ""
        html_body  = ""

        # msg.walk() iterates every MIME part of the email
        # (text/plain, text/html, image/png, application/pdf, etc.)
        for part in msg.walk():
            content_type = part.get_content_type()
            disposition  = str(part.get("Content-Disposition", ""))

            # Skip attachments at this stage
            if "attachment" in disposition:
                continue

            if content_type == "text/plain":
                try:
                    charset    = part.get_content_charset() or "utf-8"
                    plain_text = part.get_payload(decode=True).decode(charset, errors="replace")
                except Exception:
                    plain_text = str(part.get_payload())

            elif content_type == "text/html":
                try:
                    charset   = part.get_content_charset() or "utf-8"
                    html_body = part.get_payload(decode=True).decode(charset, errors="replace")
                except Exception:
                    html_body = str(part.get_payload())

        # ── Extract sender domain ──────────────────────────────────────
        # email.utils.parseaddr() safely extracts  name, address  from
        # "John Smith <john@example.com>"  →  ("John Smith", "john@example.com")
        sender_domain = ""
        _, sender_email = email.utils.parseaddr(from_)
        if "@" in sender_email:
            sender_domain = sender_email.split("@")[-1].lower().strip()

        # ── Build and return the structured dict ───────────────────────
        return {
            "subject"       : subject,
            "from"          : from_,
            "to"            : to_,
            "date"          : date_,
            "reply_to"      : reply_to,
            "message_id"    : msg_id,
            "x_mailer"      : x_mailer,
            "x_originating_ip": x_origin,
            "sender_email"  : sender_email,
            "sender_domain" : sender_domain,
            "plain_text"    : plain_text,
            "html_body"     : html_body,
            "all_headers"   : all_headers,
            "raw_message"   : msg,   # the full Message object for attachment extraction
        }

    except FileNotFoundError:
        print(f"[!] File not found: {file_path}")
        return None
    except Exception as e:
        print(f"[!] Error parsing email: {e}")
        return None


def _decode_header(raw: str) -> str:
    """
    Decodes encoded email subjects like:
    =?UTF-8?B?VXJnZW50...?=  →  "Urgent: Your account has been compromised"

    Many phishing emails encode their subject line to bypass spam filters.
    """
    if not raw:
        return ""
    try:
        parts = email.header.decode_header(raw)
        decoded = []
        for part, charset in parts:
            if isinstance(part, bytes):
                decoded.append(part.decode(charset or "utf-8", errors="replace"))
            else:
                decoded.append(str(part))
        return " ".join(decoded)
    except Exception:
        return str(raw)
