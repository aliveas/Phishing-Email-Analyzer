"""
extractors/attachment_extractor.py
====================================
Extracts metadata and file hashes from email attachments.

For each attachment we collect:
  - Filename and MIME type
  - Size in KB
  - MD5 and SHA256 hashes (for VirusTotal lookups)
  - Whether the file type is considered dangerous

We do NOT save the attachment to disk by default — we only
read its bytes in memory to compute the hash. This is safer.
"""

import hashlib


# ─────────────────────────────────────────────
# File extensions considered dangerous
# ─────────────────────────────────────────────
DANGEROUS_EXTENSIONS = {
    # Executables
    ".exe", ".dll", ".com", ".bat", ".cmd", ".msi",
    # Scripts
    ".js", ".vbs", ".vbe", ".wsf", ".ps1", ".psm1", ".psd1",
    # Office macros
    ".docm", ".xlsm", ".pptm", ".dotm",
    # Archives (can contain malware)
    ".iso", ".img",
    # Other
    ".hta", ".scr", ".pif", ".reg", ".lnk",
}

# MIME types that are dangerous even if extension looks safe
DANGEROUS_MIMES = {
    "application/x-msdownload",
    "application/x-executable",
    "application/x-dosexec",
    "application/x-sh",
    "application/x-bat",
    "application/x-msi",
    "text/x-shellscript",
}


def extract_attachments(email_data: dict) -> list[dict]:
    """
    Extracts all attachments from the parsed email message.

    Parameters
    ----------
    email_data : dict — output from eml_reader.read_eml()
                        must contain "raw_message" key

    Returns
    -------
    list of attachment dicts:
      {
        "filename"    : str   — original filename
        "mime_type"   : str   — e.g. "application/pdf"
        "size_bytes"  : int
        "size_kb"     : str   — rounded to 2 decimal places
        "md5"         : str   — MD5 hex digest
        "sha256"      : str   — SHA-256 hex digest (used for VT lookup)
        "is_dangerous": bool  — True if file type is high risk
        "extension"   : str   — file extension e.g. ".exe"
      }
    """
    attachments = []
    msg = email_data.get("raw_message")

    if not msg:
        return []

    # msg.walk() iterates every MIME part in the email
    for part in msg.walk():
        # Content-Disposition tells us if this part is an attachment
        # Typical value: 'attachment; filename="invoice.pdf"'
        disposition = str(part.get("Content-Disposition", ""))

        if "attachment" not in disposition:
            continue

        # ── Get filename ───────────────────────────────────────────────
        filename = part.get_filename()
        if not filename:
            filename = "unknown_attachment"

        # Decode encoded filenames like =?UTF-8?B?...?=
        import email.header
        decoded_parts = email.header.decode_header(filename)
        filename_parts = []
        for part_bytes, charset in decoded_parts:
            if isinstance(part_bytes, bytes):
                filename_parts.append(
                    part_bytes.decode(charset or "utf-8", errors="replace")
                )
            else:
                filename_parts.append(str(part_bytes))
        filename = "".join(filename_parts)

        # ── Get MIME type ──────────────────────────────────────────────
        mime_type = part.get_content_type()

        # ── Get raw bytes ──────────────────────────────────────────────
        # get_payload(decode=True) decodes base64/quoted-printable encoding
        raw_bytes = part.get_payload(decode=True)
        if raw_bytes is None:
            raw_bytes = b""

        size_bytes = len(raw_bytes)
        size_kb    = round(size_bytes / 1024, 2)

        # ── Compute file hashes ────────────────────────────────────────
        # hashlib lets us compute cryptographic hashes in a few lines
        md5_hash    = hashlib.md5(raw_bytes).hexdigest()
        sha256_hash = hashlib.sha256(raw_bytes).hexdigest()

        # ── Check if dangerous ─────────────────────────────────────────
        import os
        extension    = os.path.splitext(filename)[-1].lower()
        is_dangerous = (
            extension  in DANGEROUS_EXTENSIONS or
            mime_type  in DANGEROUS_MIMES
        )

        attachments.append({
            "filename"    : filename,
            "mime_type"   : mime_type,
            "size_bytes"  : size_bytes,
            "size_kb"     : size_kb,
            "md5"         : md5_hash,
            "sha256"      : sha256_hash,
            "is_dangerous": is_dangerous,
            "extension"   : extension,
        })

    return attachments
