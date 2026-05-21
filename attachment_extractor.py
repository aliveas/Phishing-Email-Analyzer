import hashlib

DANGEROUS_EXTENSIONS = {
   
    ".exe", ".dll", ".com", ".bat", ".cmd", ".msi",
    
    ".js", ".vbs", ".vbe", ".wsf", ".ps1", ".psm1", ".psd1",
 
    ".docm", ".xlsm", ".pptm", ".dotm",
    
    ".iso", ".img",
   
    ".hta", ".scr", ".pif", ".reg", ".lnk",
}


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

    attachments = []
    msg = email_data.get("raw_message")

    if not msg:
        return []

    for part in msg.walk():
       
        disposition = str(part.get("Content-Disposition", ""))

        if "attachment" not in disposition:
            continue

       
        filename = part.get_filename()
        if not filename:
            filename = "unknown_attachment"

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

     
        mime_type = part.get_content_type()

       
        raw_bytes = part.get_payload(decode=True)
        if raw_bytes is None:
            raw_bytes = b""

        size_bytes = len(raw_bytes)
        size_kb    = round(size_bytes / 1024, 2)

      
        md5_hash    = hashlib.md5(raw_bytes).hexdigest()
        sha256_hash = hashlib.sha256(raw_bytes).hexdigest()

       
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
