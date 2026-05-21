
import email
import email.utils
from email import policy


def read_eml(file_path: str) -> dict | None:
   
    try:

        with open(file_path, "rb") as f:
            raw_bytes = f.read()

        
        msg = email.message_from_bytes(raw_bytes, policy=policy.compat32)

        
        subject  = _decode_header(msg.get("Subject", ""))
        from_    = msg.get("From", "")
        to_      = msg.get("To", "")
        date_    = msg.get("Date", "")
        reply_to = msg.get("Reply-To", "")
        msg_id   = msg.get("Message-ID", "")
        x_mailer = msg.get("X-Mailer", "")
        x_origin = msg.get("X-Originating-IP", "")

        
        all_headers = [(k, v) for k, v in msg.items()]

      
        plain_text = ""
        html_body  = ""

        
        for part in msg.walk():
            content_type = part.get_content_type()
            disposition  = str(part.get("Content-Disposition", ""))

       
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

       
        sender_domain = ""
        _, sender_email = email.utils.parseaddr(from_)
        if "@" in sender_email:
            sender_domain = sender_email.split("@")[-1].lower().strip()

      
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
            "raw_message"   : msg,   
        }

    except FileNotFoundError:
        print(f"[!] File not found: {file_path}")
        return None
    except Exception as e:
        print(f"[!] Error parsing email: {e}")
        return None


def _decode_header(raw: str) -> str:
    
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
