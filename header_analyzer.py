

import email.utils
import re

IMPERSONATED_BRANDS = [
    "paypal", "amazon", "microsoft", "apple", "google", "facebook",
    "netflix", "bank", "chase", "wells fargo", "citibank", "dhl",
    "fedex", "ups", "instagram", "whatsapp", "dropbox", "linkedin",
    "twitter", "zoom", "docusign", "irs", "government", "support",
]


def analyze_headers(email_data: dict) -> list:
    
    findings = []
    headers  = dict(email_data.get("all_headers", []))

    spf_raw = _get_header(headers, "Received-SPF") or \
              _search_auth_results(headers, "spf")

    if spf_raw:
        spf_raw_lower = spf_raw.lower()
        if "fail" in spf_raw_lower and "softfail" not in spf_raw_lower:
            findings.append({
                "category"    : "SPF",
                "severity"    : "HIGH",
                "indicator"   : "Received-SPF: fail",
                "description" : "SPF check FAILED — the sending server is NOT authorised to send mail for this domain. Classic spoofing indicator.",
                "remediation" : "This email is likely spoofed. The From domain's SPF record explicitly rejects this sending server.",
            })
        elif "softfail" in spf_raw_lower:
            findings.append({
                "category"    : "SPF",
                "severity"    : "MEDIUM",
                "indicator"   : "Received-SPF: softfail",
                "description" : "SPF check returned SOFTFAIL — the sending server is not fully authorised. Treat with caution.",
                "remediation" : "Verify the sender through an alternative channel. The domain has weak SPF protection.",
            })
        elif "pass" in spf_raw_lower:
            pass  
    else:
        findings.append({
            "category"    : "SPF",
            "severity"    : "LOW",
            "indicator"   : "Received-SPF: missing",
            "description" : "No SPF result found in headers — the receiving server did not record SPF validation.",
            "remediation" : "Cannot verify if the sending server is authorised. Treat as unverified.",
        })

    dkim_sig = _get_header(headers, "DKIM-Signature")
    dkim_auth = _search_auth_results(headers, "dkim")

    if not dkim_sig:
        findings.append({
            "category"    : "DKIM",
            "severity"    : "MEDIUM",
            "indicator"   : "DKIM-Signature: missing",
            "description" : "No DKIM signature found — the email has not been cryptographically signed by the sending domain.",
            "remediation" : "Legitimate organisations (banks, PayPal, Google, etc.) always sign their emails. Absence of DKIM is suspicious.",
        })
    elif dkim_auth and "fail" in dkim_auth.lower():
        findings.append({
            "category"    : "DKIM",
            "severity"    : "HIGH",
            "indicator"   : "DKIM: fail",
            "description" : "DKIM signature is INVALID — the email content was modified after signing, or the signature is forged.",
            "remediation" : "This email has been tampered with or the signature is fraudulent. High phishing confidence.",
        })

    dmarc_auth = _search_auth_results(headers, "dmarc")
    if dmarc_auth:
        if "fail" in dmarc_auth.lower():
            findings.append({
                "category"    : "DMARC",
                "severity"    : "HIGH",
                "indicator"   : "DMARC: fail",
                "description" : "DMARC check FAILED — email failed both SPF and DKIM alignment. Strong phishing indicator.",
                "remediation" : "This email has failed all authentication checks. Very likely a spoofed/phishing email.",
            })

    from_   = email_data.get("from", "")
    reply_to = email_data.get("reply_to", "")

    if reply_to:
        _, from_addr    = email.utils.parseaddr(from_)
        _, reply_addr   = email.utils.parseaddr(reply_to)
        from_domain     = from_addr.split("@")[-1].lower()  if "@" in from_addr  else ""
        reply_domain    = reply_addr.split("@")[-1].lower() if "@" in reply_addr else ""

        if from_domain and reply_domain and from_domain != reply_domain:
            findings.append({
                "category"    : "Reply-To Mismatch",
                "severity"    : "HIGH",
                "indicator"   : f"From: {from_domain}  ≠  Reply-To: {reply_domain}",
                "description" : (
                    f"Reply-To domain ({reply_domain}) differs from From domain ({from_domain}). "
                    "Replies will go to a DIFFERENT organisation than the apparent sender."
                ),
                "remediation" : "Do NOT reply to this email. The reply will go to an attacker-controlled address.",
            })

    if from_:
        display_name, from_addr = email.utils.parseaddr(from_)
        display_name_lower = display_name.lower()
        from_domain = from_addr.split("@")[-1].lower() if "@" in from_addr else ""

        for brand in IMPERSONATED_BRANDS:
            if brand in display_name_lower and brand not in from_domain:
                findings.append({
                    "category"    : "Display Name Spoofing",
                    "severity"    : "HIGH",
                    "indicator"   : f"'{display_name}' <{from_addr}>",
                    "description" : (
                        f"Display name claims to be '{brand}' but the actual email address "
                        f"is from '{from_domain}'. Classic impersonation technique."
                    ),
                    "remediation" : "Always check the actual email address, not just the display name.",
                })
                break  
 
    if not email_data.get("message_id"):
        findings.append({
            "category"    : "Headers",
            "severity"    : "LOW",
            "indicator"   : "Message-ID: missing",
            "description" : "No Message-ID header found. Legitimate mail servers always generate a unique Message-ID.",
            "remediation" : "Low confidence on its own, but combined with other indicators increases phishing confidence.",
        })

    x_mailer = email_data.get("x_mailer", "").lower()
    suspicious_mailers = ["mass mailer", "bulk", "phpmailer/", "sendblaster", "turbomailer"]
    for mailer in suspicious_mailers:
        if mailer in x_mailer:
            findings.append({
                "category"    : "X-Mailer",
                "severity"    : "MEDIUM",
                "indicator"   : f"X-Mailer: {email_data.get('x_mailer', '')}",
                "description" : f"Email was sent using a mass/bulk mailing tool: {email_data.get('x_mailer', '')}",
                "remediation" : "Mass mailing tools are commonly used for phishing campaigns.",
            })
            break

    return findings


def _get_header(headers: dict, name: str) -> str:
    """Case-insensitive header lookup."""
    for key, val in headers.items():
        if key.lower() == name.lower():
            return val
    return ""


def _search_auth_results(headers: dict, protocol: str) -> str:
    
    auth_results = _get_header(headers, "Authentication-Results")
    if not auth_results:
        return ""

    pattern = rf"{protocol}=\S+"
    match = re.search(pattern, auth_results, re.IGNORECASE)
    return match.group(0) if match else ""
