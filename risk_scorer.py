HEADER_RULE_SCORES = {
    "SPF — fail"                    : 30,
    "SPF — softfail"                : 20,
    "SPF — missing"                 : 10,
    "DKIM — verification failed"    : 30,
    "DKIM — missing signature"      : 20,
    "DMARC — fail"                  : 35,
    "Reply-To / From mismatch"      : 25,
    "Return-Path / From mismatch"   : 15,
    "Suspicious mailer"             : 15,
    "Anonymizing relay detected"    : 25,
    "Long routing chain"            : 10,
}


def calculate_risk(
    header_findings : list,
    urls            : list,
    attachments     : list,
    vt_url_results  : list,
    vt_hash_results : list,
    whois_result    : dict,
) -> dict:
    
    score      = 0
    indicators = []

    def add(name: str, pts: int, detail: str = ""):
        nonlocal score
        score += pts
        indicators.append({"name": name, "points": pts, "detail": detail})

   
    for finding in header_findings:
        indicator_name = finding.get("indicator", "")
        
        for rule_key, pts in HEADER_RULE_SCORES.items():
            if rule_key.lower() in indicator_name.lower():
                add(indicator_name, pts, finding.get("detail", ""))
                break

  
    shorteners   = [u for u in urls if u.get("is_shortener")]
    ip_urls      = [u for u in urls if u.get("is_ip_url")]
    sus_tld_urls = [u for u in urls if u.get("suspicious_tld")]
    form_actions = [u for u in urls if u.get("is_form_action")]

    if shorteners:
        add(f"URL shortener(s) found ({len(shorteners)})",
            15 * min(len(shorteners), 2),
            f"Shorteners: {', '.join(u['url'] for u in shorteners[:3])}")

    if ip_urls:
        add(f"IP-based URL(s) found ({len(ip_urls)})",
            20,
            f"IPs: {', '.join(u['url'][:40] for u in ip_urls[:2])}")

    if sus_tld_urls:
        add(f"Suspicious TLD(s) ({len(sus_tld_urls)})",
            10,
            f"Domains: {', '.join(u['domain'] for u in sus_tld_urls[:3])}")

    if form_actions:
        add(f"HTML form submitting externally ({len(form_actions)})",
            20,
            f"Form targets: {', '.join(u['url'][:40] for u in form_actions[:2])}")

   
    dangerous_atts = [a for a in attachments if a.get("is_dangerous")]
    medium_atts    = [a for a in attachments if a.get("is_medium") and not a.get("is_dangerous")]

    for att in dangerous_atts:
        add(f"Dangerous attachment: {att['filename']}",
            35,
            att.get("risk_reason", "High-risk file type"))

    for att in medium_atts:
        add(f"Medium-risk attachment: {att['filename']}",
            10,
            att.get("risk_reason", "Potentially risky file type"))

   
    vt_malicious  = [r for r in vt_url_results if r.get("verdict") == "malicious"]
    vt_suspicious = [r for r in vt_url_results if r.get("verdict") == "suspicious"]

    for r in vt_malicious:
        add(f"VT: URL flagged malicious ({r['malicious']}/{r['total']} engines)",
            40,
            r["query"][:80])

    for r in vt_suspicious:
        add(f"VT: URL flagged suspicious ({r['suspicious']}/{r['total']} engines)",
            20,
            r["query"][:80])

  
    hash_malicious = [r for r in vt_hash_results if r.get("verdict") == "malicious"]
    for r in hash_malicious:
        add(f"VT: Attachment hash is known malware ({r['malicious']}/{r['total']})",
            45,
            r["query"][:64])


    age = whois_result.get("domain_age_days")
    if age is not None:
        if age < 7:
            add("Sender domain registered < 7 days ago", 40,
                f"Domain: {whois_result.get('domain')} — created {age} days ago")
        elif age < 30:
            add("Sender domain registered < 30 days ago", 30,
                f"Domain: {whois_result.get('domain')} — created {age} days ago")
        elif age < 180:
            add("Sender domain registered < 6 months ago", 15,
                f"Domain: {whois_result.get('domain')} — created {age} days ago")

  
    score = min(score, 100)

   
    if score >= 70:
        level = "Phishing"
        color = "#E24B4A"
    elif score >= 31:
        level = "Suspicious"
        color = "#BA7517"
    else:
        level = "Clean"
        color = "#3B6D11"

    return {
        "score"      : score,
        "level"      : level,
        "color"      : color,
        "indicators" : indicators,
    }
