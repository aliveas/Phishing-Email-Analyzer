"""
analyzer.py  —  Phishing Email Analyzer
========================================
Main entry point. Orchestrates the full pipeline:
  .eml file → parse → extract → intel APIs → risk score → HTML report

Usage:
  python analyzer.py samples/email.eml
  python analyzer.py samples/email.eml --output report.html --verbose
  python analyzer.py samples/email.eml --no-vt   (skip VirusTotal)
"""

import argparse
import datetime
import os
import re
import sys
import time

from colorama import Fore, Style, init
from dotenv import load_dotenv

from eml_reader import read_eml
from header_analyzer import analyze_headers
from url_extractor import extract_urls
from attachment_extractor import extract_attachments
from virustotal import scan_urls_vt, scan_hashes_vt
from whois_lookup import lookup_domain
from risk_scorer import calculate_risk
from generator import generate_report

load_dotenv()        # reads VT_API_KEY from your .env file
init(autoreset=True) # colourama — makes colours work on Windows too
if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")


# ─────────────────────────────────────────────
# Banner + helpers
# ─────────────────────────────────────────────

def print_banner():
    print(f"""
{Fore.CYAN}+------------------------------------------------------+
|           Phishing Email Analyzer  v1.0              |
|         SOC Analysis Tool  -  2026 Edition           |
+------------------------------------------------------+{Style.RESET_ALL}
""")


def parse_args():
    p = argparse.ArgumentParser(
        description="Analyze a .eml email file for phishing indicators"
    )
    p.add_argument("eml_file", help="Path to the .eml file  e.g. samples/phish.eml")
    p.add_argument("--output",  default="report.html",
                   help="Output HTML report name (saved to output/ folder)")
    p.add_argument("--verbose", action="store_true",
                   help="Print every URL and request detail")
    p.add_argument("--no-vt",   action="store_true",
                   help="Skip VirusTotal API (use if you have no API key yet)")
    p.add_argument("--no-whois", action="store_true",
                   help="Skip WHOIS lookup for sender domain")
    return p.parse_args()


def section(title: str):
    print(f"\n{Fore.CYAN}{'-'*54}\n[*] {title}\n{'-'*54}{Style.RESET_ALL}")


def finding(level: str, msg: str):
    colours = {"HIGH": Fore.RED, "MEDIUM": Fore.YELLOW,
               "LOW": Fore.BLUE, "OK": Fore.GREEN, "INFO": Fore.CYAN}
    c = colours.get(level, Fore.WHITE)
    print(f"  {c}[{level}]{Style.RESET_ALL}  {msg}")


# ─────────────────────────────────────────────
# Main pipeline
# ─────────────────────────────────────────────

def main():
    print_banner()
    args = parse_args()

    if not os.path.exists(args.eml_file):
        print(f"{Fore.RED}[!] File not found: {args.eml_file}")
        sys.exit(1)

    start     = time.time()
    scan_time = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"{Fore.CYAN}[*] File    : {args.eml_file}")
    print(f"[*] Started : {scan_time}")

    # ── 1. Parse .eml ────────────────────────────────────────────────
    section("Step 1/6  Parsing .eml file")
    email_data = read_eml(args.eml_file)
    if not email_data:
        print(f"{Fore.RED}[!] Could not parse the email file.")
        sys.exit(1)

    finding("INFO", f"Subject   : {email_data.get('subject','N/A')}")
    finding("INFO", f"From      : {email_data.get('from','N/A')}")
    finding("INFO", f"To        : {email_data.get('to','N/A')}")
    finding("INFO", f"Date      : {email_data.get('date','N/A')}")
    finding("INFO", f"Reply-To  : {email_data.get('reply_to','None')}")

    # ── 2. Header analysis ───────────────────────────────────────────
    section("Step 2/6  Analyzing email headers")
    header_findings = analyze_headers(email_data)
    for f_ in header_findings:
        # Template expects detail/raw_value fields.
        f_.setdefault("detail", f_.get("description", ""))
        f_.setdefault("raw_value", "")
    for f_ in header_findings:
        finding(f_["severity"], f_["description"])
    if not header_findings:
        finding("OK", "No suspicious header indicators found")

    # ── 3. URL extraction ────────────────────────────────────────────
    section("Step 3/6  Extracting URLs from email body")
    urls = extract_urls(email_data)
    for u in urls:
        domain = (u.get("domain") or "").lower()
        # Add compatibility fields used by scoring/template.
        u.setdefault("is_ip_url", bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", domain)))
        u.setdefault("suspicious_tld", domain.endswith((".ru", ".tk", ".xyz", ".top", ".click", ".gq", ".cn")))
        u.setdefault("is_form_action", False)
    finding("INFO", f"Found {len(urls)} URL(s)")
    if args.verbose:
        for u in urls:
            print(f"         {Fore.CYAN}→ {u}")

    # ── 4. Attachments ───────────────────────────────────────────────
    section("Step 4/6  Scanning attachments")
    attachments = extract_attachments(email_data)
    medium_exts = {".pdf", ".zip", ".rar", ".7z", ".doc", ".docx", ".xls", ".xlsx"}
    for att in attachments:
        ext = (att.get("extension") or "").lower()
        att.setdefault("is_medium", ext in medium_exts and not att.get("is_dangerous", False))
        if att.get("is_dangerous"):
            att.setdefault("risk_reason", f"Dangerous extension {ext or 'unknown'}")
        elif att.get("is_medium"):
            att.setdefault("risk_reason", f"Potentially risky extension {ext}")
    if attachments:
        finding("INFO", f"Found {len(attachments)} attachment(s)")
        for att in attachments:
            finding("INFO", f"{att['filename']}  |  {att['mime_type']}  |  {att['size_kb']} KB")
            if att.get("is_dangerous"):
                finding("HIGH", f"Dangerous file type: {att['filename']}")
    else:
        finding("OK", "No attachments found")

    # ── 5. VirusTotal ────────────────────────────────────────────────
    section("Step 5/6  VirusTotal threat intelligence")
    vt_url_results  = []
    vt_hash_results = []

    if args.no_vt:
        finding("INFO", "VirusTotal skipped (--no-vt flag used)")
    else:
        vt_key = os.getenv("VT_API_KEY", "")
        if not vt_key:
            finding("INFO", "VT_API_KEY not set — skipping VirusTotal")
            print(f"  {Fore.YELLOW}    Tip: Add VT_API_KEY=your_key to your .env file")
        else:
            if urls:
                finding("INFO", f"Scanning {len(urls)} URL(s) on VirusTotal...")
                vt_url_results = scan_urls_vt(urls, vt_key, args.verbose)
                for r in vt_url_results:
                    total = (r.get("malicious", 0) + r.get("suspicious", 0) +
                             r.get("harmless", 0) + r.get("undetected", 0))
                    r["query"] = r.get("url", "")
                    r["total"] = total
                    if r.get("malicious", 0) > 0:
                        r["verdict"] = "malicious"
                    elif r.get("suspicious", 0) > 0:
                        r["verdict"] = "suspicious"
                    else:
                        r["verdict"] = "clean"
                    if r.get("malicious", 0) > 0:
                        finding("HIGH", f"Malicious URL ({r['malicious']} engines): {r['url'][:55]}")
                    elif args.verbose:
                        finding("OK", f"Clean: {r['url'][:55]}")

            if attachments:
                hashes = [a["sha256"] for a in attachments if a.get("sha256")]
                if hashes:
                    finding("INFO", f"Scanning {len(hashes)} hash(es) on VirusTotal...")
                    vt_hash_results = scan_hashes_vt(hashes, vt_key, args.verbose)
                    for r in vt_hash_results:
                        total = (r.get("malicious", 0) + r.get("suspicious", 0) + r.get("harmless", 0))
                        r["query"] = r.get("hash", "")
                        r["total"] = total
                        if r.get("malicious", 0) > 0:
                            r["verdict"] = "malicious"
                        elif r.get("suspicious", 0) > 0:
                            r["verdict"] = "suspicious"
                        else:
                            r["verdict"] = "clean"
                        if r.get("malicious", 0) > 0:
                            finding("HIGH", f"Malicious hash ({r['malicious']} engines): {r['hash'][:20]}...")

    # ── 6. WHOIS ─────────────────────────────────────────────────────
    section("Step 6/6  WHOIS domain reputation")
    whois_data    = {}
    sender_domain = email_data.get("sender_domain", "")

    if args.no_whois:
        finding("INFO", "WHOIS skipped (--no-whois flag used)")
    elif sender_domain:
        finding("INFO", f"Looking up: {sender_domain}")
        whois_data = lookup_domain(sender_domain)
        if "age_days" in whois_data and "domain_age_days" not in whois_data:
            whois_data["domain_age_days"] = whois_data.get("age_days")
        if "expiry_date" in whois_data and "expiration_date" not in whois_data:
            whois_data["expiration_date"] = whois_data.get("expiry_date")
        age = whois_data.get("domain_age_days")

        if age is not None:
            if age < 30:
                finding("HIGH", f"Domain age: {age} day(s)  <  30 days - HIGH RISK")
            elif age < 180:
                finding("MEDIUM", f"Domain age: {age} days  (< 180 days - medium risk)")
            else:
                finding("OK", f"Domain age: {age} days — established domain")

        if whois_data.get("registrar"):
            finding("INFO", f"Registrar : {whois_data['registrar']}")
        if whois_data.get("country"):
            finding("INFO", f"Country   : {whois_data['country']}")
    else:
        finding("INFO", "Could not extract sender domain")

    # ── Risk score + report ──────────────────────────────────────────
    risk    = calculate_risk(
        header_findings=header_findings,
        urls=urls,
        attachments=attachments,
        vt_url_results=vt_url_results,
        vt_hash_results=vt_hash_results,
        whois_result=whois_data,
    )
    elapsed = round(time.time() - start, 1)

    print(f"\n{Fore.CYAN}{'='*54}")
    print(f"  ANALYSIS COMPLETE  in {elapsed}s")
    print(f"{'='*54}{Style.RESET_ALL}")
    print(f"  Risk Score : {risk['score']}/100")
    risk_c = Fore.RED if risk["level"] == "Phishing" else (
             Fore.YELLOW if risk["level"] == "Suspicious" else Fore.GREEN)
    print(f"  Risk Level : {risk_c}{risk['level']}{Style.RESET_ALL}")
    print(f"  Indicators : {len(risk.get('indicators', []))}")

    os.makedirs("output", exist_ok=True)
    out_path = os.path.join("output", args.output)

    generate_report(
        eml_file        = args.eml_file,
        email_data      = email_data,
        header_findings = header_findings,
        urls            = urls,
        attachments     = attachments,
        vt_url_results  = vt_url_results,
        vt_hash_results = vt_hash_results,
        whois_result    = whois_data,
        risk            = risk,
        scan_time       = scan_time,
        elapsed         = elapsed,
        output_path     = out_path,
    )
    print(f"\n{Fore.GREEN}[*] Report saved -> {out_path}")
    print(f"    Open in your browser to view the full analysis.\n")


if __name__ == "__main__":
    main()
