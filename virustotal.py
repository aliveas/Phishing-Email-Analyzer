"""
intel/virustotal.py
====================
Integrates with the VirusTotal API v3 to scan URLs and file hashes.

Free tier limits:
  - 500 requests per day
  - 4 requests per minute  →  we add time.sleep(16) between calls

How URL scanning works:
  1. POST the URL to /api/v3/urls  →  get back a scan ID
  2. GET /api/v3/analyses/{scan_id}  →  get results from 70+ engines

How hash scanning works:
  1. GET /api/v3/files/{sha256}  →  instant results (no waiting!)
     If the hash is unknown, VT returns 404 — which means it's not
     in their database (could be new malware or clean file)
"""

import base64
import time
import requests


VT_BASE = "https://www.virustotal.com/api/v3"

# How many seconds to wait between API calls to respect the rate limit
# Free tier = 4 requests/minute  →  1 request every 15 seconds
RATE_LIMIT_SLEEP = 16


# ─────────────────────────────────────────────
# URL scanning
# ─────────────────────────────────────────────

def scan_urls_vt(urls: list, api_key: str, verbose: bool = False) -> list[dict]:
    """
    Submits each URL to VirusTotal and returns scan results.

    Parameters
    ----------
    urls    : list of URL dicts (from url_extractor)
    api_key : str  — your VirusTotal API key
    verbose : bool — print request details

    Returns
    -------
    list of result dicts:
      {
        "url"       : str  — the URL that was scanned
        "malicious" : int  — number of engines that flagged it
        "suspicious": int  — number of engines that marked suspicious
        "harmless"  : int
        "undetected": int
        "scan_id"   : str
        "error"     : str  — set if something went wrong
      }
    """
    headers = {
        "x-apikey"    : api_key,
        "Content-Type": "application/x-www-form-urlencoded",
    }
    results = []

    for url_entry in urls:
        url = url_entry["url"] if isinstance(url_entry, dict) else url_entry

        if verbose:
            print(f"         [VT] Scanning URL: {url[:60]}")

        try:
            # ── Step 1: Submit URL for scanning ───────────────────────
            resp = requests.post(
                f"{VT_BASE}/urls",
                headers=headers,
                data=f"url={requests.utils.quote(url, safe='')}",
                timeout=20,
            )

            if resp.status_code == 429:
                print("         [VT] Rate limit hit — waiting 60s...")
                time.sleep(60)
                resp = requests.post(
                    f"{VT_BASE}/urls",
                    headers=headers,
                    data=f"url={requests.utils.quote(url, safe='')}",
                    timeout=20,
                )

            if resp.status_code != 200:
                results.append({"url": url, "error": f"HTTP {resp.status_code}"})
                continue

            scan_id = resp.json()["data"]["id"]

            # ── Step 2: Wait briefly then fetch analysis results ──────
            time.sleep(5)  # Give VT time to finish scanning

            analysis_resp = requests.get(
                f"{VT_BASE}/analyses/{scan_id}",
                headers={"x-apikey": api_key},
                timeout=20,
            )

            if analysis_resp.status_code == 200:
                stats = (
                    analysis_resp.json()
                    .get("data", {})
                    .get("attributes", {})
                    .get("stats", {})
                )
                results.append({
                    "url"       : url,
                    "malicious" : stats.get("malicious",  0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless"  : stats.get("harmless",   0),
                    "undetected": stats.get("undetected", 0),
                    "scan_id"   : scan_id,
                })
            else:
                results.append({
                    "url"    : url,
                    "error"  : f"Analysis fetch failed: HTTP {analysis_resp.status_code}",
                })

        except requests.exceptions.RequestException as e:
            results.append({"url": url, "error": str(e)})

        # Respect the rate limit between requests
        time.sleep(RATE_LIMIT_SLEEP)

    return results


# ─────────────────────────────────────────────
# File hash scanning
# ─────────────────────────────────────────────

def scan_hashes_vt(hashes: list[str], api_key: str,
                   verbose: bool = False) -> list[dict]:
    """
    Looks up file hashes on VirusTotal.
    This is faster than URL scanning — no waiting for analysis.

    Parameters
    ----------
    hashes  : list of SHA256 hash strings
    api_key : str  — your VirusTotal API key
    verbose : bool

    Returns
    -------
    list of result dicts:
      {
        "hash"      : str  — the hash that was looked up
        "malicious" : int  — engines that flagged it
        "known"     : bool — False means hash not in VT database
        "error"     : str  — set if something went wrong
      }
    """
    headers = {"x-apikey": api_key}
    results = []

    for sha256 in hashes:
        if verbose:
            print(f"         [VT] Looking up hash: {sha256[:20]}...")

        try:
            resp = requests.get(
                f"{VT_BASE}/files/{sha256}",
                headers=headers,
                timeout=20,
            )

            if resp.status_code == 404:
                # Hash not in VT database — could be new or clean
                results.append({
                    "hash"      : sha256,
                    "malicious" : 0,
                    "known"     : False,
                    "note"      : "Hash not found in VirusTotal database",
                })

            elif resp.status_code == 200:
                attrs = resp.json().get("data", {}).get("attributes", {})
                stats = attrs.get("last_analysis_stats", {})
                results.append({
                    "hash"      : sha256,
                    "malicious" : stats.get("malicious",  0),
                    "suspicious": stats.get("suspicious", 0),
                    "harmless"  : stats.get("harmless",   0),
                    "known"     : True,
                    "file_name" : attrs.get("meaningful_name", "unknown"),
                    "file_type" : attrs.get("type_description", "unknown"),
                })

            elif resp.status_code == 429:
                print("         [VT] Rate limit hit — waiting 60s...")
                time.sleep(60)
                results.append({"hash": sha256, "error": "Rate limited — try again"})

            else:
                results.append({
                    "hash" : sha256,
                    "error": f"HTTP {resp.status_code}",
                })

        except requests.exceptions.RequestException as e:
            results.append({"hash": sha256, "error": str(e)})

        time.sleep(RATE_LIMIT_SLEEP)

    return results
