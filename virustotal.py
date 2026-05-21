import base64
import time
import requests


VT_BASE = "https://www.virustotal.com/api/v3"


RATE_LIMIT_SLEEP = 16


def scan_urls_vt(urls: list, api_key: str, verbose: bool = False) -> list[dict]:
    
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

      
            time.sleep(5)  

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

      
        time.sleep(RATE_LIMIT_SLEEP)

    return results

def scan_hashes_vt(hashes: list[str], api_key: str,
                   verbose: bool = False) -> list[dict]:
    
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
