import re
from urllib.parse import urlparse
from bs4 import BeautifulSoup
URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "ow.ly", "buff.ly",
    "goo.gl", "short.link", "rb.gy", "cutt.ly", "is.gd",
    "tiny.cc", "shorte.st", "adf.ly", "bc.vc", "clck.ru",
}

SUSPICIOUS_KEYWORDS = [
    "login", "signin", "sign-in", "verify", "verification",
    "secure", "security", "update", "confirm", "account",
    "password", "credential", "billing", "payment", "invoice",
    "click-here", "urgent", "limited-time", "suspended",
]

URL_REGEX = re.compile(
    r'https?://'                  
    r'[a-zA-Z0-9\-._~:/?#\[\]@!$&\'()*+,;=%]+' 
)


def extract_urls(email_data: dict) -> list[dict]:
   
    found_urls = {}   

    html_body  = email_data.get("html_body",  "")
    plain_text = email_data.get("plain_text", "")

    
    if html_body:
        soup = BeautifulSoup(html_body, "html.parser")

        for anchor in soup.find_all("a", href=True):
            url = anchor["href"].strip()

          
            if not url.startswith(("http://", "https://")):
                continue

          
            display_text = anchor.get_text(strip=True)[:100]

            if url not in found_urls:
                found_urls[url] = _build_url_entry(url, "html", display_text)

    
    if plain_text:
        for match in URL_REGEX.finditer(plain_text):
            url = match.group(0).rstrip(".,);\"'")  
            if url not in found_urls:
                found_urls[url] = _build_url_entry(url, "text", "")

   
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
