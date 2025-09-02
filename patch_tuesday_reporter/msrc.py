"""
MSRC data ophalen. Werkt met twee paden:
1) API (vereist MSRC_API_KEY env) — rijker, stabieler.
2) RSS fallback (geen key of fout) — minder rijk, maar bruikbaar.

Uitvoer-normalisatie:
[
  {
    "cve": "CVE-2025-XXXX",
    "title": "...",
    "product": "Windows ...",
    "cvss": 7.8,
    "severity": "Critical|Important|...",
    "published": "2025-09-09",
    "kb": "KB5031234",
    "url": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-..."
  }, ...
]
"""

import os, re, requests, xml.etree.ElementTree as ET
from dateutil import parser

API_BASE = "https://api.msrc.microsoft.com/sug/v2.0/en-US"
API_VER  = "2022-01-01"  # kan wijzigen

def _with_api_headers():
    key = os.getenv("MSRC_API_KEY")
    if not key:
        return None
    return {"api-key": key}

def fetch_vulns_via_api(timeout=60) -> list[dict]:
    headers = _with_api_headers()
    if not headers:
        return []

    url = f"{API_BASE}/vulnerability?api-version={API_VER}"
    try:
        r = requests.get(url, headers=headers, timeout=timeout)
        r.raise_for_status()
    except Exception as e:
        print(f"WARN: API call naar MSRC mislukt: {e}")
        return []

    data = r.json()
    vulns = []
    for item in data.get("value", []):
        cve = item.get("cveNumber") or item.get("cve")
        if not cve:
            continue
        title = item.get("title") or item.get("vulnTitle") or ""
        severity = (item.get("severity") or "").strip()
        cvss = item.get("cvssScore")
        try:
            cvss = float(cvss) if cvss is not None else None
        except:
            cvss = None
        published = item.get("publishedDate") or item.get("publishDate")
        if published:
            try:
                published_dt = parser.parse(published).date().isoformat()
            except Exception:
                published_dt = None
        else:
            published_dt = None
        product = item.get("product") or ", ".join(item.get("products", []) or [])
        kb = item.get("kbArticles") or ""
        urlv = f"https://msrc.microsoft.com/update-guide/vulnerability/{cve}"

        vulns.append({
            "cve": cve.strip().upper(),
            "title": title,
            "product": product or "",
            "cvss": cvss,
            "severity": severity,
            "published": published_dt,
            "kb": kb if isinstance(kb, str) else ", ".join(kb) if kb else "",
            "url": urlv
        })
    return vulns

def fetch_vulns_via_rss(timeout=60) -> list[dict]:
    rss_url = "https://msrc.microsoft.com/update-guide/rss"
    try:
        r = requests.get(rss_url, timeout=timeout, headers={"User-Agent": "Mozilla/5.0"})
        r.raise_for_status()
    except Exception as e:
        print(f"WARN: RSS ophalen mislukt: {e}")
        return []

    text = r.text.strip()

    # Quick sanity check: RSS zou XML moeten zijn
    if not text.startswith("<?xml") and "<rss" not in text.lower():
        print("WARN: RSS feed is geen geldige XML (waarschijnlijk HTML ontvangen).")
        return []

    try:
        root = ET.fromstring(text)
    except ET.ParseError as e:
        print(f"WARN: Fout bij parsen RSS: {e}")
        return []

    items = root.findall(".//item")
    vulns = []
    for it in items:
        title = (it.findtext("title") or "").strip()
        link = (it.findtext("link") or "").strip()
        pub = (it.findtext("pubDate") or "").strip()
        try:
            published_dt = parser.parse(pub).date().isoformat()
        except Exception:
            published_dt = None

        m = re.search(r"(CVE-\d{4}-\d+)", title, re.IGNORECASE)
        cve = m.group(1).upper() if m else None
        if not cve:
            continue
        vulns.append({
            "cve": cve,
            "title": title,
            "product": "",
            "cvss": None,
            "severity": "",
            "published": published_dt,
            "kb": "",
            "url": link
        })
    return vulns

def fetch_vulnerabilities() -> list[dict]:
    """Probeer eerst API, anders RSS fallback."""
    vulns = fetch_vulns_via_api()
    if vulns:
        print(f"INFO: {len(vulns)} items geladen via MSRC API")
        return vulns
    vulns = fetch_vulns_via_rss()
    print(f"INFO: {len(vulns)} items geladen via RSS fallback")
    return vulns
