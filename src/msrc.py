"""
MSRC data ophalen. Werkt met twee paden:
1) API (vereist MSRC_API_KEY env) — rijker, stabieler.
2) RSS fallback (geen key): voldoende voor titels, CVE's en links.

Uitvoer-normalisatie:
[
  {
    "cve": "CVE-2025-XXXX",
    "title": "...",
    "product": "Windows ...",
    "cvss": 7.8,              # indien beschikbaar
    "severity": "Critical|Important|... (optioneel)",
    "published": "2025-09-09",
    "kb": "KB5031234",        # indien beschikbaar
    "url": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-..."
  }, ...
]
"""
import os, re, requests, xml.etree.ElementTree as ET
from datetime import datetime, timezone
from dateutil import parser

API_BASE = "https://api.msrc.microsoft.com/sug/v2.0/en-US"
API_VER  = "2022-01-01"  # kan door MS wijzigen

def _with_api_headers():
    key = os.getenv("MSRC_API_KEY")
    if not key:
        return None
    return {"api-key": key}

def fetch_vulns_via_api(query_days=40, timeout=60) -> list[dict]:
    """
    Vraagt recente CVRF data op (laatste ~query_days).
    Let op: API kan veranderen; probeer defensief te parsen.
    """
    headers = _with_api_headers()
    if not headers:
        return []

    # Recent by lastModifiedStartDate
    url = f"{API_BASE}/vulnerability?api-version={API_VER}&$filter=lastModified ge {datetime.utcnow().date().isoformat()}"
    # De filter hierboven is te strak; fallback zonder filter en client-side filteren.
    url = f"{API_BASE}/vulnerability?api-version={API_VER}"
    r = requests.get(url, headers=headers, timeout=timeout)
    r.raise_for_status()
    data = r.json()
    vulns = []
    for item in data.get("value", []):
        cve = item.get("cveNumber") or item.get("cve")
        title = item.get("title") or item.get("vulnTitle")
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
            except:
                published_dt = None
        else:
            published_dt = None
        product = item.get("product") or ", ".join(item.get("products", []) or [])
        kb = item.get("kbArticles") or ""
        urlv = f"https://msrc.microsoft.com/update-guide/vulnerability/{cve}" if cve else None

        if not cve:
            continue
        vulns.append({
            "cve": cve.strip().upper(),
            "title": title or "",
            "product": product or "",
            "cvss": cvss,
            "severity": severity,
            "published": published_dt,
            "kb": kb if isinstance(kb, str) else ", ".join(kb) if kb else "",
            "url": urlv
        })
    return vulns

def fetch_vulns_via_rss(timeout=60) -> list[dict]:
    """
    Simpele RSS fallback: https://msrc.microsoft.com/update-guide/rss
    Entries bevatten title (incl. CVE), link en publish date.
    """
    rss_url = "https://msrc.microsoft.com/update-guide/rss"
    r = requests.get(rss_url, timeout=timeout)
    r.raise_for_status()
    root = ET.fromstring(r.text)
    ns = {"atom": "http://www.w3.org/2005/Atom", "rss": "http://purl.org/rss/1.0/"}
    items = root.findall(".//item")
    vulns = []
    for it in items:
        title = (it.findtext("title") or "").strip()
        link = (it.findtext("link") or "").strip()
        pub = (it.findtext("pubDate") or "").strip()
        try:
            published_dt = parser.parse(pub).date().isoformat()
        except:
            published_dt = None

        # Probeer CVE uit titel te halen
        m = re.search(r"(CVE-\d{4}-\d+)", title, re.IGNORECASE)
        cve = m.group(1).upper() if m else None
        if not cve:
            continue
        vulns.append({
            "cve": cve,
            "title": title,
            "product": "",       # Niet beschikbaar in RSS
            "cvss": None,        # Niet beschikbaar in RSS
            "severity": "",
            "published": published_dt,
            "kb": "",
            "url": link
        })
    return vulns

def fetch_vulnerabilities() -> list[dict]:
    api = fetch_vulns_via_api()
    return api if api else fetch_vulns_via_rss()
