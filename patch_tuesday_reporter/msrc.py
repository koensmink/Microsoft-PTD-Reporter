"""
MSRC data ophalen via SUG v2 API (zonder API key) met RSS fallback.

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
import re, requests, xml.etree.ElementTree as ET
from dateutil import parser

API_BASE = "https://api.msrc.microsoft.com/sug/v2.0/en-US"

def fetch_vulns_via_api(timeout=60) -> list[dict]:
    """
    Probeert de SUG v2 'vulnerability' endpoint zonder auth (API key niet meer vereist).
    Als er toch een 401/403 komt, geven we [] terug (caller mag RSS proberen).
    """
    url = f"{API_BASE}/vulnerability"
    try:
        r = requests.get(url, timeout=timeout, headers={"Accept": "application/json"})
        # als MS throttled of tijdelijk 50x geeft, raise_for_status triggert except
        r.raise_for_status()
    except requests.HTTPError as e:
        code = getattr(e.response, "status_code", None)
        print(f"WARN: SUG API HTTP {code}: {e}")
        return []
    except Exception as e:
        print(f"WARN: SUG API call mislukt: {e}")
        return []

    try:
        data = r.json()
    except Exception as e:
        print(f"WARN: SUG API gaf geen JSON: {e}")
        return []

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
    """
    Robuuste RSS fallback (sommige omgevingen krijgen HTML/redirects terug).
    """
    rss_url = "https://msrc.microsoft.com/update-guide/rss"
    try:
        r = requests.get(rss_url, timeout=timeout, headers={"User-Agent": "Mozilla/5.0"})
        r.raise_for_status()
    except Exception as e:
        print(f"WARN: RSS ophalen mislukt: {e}")
        return []

    text = r.text.strip()
    # Sanity check: verwacht XML, niet HTML
    if not text.startswith("<?xml") and "<rss" not in text.lower():
        print("WARN: RSS geen geldige XML (waarschijnlijk HTML ontvangen).")
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
    """
    Eerst SUG v2 API proberen (zonder key); als dat niets oplevert, RSS fallback.
    """
    api = fetch_vulns_via_api()
    if api:
        print(f"INFO: {len(api)} items geladen via SUG v2 API (zonder key).")
        return api
    rss = fetch_vulns_via_rss()
    print(f"INFO: {len(rss)} items geladen via RSS fallback.")
    return rss
