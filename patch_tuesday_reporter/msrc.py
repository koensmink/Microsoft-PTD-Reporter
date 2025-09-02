# patch_tuesday_reporter/msrc.py
"""
SUG v2 API (zonder key) + robuuste fallback naar RSS.
Haalt eerst een paginated lijst op met $select en vult lege velden aan via de detail-endpoint.
"""

import re, requests, xml.etree.ElementTree as ET
from dateutil import parser

API_BASE = "https://api.msrc.microsoft.com/sug/v2.0/en-US"
LIST_URL = f"{API_BASE}/vulnerability"
DETAIL_URL = f"{API_BASE}/vulnerability/{{cve}}"

# ----- helpers ---------------------------------------------------------------

def _try_float(x):
    try:
        return float(x) if x is not None and x != "" else None
    except Exception:
        return None

def _iso_date(s):
    if not s:
        return None
    try:
        return parser.parse(s).date().isoformat()
    except Exception:
        return None

def _norm_kb(kb):
    # API kan string, lijst van strings, of lijst van dicts teruggeven
    if not kb:
        return ""
    if isinstance(kb, str):
        return kb
    if isinstance(kb, list):
        vals = []
        for item in kb:
            if isinstance(item, str):
                vals.append(item)
            elif isinstance(item, dict):
                # soms { "kbid": "KB5031234" } o.i.d.
                for k in ("kbid", "kb", "id", "value"):
                    if item.get(k):
                        vals.append(str(item[k]))
                        break
        return ", ".join(sorted(set(vals)))
    return str(kb)

def _norm_products(prod, products):
    # Sommige responses hebben "product", anderen "products" (lijst)
    if prod:
        return prod
    if not products:
        return ""
    if isinstance(products, list):
        return ", ".join(sorted({str(p) for p in products if p}))
    return str(products)

# ----- SUG v2 API ------------------------------------------------------------

def fetch_vulns_via_api(timeout=60, max_pages=10, page_size=1000) -> list[dict]:
    """
    Haal lijst van vulnerabilities op met expliciet $select en paging.
    Vul ontbrekende velden per item aan met detail-endpoint (best effort).
    """
    select = ",".join([
        "cveNumber",
        "title",
        "severity",
        "cvssScore",
        "product",
        "products",
        "kbArticles",
        "publishDate",
        "publishedDate",  # sommige varianten
        "vulnTitle",      # backstop voor oudere/andere velden
    ])
    url = f"{LIST_URL}?$select={select}&$top={page_size}"

    all_items = []
    pages = 0
    while url and pages < max_pages:
        try:
            r = requests.get(url, timeout=timeout, headers={"Accept": "application/json"})
            r.raise_for_status()
            data = r.json()
        except Exception as e:
            print(f"WARN: SUG list call mislukt: {e}")
            break

        vals = data.get("value", [])
        all_items.extend(vals)
        url = data.get("@odata.nextLink")  # paging
        pages += 1

    # Normaliseren en enrichen
    out = []
    missing_detail = []  # candidates met ontbrekende kernvelden
    for it in all_items:
        cve = (it.get("cveNumber") or it.get("cve") or "").strip().upper()
        if not cve:
            continue

        title = it.get("title") or it.get("vulnTitle") or ""
        severity = (it.get("severity") or "").strip()
        cvss = _try_float(it.get("cvssScore"))
        published = _iso_date(it.get("publishDate") or it.get("publishedDate"))
        product = _norm_products(it.get("product"), it.get("products"))
        kb = _norm_kb(it.get("kbArticles"))

        row = {
            "cve": cve,
            "title": title,
            "product": product,
            "cvss": cvss,
            "severity": severity,
            "published": published,
            "kb": kb,
            "url": f"https://msrc.microsoft.com/update-guide/vulnerability/{cve}",
        }

        # als er nog te veel leeg is, later detail call proberen
        if not title or not product or not published:
            missing_detail.append((cve, row))
        out.append(row)

    # Detail-oproep voor ontbrekende velden (beperk tot 200 om misbruik/throttle te vermijden)
    for cve, row in missing_detail[:200]:
        try:
            d = _fetch_detail(cve, timeout=timeout)
            if not d:
                continue
            row["title"] = row["title"] or d.get("title", "")
            row["severity"] = row["severity"] or (d.get("severity") or "").strip()
            row["cvss"] = row["cvss"] if row["cvss"] is not None else _try_float(d.get("cvssScore"))
            row["product"] = row["product"] or _norm_products(d.get("product"), d.get("products"))
            row["kb"] = row["kb"] or _norm_kb(d.get("kbArticles"))
            row["published"] = row["published"] or _iso_date(d.get("publishDate") or d.get("publishedDate"))
        except Exception as e:
            print(f"WARN: detail {cve} mislukt: {e}")

    print(f"INFO: SUG API: {len(out)} items, detail aangevuld voor {min(len(missing_detail),200)} kandidaten.")
    return out

def _fetch_detail(cve: str, timeout=30) -> dict | None:
    url = DETAIL_URL.format(cve=cve)
    r = requests.get(url, timeout=timeout, headers={"Accept": "application/json"})
    if r.status_code == 404:
        return None
    r.raise_for_status()
    return r.json()

# ----- RSS fallback ----------------------------------------------------------

def fetch_vulns_via_rss(timeout=60) -> list[dict]:
    """
    Robuuste RSS fallback (sommige omgevingen krijgen HTML/redirects terug).
    """
    rss_url = "https://api.msrc.microsoft.com/update-guide/rss"
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
        published_dt = _iso_date(pub)

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
            "url": link or f"https://msrc.microsoft.com/update-guide/vulnerability/{cve}"
        })
    return vulns

# ----- public API ------------------------------------------------------------

def fetch_vulnerabilities() -> list[dict]:
    """
    Eerst SUG v2 API proberen (met $select + paging + detail); als dat niets oplevert, RSS fallback.
    """
    api = fetch_vulns_via_api()
    if api:
        print(f"INFO: {len(api)} items geladen via SUG v2 API.")
        return api
    rss = fetch_vulns_via_rss()
    print(f"INFO: {len(rss)} items geladen via RSS fallback.")
    return rss
