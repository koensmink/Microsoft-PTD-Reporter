# patch_tuesday_reporter/msrc.py
"""
SUG v2 API (zonder key) + CVRF v3.0 enrichment + robuuste RSS fallback.

Output rows:
{
  "cve": "CVE-2025-XXXX",
  "title": "...",
  "product": "Windows Server, ...",
  "cvss": 7.8,
  "severity": "Critical|Important|...",
  "published": "YYYY-MM-DD",
  "kb": "KB5031234, KB5035678",
  "url": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-..."
}
"""
import re, requests, xml.etree.ElementTree as ET
from collections import defaultdict
from dateutil import parser

API_BASE = "https://api.msrc.microsoft.com/sug/v2.0/en-US"
LIST_URL = f"{API_BASE}/vulnerability"
DETAIL_URL = f"{API_BASE}/vulnerability/{{cve}}"

CVRF_BASE = "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf"  # e.g. /2025-Aug
RSS_URL   = "https://api.msrc.microsoft.com/update-guide/rss"

# ----------------- kleine helpers -----------------

def _try_float(x):
    try: return float(x) if x not in (None, "") else None
    except: return None

def _iso_date(s):
    if not s: return None
    try: return parser.parse(s).date().isoformat()
    except: return None

def _norm_kb(kb):
    if not kb: return ""
    if isinstance(kb, str): return kb
    if isinstance(kb, list):
        vals = []
        for item in kb:
            if isinstance(item, str):
                vals.append(item)
            elif isinstance(item, dict):
                for k in ("kbid", "kb", "id", "value"):
                    if item.get(k):
                        vals.append(str(item[k])); break
        return ", ".join(sorted(set(vals)))
    return str(kb)

def _norm_products(prod, products):
    if prod: return prod
    if not products: return ""
    if isinstance(products, list):
        return ", ".join(sorted({str(p) for p in products if p}))
    return str(products)

def _derive_product_from_title(title: str) -> str:
    t = (title or "").lower()
    if t.startswith("chromium:"): return "Microsoft Edge (Chromium-based)"
    if "sql server" in t: return "Microsoft SQL Server"
    if "exchange server" in t: return "Microsoft Exchange Server"
    if "sharepoint" in t: return "Microsoft SharePoint"
    if "windows" in t: return "Windows"
    if "office" in t or "word " in t or "excel " in t or "powerpoint" in t or "visio" in t:
        return "Microsoft Office"
    if "teams" in t: return "Microsoft Teams"
    if "azure" in t: return "Microsoft Azure"
    return ""

# ----------------- SUG v2 list + detail -----------------

def fetch_vulns_via_api(timeout=60, max_pages=10, page_size=1000) -> list[dict]:
    select = ",".join([
        "cveNumber","title","severity","cvssScore","product","products",
        "kbArticles","publishDate","publishedDate","vulnTitle"
    ])
    url = f"{LIST_URL}?$select={select}&$top={page_size}"

    all_items, pages = [], 0
    while url and pages < max_pages:
        try:
            r = requests.get(url, timeout=timeout, headers={"Accept":"application/json"})
            r.raise_for_status()
            data = r.json()
        except Exception as e:
            print(f"WARN: SUG list call mislukt: {e}")
            break
        all_items.extend(data.get("value", []))
        url = data.get("@odata.nextLink")
        pages += 1

    out, needs_detail = [], []
    for it in all_items:
        cve = (it.get("cveNumber") or it.get("cve") or "").strip().upper()
        if not cve: continue
        title = it.get("title") or it.get("vulnTitle") or ""
        severity = (it.get("severity") or "").strip()
        cvss = _try_float(it.get("cvssScore"))
        published = _iso_date(it.get("publishDate") or it.get("publishedDate"))
        product = _norm_products(it.get("product"), it.get("products"))
        kb = _norm_kb(it.get("kbArticles"))

        row = {
            "cve": cve, "title": title, "product": product,
            "cvss": cvss, "severity": severity, "published": published,
            "kb": kb, "url": f"https://msrc.microsoft.com/update-guide/vulnerability/{cve}"
        }
        if not title or not product or not published or (severity == "" and cvss is None and kb == ""):
            needs_detail.append((cve, row))
        out.append(row)

    # detail calls (cap op 200 om throttling te beperken)
    for cve, row in needs_detail[:200]:
        try:
            d = _fetch_detail(cve, timeout=timeout)
            if not d: continue
            row["title"] = row["title"] or d.get("title","") or d.get("vulnTitle","")
            row["severity"] = row["severity"] or (d.get("severity") or "").strip()
            row["cvss"] = row["cvss"] if row["cvss"] is not None else _try_float(d.get("cvssScore"))
            row["product"] = row["product"] or _norm_products(d.get("product"), d.get("products"))
            row["kb"] = row["kb"] or _norm_kb(d.get("kbArticles"))
            row["published"] = row["published"] or _iso_date(d.get("publishDate") or d.get("publishedDate"))
        except Exception as e:
            print(f"WARN: detail {cve} mislukt: {e}")

    return out

def _fetch_detail(cve: str, timeout=30) -> dict | None:
    url = DETAIL_URL.format(cve=cve)
    r = requests.get(url, timeout=timeout, headers={"Accept":"application/json"})
    if r.status_code == 404: return None
    r.raise_for_status()
    return r.json()

# ----------------- CVRF enrichment -----------------

def _cvrf_doc_id(iso_date: str) -> str | None:
    if not iso_date: return None
    # verwacht 'YYYY-MM-DD' → 'YYYY-Mon' (Engelse maand afk.)
    try:
        dt = parser.parse(iso_date)
        return dt.strftime("%Y-%b")  # e.g., 2025-Aug
    except: return None

def _fetch_cvrf_xml(doc_id: str, timeout=60) -> ET.Element | None:
    url = f"{CVRF_BASE}/{doc_id}"
    try:
        r = requests.get(url, timeout=timeout, headers={"User-Agent":"Mozilla/5.0"})
        r.raise_for_status()
    except Exception as e:
        print(f"WARN: CVRF {doc_id} ophalen mislukt: {e}")
        return None

    txt = r.text.strip()
    if not txt.startswith("<?xml") and "<cvrf:document" not in txt.lower():
        print(f"WARN: CVRF {doc_id} lijkt geen XML.")
        return None
    try:
        return ET.fromstring(txt)
    except ET.ParseError as e:
        print(f"WARN: CVRF {doc_id} parse error: {e}")
        return None

def _cvrf_build_maps(root: ET.Element):
    ns = {"cvrf":"http://www.icasi.org/CVRF/schema/v1.1"}  # MS gebruikt nog steeds deze namespace in v3 endpoint
    # ProductTree: map ID -> FullProductName
    pid_to_name = {}
    for fp in root.findall(".//cvrf:FullProductName", ns):
        pid = fp.get("ProductID")
        name = (fp.text or "").strip()
        if pid and name:
            pid_to_name[pid] = name

    # Vulnerabilities: map CVE -> set(ProductIDs), CVSS/Severity, KBs
    vulns = {}
    for v in root.findall(".//cvrf:Vulnerability", ns):
        cve = (v.findtext("cvrf:CVE", default="", namespaces=ns) or "").strip().upper()
        if not cve: continue
        prod_ids = set()
        for e in v.findall(".//cvrf:ProductID", ns):
            if e.text: prod_ids.add(e.text.strip())

        # CVSS base score (v2/v3 kunnen beide voorkomen)
        cvss = None
        for score in v.findall(".//cvrf:BaseScore", ns):
            cvss = _try_float(score.text)
            if cvss is not None: break

        # Severity – MS gebruikt vaak 'Threats/Threat/Description' of 'CVSSSeverity'
        severity = v.findtext(".//cvrf:CVSSSeverity", default="", namespaces=ns) or ""
        severity = severity.strip()

        # KB’s – vaak in Remediations/Description of URL
        kb_set = set()
        for desc in v.findall(".//cvrf:Remediations//cvrf:Description", ns):
            for m in re.findall(r"KB\d{7,}", (desc.text or "")):
                kb_set.add(m)
        for url in v.findall(".//cvrf:Remediations//cvrf:URL", ns):
            for m in re.findall(r"KB\d{7,}", (url.text or "")):
                kb_set.add(m)

        vulns[cve] = {
            "product_ids": prod_ids,
            "cvss": cvss,
            "severity": severity,
            "kbs": ", ".join(sorted(kb_set)) if kb_set else ""
        }
    return pid_to_name, vulns

def enrich_with_cvrf(rows: list[dict]) -> list[dict]:
    # Groepeer per maand-ID en verrijk ontbrekende velden
    by_doc = defaultdict(list)
    for r in rows:
        doc_id = _cvrf_doc_id(r.get("published"))
        if doc_id:
            by_doc[doc_id].append(r)

    for doc_id, items in by_doc.items():
        root = _fetch_cvrf_xml(doc_id)
        if not root: 
            # fallback: zet afgeleide product voor Chromium/Windows etc.
            for r in items:
                if not r.get("product"):
                    r["product"] = _derive_product_from_title(r.get("title",""))
            continue
        pid_to_name, cvrf_map = _cvrf_build_maps(root)

        for r in items:
            cve = r["cve"]
            info = cvrf_map.get(cve)
            if not info:
                # geen match in CVRF → heuristiek voor product
                if not r.get("product"):
                    r["product"] = _derive_product_from_title(r.get("title",""))
                continue

            # Producten mappen
            if not r.get("product") and info["product_ids"]:
                names = [pid_to_name.get(pid) for pid in info["product_ids"] if pid_to_name.get(pid)]
                if names:
                    r["product"] = ", ".join(sorted(set(names)))

            # KB’s aanvullen
            if not r.get("kb"):
                r["kb"] = info["kbs"]

            # CVSS/Severity aanvullen wanneer leeg
            if r.get("cvss") is None and info["cvss"] is not None:
                r["cvss"] = info["cvss"]
            if not r.get("severity") and info["severity"]:
                r["severity"] = info["severity"]

            # Als published leeg was, laat zoals is (SUG geeft dat meestal wel)
    return rows

# ----------------- RSS fallback -----------------

def fetch_vulns_via_rss(timeout=60) -> list[dict]:
    try:
        r = requests.get(RSS_URL, timeout=timeout, headers={"User-Agent":"Mozilla/5.0"})
        r.raise_for_status()
    except Exception as e:
        print(f"WARN: RSS ophalen mislukt: {e}")
        return []

    text = r.text.strip()
    if not text.startswith("<?xml") and "<rss" not in text.lower():
        print("WARN: RSS geen geldige XML (waarschijnlijk HTML ontvangen).")
        return []

    try:
        root = ET.fromstring(text)
    except ET.ParseError as e:
        print(f"WARN: RSS parse error: {e}")
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
        if not cve: continue
        vulns.append({
            "cve": cve, "title": title,
            "product": _derive_product_from_title(title),
            "cvss": None, "severity": "",
            "published": published_dt, "kb": "",
            "url": link or f"https://msrc.microsoft.com/update-guide/vulnerability/{cve}"
        })
    return vulns

# ----------------- publieke entrypoint -----------------

def fetch_vulnerabilities() -> list[dict]:
    # 1) SUG lijst + detail
    rows = fetch_vulns_via_api()
    # 2) CVRF enrich voor missende velden
    rows = enrich_with_cvrf(rows)
    # 3) Als SUG niets gaf, fallback op RSS
    if not rows:
        rows = fetch_vulns_via_rss()
    print(f"INFO: totaal {len(rows)} items na enrichment.")
    return rows
