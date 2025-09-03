"""
SUG v2 API (zonder key) + sterke CVRF v3.0 enrichment + NVD fallback voor CVSS/Severity + RSS fallback.

Output per row:
{
  "cve": "CVE-2025-XXXX",
  "title": "...",
  "product": "Windows ...",
  "cvss": 7.8,
  "severity": "Critical|Important|High|Medium|Low",
  "published": "YYYY-MM-DD",
  "kb": "KB5031234, ...",
  "url": "https://msrc.microsoft.com/update-guide/vulnerability/CVE-..."
}
"""
from __future__ import annotations
import re, time, requests, xml.etree.ElementTree as ET
from collections import defaultdict
from dateutil import parser

from .enrichers.nvd import enrich_many as nvd_enrich

API_BASE   = "https://api.msrc.microsoft.com/sug/v2.0/en-US"
LIST_URL   = f"{API_BASE}/vulnerability"
DETAIL_URL = f"{API_BASE}/vulnerability/{{cve}}"
CVRF_BASE  = "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf"
RSS_URL    = "https://api.msrc.microsoft.com/update-guide/rss"

# ---------------- helpers ----------------

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
                for k in ("kbid","kb","id","value","KB"):
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
    if t.startswith("chromium:") or "edge (chromium" in t or "chromium-based" in t:
        return "Microsoft Edge (Chromium-based)"
    if "sql server" in t: return "Microsoft SQL Server"
    if "exchange server" in t: return "Microsoft Exchange Server"
    if "sharepoint" in t: return "Microsoft SharePoint"
    if "azure" in t: return "Microsoft Azure"
    if "teams" in t: return "Microsoft Teams"
    if "windows" in t: return "Windows"
    if any(w in t for w in ["office", "word ", "excel ", "powerpoint", "visio"]):
        return "Microsoft Office"
    return ""

# --------------- SUG list + detail ---------------

def fetch_vulns_via_api(timeout=60, max_pages=8, page_size=1000) -> list[dict]:
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
        time.sleep(0.15)  # gebalanceerd op CI

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
        if not title or not product or not published or (not severity and cvss is None and not kb):
            needs_detail.append((cve, row))
        out.append(row)

    for cve, row in needs_detail[:200]:
        try:
            d = _fetch_detail(cve, timeout=timeout)
            if not d: continue
            row["title"]     = row["title"] or d.get("title","") or d.get("vulnTitle","")
            row["severity"]  = row["severity"] or (d.get("severity") or "").strip()
            row["cvss"]      = row["cvss"] if row["cvss"] is not None else _try_float(d.get("cvssScore"))
            row["product"]   = row["product"] or _norm_products(d.get("product"), d.get("products"))
            row["kb"]        = row["kb"] or _norm_kb(d.get("kbArticles"))
            row["published"] = row["published"] or _iso_date(d.get("publishDate") or d.get("publishedDate"))
        except Exception as e:
            print(f"WARN: detail {cve} mislukt: {e}")
        time.sleep(0.1)
    return out

def _fetch_detail(cve: str, timeout=30) -> dict | None:
    url = DETAIL_URL.format(cve=cve)
    r = requests.get(url, timeout=timeout, headers={"Accept":"application/json"})
    if r.status_code == 404: return None
    r.raise_for_status()
    return r.json()

# --------------- CVRF enrichment (product/kb/cvss/severity waar mogelijk) ---------------

def _cvrf_doc_id(iso_date: str) -> str | None:
    if not iso_date: return None
    try:
        dt = parser.parse(iso_date)
        return dt.strftime("%Y-%b")  # bijv. 2025-Aug
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
        print(f"WARN: CVRF {doc_id} geen XML.")
        return None
    try:
        return ET.fromstring(txt)
    except ET.ParseError as e:
        print(f"WARN: CVRF {doc_id} parse error: {e}")
        return None

def _cvrf_build_maps(root: ET.Element):
    ns = {"cvrf":"http://www.icasi.org/CVRF/schema/v1.1"}

    pid_to_name = {}
    for fp in root.findall(".//cvrf:FullProductName", ns):
        pid = fp.get("ProductID")
        name = (fp.text or "").strip()
        if pid and name:
            pid_to_name[pid] = name

    vulns = {}
    for v in root.findall(".//cvrf:Vulnerability", ns):
        cve = (v.findtext("cvrf:CVE", default="", namespaces=ns) or "").strip().upper()
        if not cve: continue

        prod_ids = set()
        for pid in v.findall(".//cvrf:ProductStatuses/cvrf:Status/cvrf:ProductID", ns):
            if pid.text: prod_ids.add(pid.text.strip())
        if not prod_ids:
            for pid in v.findall(".//cvrf:ProductID", ns):
                if pid.text: prod_ids.add(pid.text.strip())

        # CVSS
        cvss = None
        for score in v.findall(".//cvrf:BaseScore", ns):
            cvss = _try_float(score.text)
            if cvss is not None: break
        if cvss is None:
            for score in v.findall(".//cvrf:CVSSScoreSets//cvrf:CVSSScoreSet//cvrf:BaseScore", ns):
                cvss = _try_float(score.text)
                if cvss is not None: break

        # Severity
        severity = v.findtext(".//cvrf:CVSSSeverity", default="", namespaces=ns) or ""
        severity = severity.strip()
        if not severity:
            for th in v.findall(".//cvrf:Threats/cvrf:Threat", ns):
                ttype = (th.findtext("cvrf:Type", default="", namespaces=ns) or "").strip().lower()
                if ttype in ("impact","severity"):
                    desc = th.findtext("cvrf:Description", default="", namespaces=ns) or ""
                    m = re.search(r"\b(Critical|Important|Moderate|Low|High|Medium)\b", desc, re.IGNORECASE)
                    if m:
                        severity = m.group(1).capitalize()
                        break

        # KB’s
        kb_set = set()
        for node in v.findall(".//cvrf:Remediations//cvrf:Description", ns) + v.findall(".//cvrf:Remediations//cvrf:URL", ns):
            for m in re.findall(r"KB\d{7,}", (node.text or "")):
                kb_set.add(m)
        for note in v.findall(".//cvrf:Notes/cvrf:Note", ns):
            for m in re.findall(r"KB\d{7,}", (note.text or "")):
                kb_set.add(m)

        vulns[cve] = {
            "product_ids": prod_ids,
            "cvss": cvss,
            "severity": severity,
            "kbs": ", ".join(sorted(kb_set)) if kb_set else ""
        }
    return pid_to_name, vulns

def enrich_with_cvrf(rows: list[dict]) -> list[dict]:
    by_doc = defaultdict(list)
    for r in rows:
        doc_id = _cvrf_doc_id(r.get("published"))
        if doc_id:
            by_doc[doc_id].append(r)

    for doc_id, items in by_doc.items():
        root = _fetch_cvrf_xml(doc_id)
        if not root:
            for r in items:
                if not r.get("product"):
                    r["product"] = _derive_product_from_title(r.get("title",""))
            continue

        pid_to_name, cvrf_map = _cvrf_build_maps(root)
        for r in items:
            info = cvrf_map.get(r["cve"])
            if not info:
                if not r.get("product"):
                    r["product"] = _derive_product_from_title(r.get("title",""))
                continue

            if not r.get("product") and info["product_ids"]:
                names = [pid_to_name.get(pid) for pid in info["product_ids"] if pid_to_name.get(pid)]
                if names:
                    r["product"] = ", ".join(sorted(set(names)))

            if not r.get("kb") and info["kbs"]:
                r["kb"] = info["kbs"]

            if r.get("cvss") is None and info["cvss"] is not None:
                r["cvss"] = info["cvss"]

            if not r.get("severity") and info["severity"]:
                r["severity"] = info["severity"]

    return rows

# --------------- NVD fallback voor CVSS/Severity ---------------

def enrich_with_nvd(rows: list[dict]) -> list[dict]:
    need = [r["cve"] for r in rows if (r.get("cvss") is None or not r.get("severity"))]
    if not need:
        return rows
    nvd_map = nvd_enrich(need, delay_sec=0.2)
    for r in rows:
        info = nvd_map.get(r["cve"])
        if not info:
            continue
        if r.get("cvss") is None and info.get("cvss") is not None:
            r["cvss"] = info["cvss"]
        if not r.get("severity") and info.get("severity"):
            # Harmoniseer NVD (HIGH/MEDIUM/LOW/CRITICAL) naar MS-stijl waar logisch
            sev = info["severity"].capitalize()
            r["severity"] = "Critical" if sev == "Critical" else "Important" if sev == "High" else "Moderate" if sev == "Medium" else "Low" if sev == "Low" else sev
    return rows

# --------------- RSS fallback ---------------

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
        pub  = (it.findtext("pubDate") or "").strip()
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

# --------------- entrypoint ---------------

def fetch_vulnerabilities() -> list[dict]:
    rows = fetch_vulns_via_api()
    rows = enrich_with_cvrf(rows)   # product/kb/cvss/severity waar mogelijk
    rows = enrich_with_nvd(rows)    # wat nog leeg is: vul met NVD
    if not rows:
        rows = fetch_vulns_via_rss()
    print(f"INFO: totaal {len(rows)} items na enrichment.")
    return rows
