""" SUG v2 API (zonder key) + CVRF v3.0 enrichment + NVD fallback voor CVSS/Severity + RSS fallback.
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

import re
import time
import json
import logging
from typing import Any, Dict, List, Tuple, Optional

import requests
import xml.etree.ElementTree as ET
from dateutil import parser

from .enrichers.nvd import enrich_many as nvd_enrich

# Endpoints
API_BASE = "https://api.msrc.microsoft.com/sug/v2.0/en-US"
LIST_URL = f"{API_BASE}/vulnerability"
DETAIL_URL = f"{API_BASE}/vulnerability/{{cve}}"
CVRF_BASE = "https://api.msrc.microsoft.com/cvrf/v3.0/cvrf"
RSS_URL = "https://api.msrc.microsoft.com/update-guide/rss"

# ---------- helpers ----------

def _try_float(x) -> Optional[float]:
    try:
        return float(x) if x not in (None, "") else None
    except Exception:
        return None

def _iso_date(s: Optional[str]) -> Optional[str]:
    if not s:
        return None
    try:
        return parser.parse(s).date().isoformat()
    except Exception:
        return None

def _first_nonempty(*vals: Any) -> str:
    for v in vals:
        if v is None:
            continue
        if isinstance(v, str) and v.strip():
            return v.strip()
        if not isinstance(v, str) and v:
            return str(v)
    return ""

def _norm_kb(kb: Any) -> str:
    """
    Normalize KB values to a comma-separated string.
    Accepts a string, list[str], or list[dict] with common keys.
    """
    if not kb:
        return ""
    if isinstance(kb, str):
        return kb
    if isinstance(kb, list):
        vals: List[str] = []
        for item in kb:
            if isinstance(item, str):
                vals.append(item)
            elif isinstance(item, dict):
                # FIX: body toegevoegd i.p.v. lege 'for'-regel
                for k in ("kbid", "kb", "id", "value", "KB"):
                    if k in item and item[k]:
                        vals.append(str(item[k]))
                        break
        return ", ".join(dict.fromkeys(v.strip() for v in vals if v))  # unique-preserving
    if isinstance(kb, dict):
        for k in ("kbid", "kb", "id", "value", "KB"):
            if k in kb and kb[k]:
                return str(kb[k])
        return ""
    return str(kb)

def _http_get_json(url: str, params: Optional[dict] = None, timeout: int = 30) -> Optional[dict]:
    try:
        r = requests.get(url, params=params, timeout=timeout)
        r.raise_for_status()
        return r.json()
    except Exception as e:
        logging.warning("GET %s failed: %s", url, e)
        return None

def _http_get_text(url: str, params: Optional[dict] = None, timeout: int = 30) -> Optional[str]:
    try:
        r = requests.get(url, params=params, timeout=timeout)
        r.raise_for_status()
        return r.text
    except Exception as e:
        logging.warning("GET %s failed: %s", url, e)
        return None

# ---------- core fetchers ----------

def fetch_vulns_via_api(force_detail: bool = False, detail_cap: int = 1000) -> List[dict]:
    """
    Haal lijst van SUG (v2) en verrijk optioneel met detail endpoints.
    """
    data = _http_get_json(LIST_URL) or {}
    items = data.get("vulnerabilities") or data.get("value") or []
    rows: List[dict] = []

    for it in items:
        cve = _first_nonempty(it.get("cveNumber"), it.get("cveId"), it.get("cve"), it.get("ID"))
        if not cve:
            continue

        title = _first_nonempty(it.get("title"))
        product = _first_nonempty(it.get("product"), it.get("productName"))
        severity = _first_nonempty(it.get("severity"))
        cvss = _try_float(it.get("cvssScore") or it.get("cvssV3Score") or it.get("cvss"))
        published = _iso_date(_first_nonempty(it.get("publishedDate"), it.get("published"), it.get("releaseDate")))
        url = f"https://msrc.microsoft.com/update-guide/vulnerability/{cve}"

        kb = _norm_kb(it.get("kbArticles") or it.get("kb") or it.get("kbs"))

        rows.append({
            "cve": cve,
            "title": title,
            "product": product,
            "severity": severity,
            "cvss": cvss,
            "published": published,
            "kb": kb,
            "url": url,
        })

    if force_detail and rows:
        # Verrijk per-CVE detail (cap voor performance)
        for r in rows[:max(0, detail_cap)]:
            cve = r["cve"]
            det = _http_get_json(DETAIL_URL.format(cve=cve))
            if not det:
                continue
            # Proberen aanvullende info eruit te halen
            try:
                d = det.get("vulnerability", det)
                if isinstance(d, dict):
                    r["title"] = _first_nonempty(r.get("title"), d.get("title"))
                    r["product"] = _first_nonempty(r.get("product"), d.get("product"))
                    r["severity"] = _first_nonempty(r.get("severity"), d.get("severity"))
                    r["cvss"] = r["cvss"] if r.get("cvss") is not None else _try_float(
                        d.get("cvssScore") or d.get("cvssV3Score") or d.get("cvss")
                    )
                    r["kb"] = _first_nonempty(r.get("kb"), _norm_kb(d.get("kbArticles")))
                    r["published"] = r["published"] or _iso_date(
                        _first_nonempty(d.get("publishedDate"), d.get("published"))
                    )
            except Exception as e:
                logging.debug("detail enrich fail for %s: %s", cve, e)

    return rows

def fetch_vulns_via_rss() -> List[dict]:
    """
    Fallback: parse MSRC Update Guide RSS.
    """
    text = _http_get_text(RSS_URL)
    if not text:
        return []

    rows: List[dict] = []
    try:
        root = ET.fromstring(text)
        # namespace-agnostic simpel parse
        for item in root.findall(".//item"):
            title = _first_nonempty(item.findtext("title"))
            link = _first_nonempty(item.findtext("link"))
            pubdate = _iso_date(item.findtext("pubDate"))
            # CVE uit title of link proberen te vissen
            m = re.search(r"(CVE-\d{4}-\d+)", (title or "") + " " + (link or ""), re.I)
            cve = m.group(1).upper() if m else ""
            if not cve:
                continue
            rows.append({
                "cve": cve,
                "title": title or cve,
                "product": "",
                "severity": "",
                "cvss": None,
                "published": pubdate,
                "kb": "",
                "url": link or f"https://msrc.microsoft.com/update-guide/vulnerability/{cve}",
            })
    except Exception as e:
        logging.warning("RSS parse failed: %s", e)
        return []

    return rows

# ---------- enrichers ----------

def enrich_with_cvrf(rows: List[dict]) -> List[dict]:
    """
    Best-effort CVRF enrichment. Het CVRF v3 endpoint gebruikt normaliter document IDs,
    maar we proberen op CVE te zoeken in de JSON response waar mogelijk.
    """
    if not rows:
        return rows

    # Beperkt aantal requests: vaak maandelijks document, maar we doen een eenvoudige poging:
    # (We laten zware CVRF-logic achterwege en vullen alleen als we iets bruikbaars vinden.)
    try:
        # Sommige implementaties exposen een "cvrf" index. Als het faalt, slaan we over.
        resp = _http_get_json(CVRF_BASE)
        if not resp:
            return rows

        # Heuristiek: doorzoek tekst naar KB's / productnamen / titels per CVE
        text = json.dumps(resp, ensure_ascii=False)
        for r in rows:
            cve = r.get("cve")
            if not cve:
                continue
            # KB's uit CVRF tekst matchen
            kb_hits = sorted(set(re.findall(rf"\bKB\d+\b", text, flags=re.I)))
            if kb_hits and not r.get("kb"):
                r["kb"] = ", ".join(kb_hits[:5])  # cap om het netjes te houden
    except Exception as e:
        logging.debug("CVRF enrichment skipped: %s", e)

    return rows

def enrich_with_nvd(rows: List[dict]) -> List[dict]:
    """
    Vul ontbrekende CVSS/severity vanuit NVD (via lokale enricher).
    """
    if not rows:
        return rows

    missing = [r["cve"] for r in rows if not r.get("severity") or r.get("cvss") is None]
    if not missing:
        return rows

    try:
        nvd_map = nvd_enrich(missing)  # verwacht dict: {cve: {"cvss": float, "severity": "High"...}}
    except Exception as e:
        logging.warning("NVD enrichment failed: %s", e)
        return rows

    for r in rows:
        info = nvd_map.get(r["cve"])
        if not info:
            continue
        if r.get("cvss") is None and info.get("cvss") is not None:
            r["cvss"] = _try_float(info["cvss"])
        if not r.get("severity") and info.get("severity"):
            r["severity"] = str(info["severity"])

    return rows
