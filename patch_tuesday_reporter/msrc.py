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
