# patch_tuesday_reporter/enrichers/nvd.py
"""
NVD CVE 2.0 enrichment: haal CVSS v3.1 (of v3.0) baseScore + severity per CVE op.
Docs: https://services.nvd.nist.gov/rest/json/cves/2.0

Gebruik:
    from .enrichers.nvd import enrich_many
    nvd_map = enrich_many(["CVE-2025-1234", "CVE-2025-2345"])
    # nvd_map["CVE-2025-1234"] -> {"cvss": 7.8, "severity": "High"} (severity in NVD-stijl)

Let op:
- NVD hanteert rate limits. We doen een kleine vertraging tussen requests
  en cachen resultaten in-memory binnen dit proces.
"""

from __future__ import annotations
import time
import requests

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Eenvoudige in-memory cache voor deze proces-run
_cache: dict[str, dict] = {}

def _extract_cvss_v31(metric: dict) -> tuple[float | None, str]:
    """
    Pak baseScore en baseSeverity uit een NVD v3.x metric blok.
    Return: (score, severity) — severity in NVD-stijl (Critical/High/Medium/Low).
    """
    try:
        cvss = metric.get("cvssData", {})
        score = cvss.get("baseScore")
        score = float(score) if score is not None else None
        severity = metric.get("baseSeverity") or ""
        severity = severity.capitalize()
        return score, severity
    except Exception:
        return None, ""

def fetch_nvd_cve(cve: str, timeout=20) -> dict | None:
    """
    Haal één CVE op uit NVD. Geeft dict met evt. keys: {"cvss": float|None, "severity": str}
    of {} als niets bruikbaars gevonden is. None bij harde fout.
    """
    cve = (cve or "").strip().upper()
    if not cve:
        return {}

    if cve in _cache:
        return _cache[cve]

    params = {"cveId": cve}
    try:
        r = requests.get(NVD_URL, params=params, timeout=timeout, headers={"User-Agent": "Mozilla/5.0"})
        r.raise_for_status()
        data = r.json()
    except Exception as e:
        print(f"WARN: NVD fetch {cve} failed: {e}")
        return None

    try:
        vulns = data.get("vulnerabilities", [])
        if not vulns:
            _cache[cve] = {}
            return _cache[cve]

        cve_obj = vulns[0].get("cve", {})
        metrics = cve_obj.get("metrics", {})

        # Prefer v3.1, anders v3.0
        cvss = None
        severity = ""
        for m in metrics.get("cvssMetricV31", []):
            sc, sv = _extract_cvss_v31(m)
            if sc is not None:
                cvss, severity = sc, sv
                break
        if cvss is None:
            for m in metrics.get("cvssMetricV30", []):
                sc, sv = _extract_cvss_v31(m)
                if sc is not None:
                    cvss, severity = sc, sv
                    break

        result = {}
        if cvss is not None:
            result["cvss"] = cvss
        if severity:
            result["severity"] = severity

        _cache[cve] = result
        return result
    except Exception as e:
        print(f"WARN: NVD parse {cve} failed: {e}")
        return None

def enrich_many(cves: list[str], delay_sec: float = 0.2) -> dict[str, dict]:
    """
    Batch verrijking met lichte throttling om NVD-rate limits te respecteren.
    Retourneert: { CVE -> {"cvss": float|None, "severity": "Critical|High|Medium|Low"} }
    """
    out: dict[str, dict] = {}
    for cve in cves:
        info = fetch_nvd_cve(cve)
        if info is None:
            # harde fout: sla over (geen cache)
            pass
        else:
            out[cve.upper()] = info
        time.sleep(delay_sec)
    return out
