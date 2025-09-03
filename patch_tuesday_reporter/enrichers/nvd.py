# patch_tuesday_reporter/enrichers/nvd.py
"""
NVD CVE 2.0 enrichment: haal CVSS v3.1 score + severity per CVE op.
Docs: https://services.nvd.nist.gov/rest/json/cves/2.0
"""
from __future__ import annotations
import time, requests

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Eenvoudige in-memory cache om rate-limit te ontzien
_cache: dict[str, dict] = {}

def _extract_cvss_v31(metric: dict) -> tuple[float|None, str]:
    try:
        v31 = metric.get("cvssData", {})
        score = float(v31.get("baseScore")) if v31.get("baseScore") is not None else None
        severity = (metric.get("baseSeverity") or "").capitalize()
        return score, severity
    except Exception:
        return None, ""

def fetch_nvd_cve(cve: str, timeout=20) -> dict | None:
    """
    Haal één CVE op. Retourneert dict met evt. keys: cvss, severity, products.
    """
    if cve in _cache:
        return _cache[cve]

    params = {"cveId": cve}
    try:
        r = requests.get(NVD_URL, params=params, timeout=timeout, headers={"User-Agent":"Mozilla/5.0"})
        r.raise_for_status()
        data = r.json()
    except Exception as e:
        print(f"WARN: NVD fetch {cve} failed: {e}")
        return None

    try:
        items = data.get("vulnerabilities", [])
        if not items:
            _cache[cve] = {}
            return _cache[cve]

        cve_obj = items[0].get("cve", {})
        # CVSS v3.1 zit in metrics > cvssMetricV31 (of v30), pak v31 preferent
        cvss = None
        severity = ""
        metrics = cve_obj.get("metrics", {})
        v31_list = metrics.get("cvssMetricV31") or []
        v30_list = metrics.get("cvssMetricV30") or []
        for m in v31_list:
            sc, sv = _extract_cvss_v31(m)
            if sc is not None:
                cvss, severity = sc, sv
                break
        if cvss is None:
            for m in v30_list:
                sc, sv = _extract_cvss_v31(m)
                if sc is not None:
                    cvss, severity = sc, sv
                    break

        # Simpele product-strings (optioneel)
        products = set()
        for vendor in cve_obj.get("configurations", {}).get("nodes", []):
            # Dit is vrij complex in NVD; we houden het bescheiden
            pass

        result = {"cvss": cvss, "severity": severity}
        _cache[cve] = result
        return result
    except Exception as e:
        print(f"WARN: NVD parse {cve} failed: {e}")
        return None

def enrich_many(cves: list[str], delay_sec: float = 0.2) -> dict[str, dict]:
    """
    Batch verrijking met lichte throttling.
    Retourneert map: CVE -> {"cvss": float|None, "severity": str}
    """
    out = {}
    for cve in cves:
        info = fetch_nvd_cve(cve)
        if info:
            out[cve] = info
        time.sleep(delay_sec)  # respecteer NVD rate-limit
    return out
