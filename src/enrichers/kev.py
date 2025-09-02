import requests
from datetime import datetime

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

def load_kev_set(timeout=30) -> set[str]:
    """Retourneert een set met CVE-id's die in KEV staan."""
    r = requests.get(KEV_URL, timeout=timeout)
    r.raise_for_status()
    data = r.json()
    cves = set()
    for item in data.get("vulnerabilities", []):
        cve = item.get("cveID")
        if cve:
            cves.add(cve.strip().upper())
    return cves
