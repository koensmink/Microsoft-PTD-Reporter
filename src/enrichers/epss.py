import csv, io, requests

EPSS_URL = "https://api.first.org/data/v1/epss?download=true"  # CSV

def load_epss_scores(timeout=60) -> dict[str, float]:
    """Map CVE -> EPSS score (float)."""
    r = requests.get(EPSS_URL, timeout=timeout)
    r.raise_for_status()
    content = r.content.decode("utf-8", errors="ignore")
    f = io.StringIO(content)
    reader = csv.DictReader(f)
    m = {}
    for row in reader:
        cve = row.get("cve", "").strip().upper()
        try:
            score = float(row.get("epss", 0.0))
        except:
            score = 0.0
        if cve:
            m[cve] = score
    return m
