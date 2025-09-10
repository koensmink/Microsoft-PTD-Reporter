from __future__ import annotations
import os, base64, yaml
from pathlib import Path
from .utils.date_utils import now_in_tz, is_second_tuesday, yyyymm, yyyymmdd
from .utils.io_utils import ensure_dir, write_json, read_json, write_csv
from .msrc import (
    fetch_vulns_via_api,
    enrich_with_cvrf,
    enrich_with_nvd,
    fetch_vulns_via_rss,
)
from .enrichers.kev import load_kev_set
from .enrichers.epss import load_epss_scores
from .templating import render_email
from .mailer import send_html_mail

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "output"
TEMPLATES = ROOT / "templates"

# ---------------- Helpers ----------------

def load_config():
    with open(ROOT / "config.yaml", "r", encoding="utf-8") as f:
        return yaml.safe_load(f)

def filter_scope(rows, product_filters):
    if not product_filters:
        return rows
    pf = [p.lower() for p in product_filters]
    out = []
    for r in rows:
        prod = (r.get("product") or "").lower()
        # Items zonder product laten we door om niets te missen
        if any(p in prod for p in pf) or prod == "":
            out.append(r)
    return out

def mark_urgent(row, urgent_cfg, kev_set, epss_map):
    cvss = row.get("cvss") or 0.0
    epss = epss_map.get(row["cve"], 0.0)
    in_kev = row["cve"] in kev_set if urgent_cfg.get("include_kev", True) else False
    row["epss"] = epss
    row["kev"] = in_kev
    is_urgent = (
        (cvss and cvss >= urgent_cfg.get("min_cvss", 8.0)) or
        (epss and epss >= urgent_cfg.get("min_epss", 0.30)) or
        in_kev
    )
    row["urgent"] = bool(is_urgent)
    return row

def build_csv_rows(rows):
    fields = ["cve", "title", "product", "severity", "cvss", "epss", "kev", "published", "kb", "url", "urgent"]
    out = []
    for r in rows:
        out.append({k: r.get(k, "") for k in fields})
    return fields, out

def attach_csv_bytes(name: str, rows: list, headers: list) -> dict:
    import csv, io
    s = io.StringIO()
    w = csv.DictWriter(s, fieldnames=headers)
    w.writeheader()
    for r in rows:
        w.writerow(r)
    content_bytes = s.getvalue().encode("utf-8")
    return {
        "@odata.type": "#microsoft.graph.fileAttachment",
        "name": name,
        "contentBytes": base64.b64encode(content_bytes).decode("ascii"),
        "contentType": "text/csv",
    }

def graph_env_complete() -> bool:
    required = ["GRAPH_TENANT_ID", "GRAPH_CLIENT_ID", "GRAPH_CLIENT_SECRET", "MAIL_SENDER_UPN"]
    return all(os.environ.get(k) for k in required)

# ---- Datakwaliteit helpers ----

def _row_has_quality(r: dict) -> bool:
    # “Genoeg ingevuld” = minstens severity OF cvss aanwezig
    return bool((r.get("severity") or "").strip()) or (r.get("cvss") is not None)

def compute_completeness(rows: list[dict]) -> float:
    if not rows:
        return 0.0
    ok = sum(1 for r in rows if _row_has_quality(r))
    return round(100.0 * ok / len(rows), 1)

# ---------------- Main ----------------

def main():
    cfg = load_config()
    tzname = cfg.get("timezone", "Europe/Amsterdam")
    now = now_in_tz(tzname)
    second_tuesday = is_second_tuesday(now)

    ensure_dir(OUTPUT)
    state_path = OUTPUT / "state.json"
    state = read_json(state_path, default={})
    last_seen_date = state.get("last_seen_date")  # "YYYY-MM-DD"

    # --- 1) Data ophalen met ‘force detail’ (Patch Tuesday / OOB) ---
    dataq = cfg.get("data_quality", {})
    force_detail = bool(dataq.get("force_detail_on_patch_tuesday", True) and second_tuesday)
    detail_cap = int(dataq.get("detail_max", 1000))
    rows = fetch_vulns_via_api(force_detail=force_detail, detail_cap=detail_cap)
    rows = enrich_with_cvrf(rows)
    rows = enrich_with_nvd(rows)
    if not rows:
        rows = fetch_vulns_via_rss()

    # --- 2) Scope + urgent ---
    rows = filter_scope(rows, cfg.get("product_filters", []))
    kev_set = load_kev_set()
    epss_map = load_epss_scores()
    rows = [mark_urgent(v, cfg.get("urgent", {}), kev_set, epss_map) for v in rows]

    # --- 3) Kwaliteit ---
    completeness = compute_completeness(rows)
    min_pct = float(dataq.get("min_completeness_pct", 70.0))

    # --- 4) Publicatiebestanden ---
    month_dir = OUTPUT / yyyymm(now)
    ensure_dir(month_dir)
    csv_path = month_dir / f"msrc-{yyyymmdd(now)}.csv"
    json_path = month_dir / f"msrc-{yyyymmdd(now)}.json"
    write_json(json_path, {"generated": now.isoformat(), "rows": rows})
    fields, csv_rows = build_csv_rows(rows)
    write_csv(csv_path, csv_rows, fields)

    # --- 5) OOB detectie (na publish dates) ---
    newest = None
    for r in rows:
        p = r.get("published")
        if p:
            newest = max(newest, p) if newest else p
    is_oob = False
    if newest and last_seen_date:
        is_oob = newest > last_seen_date and not second_tuesday

    if not force_detail and is_oob and dataq.get("force_detail_on_oob", True):
        rows2 = fetch_vulns_via_api(force_detail=True, detail_cap=detail_cap)
        rows2 = enrich_with_cvrf(rows2)
        rows2 = enrich_with_nvd(rows2)
        rows2 = filter_scope(rows2, cfg.get("product_filters", []))
        rows2 = [mark_urgent(v, cfg.get("urgent", {}), kev_set, epss_map) for v in rows2]
        if compute_completeness(rows2) > completeness:
            rows = rows2
            completeness = compute_completeness(rows)

    # --- 6) Mailbeslisboom met kwaliteitsdrempel ---
    should_mail = (second_tuesday or is_oob) and (completeness >= min_pct)

    # --- 7) Render HTML ---
    urgent_items = [r for r in rows if r.get("urgent")]
    urgent_cfg = cfg.get("urgent", {})
    context = {
        "org": cfg.get("org_name", ""),
        "now": now,
        "is_patch_tuesday": second_tuesday,
        "is_oob": is_oob,
        "counts": {"total": len(rows), "urgent": len(urgent_items)},
        "urgent": urgent_items[:30],
        "all": rows[:500],
        "urgent_cfg": urgent_cfg,
        "completeness": completeness,
        "min_completeness": min_pct,
    }
    html = render_email(str(Path(TEMPLATES)), "email.html.j2", context)

    # --- 8) Stuur e-mail (alleen als secrets compleet & quality gehaald) ---
    if should_mail:
        subject_prefix = cfg.get("mail", {}).get("subject_prefix", "[Security] Patch Tuesday")
        subject = f"{subject_prefix} — {now.strftime('%Y-%m')} — {context['counts']['urgent']}/{context['counts']['total']}"
        send_html_mail(subject, html, attachments=[])
