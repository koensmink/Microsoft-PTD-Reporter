import os, base64, yaml
from pathlib import Path
from datetime import datetime
from dateutil import tz
from src.utils.date_utils import now_in_tz, is_second_tuesday, yyyymm, yyyymmdd
from src.utils.io_utils import ensure_dir, write_json, read_json, write_csv
from src.msrc import fetch_vulnerabilities
from src.enrichers.kev import load_kev_set
from src.enrichers.epss import load_epss_scores
from src.templating import render_email
from src.mailer import send_html_mail

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / "output"
TEMPLATES = ROOT / "templates"

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
        if any(p in prod for p in pf) or prod == "":
            out.append(r)
    return out

def mark_urgent(row, urgent_cfg, kev_set, epss_map):
    cvss = row.get("cvss") or 0.0
    epss = epss_map.get(row["cve"], 0.0)
    in_kev = row["cve"] in kev_set if urgent_cfg.get("include_kev", True) else False
    row["epss"] = epss
    row["kev"] = in_kev
    is_urgent = (cvss and cvss >= urgent_cfg.get("min_cvss", 8.0)) or \
                (epss and epss >= urgent_cfg.get("min_epss", 0.3)) or \
                in_kev
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

def main():
    cfg = load_config()
    tzname = cfg.get("timezone", "Europe/Amsterdam")
    now = now_in_tz(tzname)
    second_tuesday = is_second_tuesday(now)

    ensure_dir(OUTPUT)
    state_path = OUTPUT / "state.json"
    state = read_json(state_path, default={})
    last_seen_date = state.get("last_seen_date")  # "YYYY-MM-DD"

    # 1) Data ophalen
    vulns = fetch_vulnerabilities()
    # 2) Scope filteren
    vulns = filter_scope(vulns, cfg.get("product_filters", []))
    # 3) Verrijken
    kev_set = load_kev_set()
    epss_map = load_epss_scores()
    rows = [mark_urgent(v, cfg.get("urgent", {}), kev_set, epss_map) for v in vulns]

    # 4) Publicatie-paden
    month_dir = OUTPUT / yyyymm(now)
    ensure_dir(month_dir)
    csv_path = month_dir / f"msrc-{yyyymmdd(now)}.csv"
    json_path = month_dir / f"msrc-{yyyymmdd(now)}.json"
    write_json(json_path, {"generated": now.isoformat(), "rows": rows})
    fields, csv_rows = build_csv_rows(rows)
    write_csv(csv_path, csv_rows, fields)

    # 5) OOB-detectie
    # Vind nieuwste published in set
    newest = None
    for r in rows:
        p = r.get("published")
        if p:
            newest = max(newest, p) if newest else p
    is_oob = False
    if newest and last_seen_date:
        # OOB als er iets nieuws is op een andere dag dan een 2e dinsdag
        # (we sturen sowieso bij nieuwe dag; de mailtekst vermeldt OOB als het niet op 2e dinsdag is)
        is_oob = newest > last_seen_date and not second_tuesday

    # 6) Bepaal of we vandaag mailen
    should_mail = second_tuesday or is_oob

    # 7) Render HTML
    urgent_items = [r for r in rows if r.get("urgent")]
    context = {
        "org": cfg.get("org_name", ""),
        "now": now,
        "is_patch_tuesday": second_tuesday,
        "is_oob": is_oob,
        "counts": {
            "total": len(rows),
            "urgent": len(urgent_items),
        },
        "urgent": urgent_items[:30],  # kort in mail, rest in CSV
        "all": rows[:500],            # safeguard
    }
    html = render_email(str(Path(TEMPLATES)), "email.html.j2", context)

    # 8) Stuur e-mail (alleen op tweede dinsdag of OOB)
    if should_mail:
        subject_prefix = cfg.get("mail", {}).get("subject_prefix", "[Security] Patch Tuesday")
        subject = f"{subject_prefix} — {now.strftime('%Y-%m')} — {context['counts']['urgent']}/{context['counts']['total']} ({cfg.get('org_name','')})"

        attachments = []
        if cfg.get("mail", {}).get("include_csv_attachment", True):
            attachments.append(attach_csv_bytes(csv_path.name, csv_rows, fields))

        send_html_mail(
            tenant_id=os.environ["GRAPH_TENANT_ID"],
            client_id=os.environ["GRAPH_CLIENT_ID"],
            client_secret=os.environ["GRAPH_CLIENT_SECRET"],
            sender_upn=os.environ["MAIL_SENDER_UPN"],
            subject=subject,
            html_body=html,
            to=cfg.get("mail", {}).get("to", []),
            cc=cfg.get("mail", {}).get("cc", []),
            bcc=cfg.get("mail", {}).get("bcc", []),
            attachments=attachments
        )

    # 9) Update state
    if newest and (not last_seen_date or newest > last_seen_date):
        state["last_seen_date"] = newest
        write_json(state_path, state)

    # 10) Console output voor Actions logs
    print(f"PatchTuesday={second_tuesday}, OOB={is_oob}, Total={len(rows)}, Urgent={len(urgent_items)}")
    print(f"CSV={csv_path}")

if __name__ == "__main__":
    main()
