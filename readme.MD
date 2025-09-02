# Patch Tuesday Reporter

⚡ Automatische maandelijkse rapportage van Microsoft **Patch Tuesday** (en out-of-band updates).  
Dit project verzamelt de officiële Microsoft Security Updates, verrijkt ze met **CISA KEV** en **EPSS**, en verstuurt een nette HTML-mail (inclusief CSV-bijlage) naar jouw security- en IT-teams.

## ✨ Features

- ✅ Automatisch detectie van **2e dinsdag** (Patch Tuesday) – timezone: *Europe/Amsterdam*  
- ✅ **Out-of-Band** detectie (directe mail bij kritieke extra updates)  
- ✅ Verrijking met:
  - [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) (exploited in the wild)
  - [EPSS](https://www.first.org/epss/) (exploit prediction scoring)  
- ✅ **Urgent-filtering**: markeer updates als urgent (CVSS ≥ 8, EPSS ≥ 0.30 of KEV-hit)  
- ✅ Automatische e-mail via **Microsoft Graph API** (inclusief CSV-bijlage)  
- ✅ HTML-mail met overzicht + CSV/JSON output voor archief  
- ✅ Dagelijkse run via **GitHub Actions**, maar verstuurt alleen bij echte updates  
- ✅ Repo-artifacts voor auditing & terugkijken  

---

## 📂 Repo-structuur

```
patch-tuesday-reporter/
├─ src/
│  ├─ main.py              # orchestrator
│  ├─ msrc.py              # data from MSRC (API + RSS fallback)
│  ├─ mailer.py            # Graph mail sender
│  ├─ templating.py        # HTML rendering (Jinja2)
│  ├─ enrichers/           # KEV & EPSS
│  └─ utils/               # helpers (dates, io)
├─ templates/
│  └─ email.html.j2        # HTML mail template
├─ output/                 # generated artifacts (CSV/JSON/state)
├─ config.yaml             # config (scope, urgent thresholds, mail)
├─ requirements.txt
└─ .github/workflows/
   └─ patch-tuesday.yml    # GitHub Actions workflow
```

---

## ⚙️ Configuratie

Alle instellingen staan in **`config.yaml`**:

```yaml
org_name: "ACME"
timezone: "Europe/Amsterdam"

product_filters:   # scope (leeg = alles)
  - "Windows"
  - "Server"
  - "Exchange"
  - ".NET"

urgent:            # criteria voor "urgent"
  min_cvss: 8.0
  min_epss: 0.30
  include_kev: true

mail:
  subject_prefix: "[Security] Microsoft Patch Tuesday"
  to: ["secops@example.com", "it-ops@example.com"]
  cc: []
  bcc: []
  include_csv_attachment: true
```

---

## 🔑 Secrets (GitHub Actions)

Voeg de volgende **Secrets** toe in je repo:

| Secret | Beschrijving |
|--------|--------------|
| `GRAPH_TENANT_ID` | Entra ID tenant ID |
| `GRAPH_CLIENT_ID` | App (client) ID |
| `GRAPH_CLIENT_SECRET` | App client secret (waarde) |
| `MAIL_SENDER_UPN` | Mailadres van verzender (bijv. `security-reports@org.com`) |
| `MSRC_API_KEY` | *(optioneel)* MSRC API key; zonder deze key wordt RSS fallback gebruikt |

> ℹ️ App Registration moet **Application Permission `Mail.Send`** hebben, met admin consent.

---

## 🚀 Gebruik

### 1. Lokaal testen
```bash
git clone https://github.com/<org>/patch-tuesday-reporter.git
cd patch-tuesday-reporter

python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

export GRAPH_TENANT_ID=...
export GRAPH_CLIENT_ID=...
export GRAPH_CLIENT_SECRET=...
export MAIL_SENDER_UPN=...

python -m src.main
```

### 2. Automatisch (GitHub Actions)

De workflow draait **dagelijks om 17:30 UTC** (19:30 NL) en beslist zelf:  
- Mail verzenden op de **2e dinsdag**  
- Mail verzenden bij **Out-of-Band** updates  

Artifact `patch-tuesday-output` bevat CSV/JSON + state.

---

## 📧 Voorbeeld mail

### Screenshot (voorbeelddata)

![Voorbeeld HTML Mail](docs/example-mail.png)

<details>
<summary>Klik hier voor HTML voorbeeld</summary>

```html
<!doctype html>
<html>
<head>
  <meta charset="utf-8"/>
  <title>Patch Tuesday September 2025</title>
  <style>
    body { font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif; padding:20px; }
    .badge { display:inline-block; padding:2px 8px; border-radius:999px; background:#eee; font-size:12px; margin-right:6px; }
    table { border-collapse: collapse; width:100%; margin-top:12px; }
    th, td { border:1px solid #ddd; padding:6px; font-size:14px; }
    th { background:#f6f8fa; text-align:left; }
    .urgent { background:#fff5f5; }
  </style>
</head>
<body>
  <h1>Microsoft Security Updates — September 2025</h1>
  <p>
    <span class="badge">Patch Tuesday</span>
    <span class="badge">ACME</span>
  </p>
  <p>
    Totaal: <b>87</b> updates — Urgent: <b>3</b>
  </p>

  <h2>Urgent Updates</h2>
  <table>
    <thead><tr>
      <th>CVE</th><th>Titel</th><th>Product</th><th>CVSS</th><th>EPSS</th><th>KEV</th><th>Link</th>
    </tr></thead>
    <tbody>
      <tr class="urgent">
        <td>CVE-2025-1234</td><td>Remote Code Execution in Windows</td><td>Windows Server 2022</td><td>9.8</td><td>0.42</td><td>Yes</td>
        <td><a href="#">Update Guide</a></td>
      </tr>
      <tr class="urgent">
        <td>CVE-2025-2345</td><td>Elevation of Privilege in Exchange</td><td>Exchange Server 2019</td><td>8.5</td><td>0.15</td><td>No</td>
        <td><a href="#">Update Guide</a></td>
      </tr>
      <tr class="urgent">
        <td>CVE-2025-3456</td><td>Information Disclosure</td><td>.NET Framework</td><td>7.8</td><td>0.31</td><td>No</td>
        <td><a href="#">Update Guide</a></td>
      </tr>
    </tbody>
  </table>

  <h2>Volledige lijst (subset)</h2>
  <table>
    <thead><tr>
      <th>CVE</th><th>Titel</th><th>Product</th><th>Severity</th><th>CVSS</th><th>EPSS</th><th>KB</th><th>Datum</th><th>Link</th>
    </tr></thead>
    <tbody>
      <tr>
        <td>CVE-2025-1111</td><td>Security Feature Bypass</td><td>Windows 10</td><td>Important</td><td>6.5</td><td>0.05</td><td>KB5031234</td><td>2025-09-09</td><td><a href="#">Update Guide</a></td>
      </tr>
      <tr>
        <td>CVE-2025-2222</td><td>Remote Code Execution</td><td>SharePoint</td><td>Critical</td><td>8.2</td><td>0.27</td><td>KB5035678</td><td>2025-09-09</td><td><a href="#">Update Guide</a></td>
      </tr>
    </tbody>
  </table>
</body>
</html>
```

</details>

---

## 🛡️ Governance & audit

- **Artifacts**: alle output wordt opgeslagen in `output/` en als GitHub artifact.  
- **State**: `output/state.json` houdt bij wat de laatste gepubliceerde update-datum was → voorkomt dubbele mails.  
- **Logging**: elke run logt naar Actions en geeft aantal total/urgent.  

---

## 🔮 Toekomstige uitbreidingen

- 📊 **Teams-notificatie** naast e-mail  
- 🌐 Publicatie naar **GitHub Pages** (history view)  
- ✅ Unit tests voor datumlogica  
- 🔄 Retry/backoff bij MSRC/EPSS timeouts  

---

## 👥 Credits

- **MSRC Security Update Guide** — officiële Microsoft bron  
- **CISA KEV Catalog** — exploited in the wild  
- **FIRST EPSS** — exploit prediction scoring  

---

## 📜 Licentie

MIT — vrij te gebruiken en aan te passen.
