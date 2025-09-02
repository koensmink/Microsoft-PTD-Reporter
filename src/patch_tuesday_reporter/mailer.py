import os, requests

GRAPH_TOKEN_URL = "https://login.microsoftonline.com/{tenant}/oauth2/v2.0/token"
SENDMAIL_URL    = "https://graph.microsoft.com/v1.0/users/{sender}/sendMail"

def get_graph_token(tenant_id: str, client_id: str, client_secret: str, scope="https://graph.microsoft.com/.default") -> str:
    data = {
        "client_id": client_id,
        "client_secret": client_secret,
        "scope": scope,
        "grant_type": "client_credentials",
    }
    url = GRAPH_TOKEN_URL.format(tenant=tenant_id)
    r = requests.post(url, data=data, timeout=60)
    r.raise_for_status()
    return r.json()["access_token"]

def send_html_mail(
    tenant_id: str,
    client_id: str,
    client_secret: str,
    sender_upn: str,
    subject: str,
    html_body: str,
    to: list[str],
    cc: list[str] | None = None,
    bcc: list[str] | None = None,
    attachments: list[dict] | None = None,
):
    token = get_graph_token(tenant_id, client_id, client_secret)
    headers = {"Authorization": f"Bearer {token}", "Content-Type": "application/json"}

    def addr(a: list[str] | None):
        return [{"emailAddress": {"address": x}} for x in (a or [])]

    payload = {
        "message": {
            "subject": subject,
            "body": {"contentType": "HTML", "content": html_body},
            "toRecipients": addr(to),
            "ccRecipients": addr(cc),
            "bccRecipients": addr(bcc),
        },
        "saveToSentItems": "true",
    }
    if attachments:
        payload["message"]["attachments"] = attachments

    url = SENDMAIL_URL.format(sender=sender_upn)
    r = requests.post(url, headers=headers, json=payload, timeout=60)
    r.raise_for_status()
