# =============================================================
# SAAF Pro — enhancements/distribution.py
# Envio de reportes por campania a Microsoft Teams y a correos propios.
#
# * Teams: Webhook entrante / flujo de Power Automate ("Cuando se recibe una
#   solicitud de webhook de Teams") con una tarjeta adaptable. La URL del
#   webhook es un secreto (secrets_store), nunca se muestra ni se registra.
# * Correo: usa el MISMO SMTP configurado en saaf.env (SAAF_SMTP_*) que ya
#   usan las alertas, pero con destinatarios propios de cada campania y
#   formato HTML (con alternativa en texto plano). No modifica alerts.py.
# =============================================================

import os
import smtplib
from email.message import EmailMessage
from urllib.parse import urlparse

import requests

from . import config as cfgmod
from . import reporting
from .log import get_logger

log = get_logger()

NETWORK_TIMEOUT_S = float(os.environ.get("SAAF_NETWORK_TIMEOUT", "30"))


def _smtp_cfg() -> dict:
    return {
        "enabled": os.environ.get("SAAF_EMAIL_ENABLED", "0").strip() == "1",
        "server": os.environ.get("SAAF_SMTP_SERVER", "").strip(),
        "port": int(os.environ.get("SAAF_SMTP_PORT", "587") or 587),
        "tls": os.environ.get("SAAF_SMTP_TLS", "1").strip() == "1",
        "from": os.environ.get("SAAF_SMTP_FROM", "").strip().strip("\r"),
        "user": os.environ.get("SAAF_SMTP_USER", "").strip().strip("\r"),
        "password": os.environ.get("SAAF_SMTP_PASSWORD", "").strip("\r\n"),
    }


def email_ready() -> tuple:
    c = _smtp_cfg()
    if not c["enabled"]:
        return False, "El correo está deshabilitado (SAAF_EMAIL_ENABLED=1 en saaf.env)."
    if not c["server"] or not c["user"] or not c["password"]:
        return False, "Faltan datos SMTP en saaf.env (servidor, usuario o contraseña)."
    return True, ""


def send_email(to: str, subject: str, text: str, html: str = None) -> tuple:
    """(ok, error). Nunca lanza."""
    ok, why = email_ready()
    if not ok:
        return False, why
    c = _smtp_cfg()
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = c["from"] or c["user"]
    msg["To"] = to
    msg.set_content(text)
    if html:
        msg.add_alternative(html, subtype="html")
    try:
        with smtplib.SMTP(c["server"], c["port"], timeout=NETWORK_TIMEOUT_S) as s:
            if c["tls"]:
                s.starttls()
            s.login(c["user"], c["password"])
            s.send_message(msg)
        return True, ""
    except Exception as e:  # noqa
        log.warning("Correo a %s falló: %s", to, e.__class__.__name__)
        return False, f"{e.__class__.__name__}: {str(e)[:120]}"


def valid_webhook(url: str) -> bool:
    try:
        u = urlparse(url or "")
        return u.scheme == "https" and bool(u.netloc)
    except Exception:
        return False


def send_teams(webhook_url: str, payload: dict) -> tuple:
    """(ok, error). Nunca lanza ni registra la URL."""
    if not valid_webhook(webhook_url):
        return False, "La URL del webhook de Teams debe empezar con https://"
    try:
        r = requests.post(webhook_url, json=payload, timeout=NETWORK_TIMEOUT_S)
        if r.status_code in (200, 201, 202):
            return True, ""
        return False, f"Teams respondió HTTP {r.status_code}: {r.text[:120]}"
    except requests.RequestException as e:
        return False, f"{e.__class__.__name__}"


def test_teams(site_id: int) -> tuple:
    url = cfgmod.get_teams_webhook(site_id)
    if not url:
        return False, "No hay webhook de Teams guardado para esta campaña."
    payload = {
        "type": "message",
        "attachments": [{
            "contentType": "application/vnd.microsoft.card.adaptive", "contentUrl": None,
            "content": {"$schema": "http://adaptivecards.io/schemas/adaptive-card.json", "type": "AdaptiveCard",
                        "version": "1.4",
                        "body": [{"type": "TextBlock", "text": "✅ SAAF Pro — prueba de conexión con Teams",
                                  "weight": "Bolder", "wrap": True},
                                 {"type": "TextBlock", "text": "Si ves este mensaje, los reportes de esta campaña llegarán a este canal.",
                                  "wrap": True}]},
        }],
    }
    return send_teams(url, payload)


def dispatch(site_id: int, report: dict, force: bool = False) -> list:
    """
    Envia el reporte segun la configuracion de la campania. Devuelve una lista
    de {'channel','target','ok','error'}. Con force=True ignora 'solo si hay
    alertas importantes' (envio manual de prueba).
    """
    cfg = cfgmod.get_site_config(site_id)["report"]
    results = []
    if not (cfg["teams_enabled"] or (cfg["email_enabled"] and cfg["emails"])):
        return results
    if cfg["only_if_important"] and not force and not report["facts"].get("important"):
        return [{"channel": "-", "target": "-", "ok": True, "error": "omitido: sin alertas importantes ni pendientes"}]

    if cfg["teams_enabled"]:
        url = cfgmod.get_teams_webhook(site_id)
        if url:
            ok, err = send_teams(url, reporting.teams_payload(report))
            results.append({"channel": "teams", "target": "webhook", "ok": ok, "error": err})
        else:
            results.append({"channel": "teams", "target": "webhook", "ok": False, "error": "falta la URL del webhook"})
    if cfg["email_enabled"] and cfg["emails"]:
        subj, text, html = reporting.subject(report), reporting.render_text(report), reporting.render_html(report)
        for to in cfg["emails"]:
            ok, err = send_email(to, subj, text, html)
            results.append({"channel": "email", "target": to, "ok": ok, "error": err})
    for r in results:
        log.info("Reporte campaña %s -> %s %s: %s", site_id, r["channel"], r["target"] if r["channel"] == "email" else "",
                 "ok" if r["ok"] else r["error"])
    return results
