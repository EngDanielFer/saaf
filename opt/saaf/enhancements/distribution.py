# =============================================================
# SAAF Pro — enhancements/distribution.py
# Envio de reportes por campania a Microsoft Teams y a correos propios.
#
# * Teams: SIN webhook ni Power Automate. Una cuenta de usuario normal inicia
#   sesion una vez en un perfil de Chromium propio y el servicio publica el
#   reporte en el chat/canal con Playwright (enhancements/teams_browser.py).
#   Cada envio se VERIFICA leyendo el mensaje en el propio chat.
# * Correo: usa el MISMO SMTP configurado en saaf.env (SAAF_SMTP_*) que ya
#   usan las alertas, pero con destinatarios propios de cada campania y
#   formato HTML (con alternativa en texto plano). No modifica alerts.py.
# =============================================================

import os
import smtplib
from email.message import EmailMessage
from urllib.parse import urlparse

from . import config as cfgmod
from . import reporting, store, teams_browser
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


SESSION_ALERT_EVERY_H = 12


def teams_ready(site_id: int) -> tuple:
    rc = cfgmod.get_site_config(site_id)["report"]
    if not (rc["teams_chat_url"] or rc["teams_chat_name"]):
        return False, "Falta el enlace o el nombre del chat/canal de Teams (Campañas → Reportes)."
    return teams_browser.playwright_ready()


def _notify_session_problem(site_id: int, res: dict):
    """Avisa por correo (como mucho cada 12 h) cuando la sesion de Teams caduco, para que no pase desapercibido."""
    if res.get("code") != teams_browser.SESSION_EXPIRED:
        return
    key = f"teams_session_alert:{site_id}"
    try:
        last = store.kv_get(key)
        if last:
            from datetime import datetime, timezone
            age = (datetime.now(timezone.utc) - datetime.fromisoformat(last)).total_seconds() / 3600
            if age < SESSION_ALERT_EVERY_H:
                return
        cfg = cfgmod.get_site_config(site_id)["report"]
        to = cfg["emails"] or [e.strip() for e in os.environ.get("SAAF_ALERT_RECIPIENTS", "").split(",") if e.strip()]
        sent = False
        for addr in to:
            ok, _ = send_email(addr, "SAAF Pro — la sesión de Teams caducó",
                               "Los reportes a Microsoft Teams no se están entregando porque la sesión de la cuenta caducó "
                               "o Microsoft pidió autenticarse de nuevo.\n\nSolución: en el servidor ejecuta\n"
                               "  venv/bin/python opt/saaf/scripts/python/teams_login.py\ne inicia sesión (con MFA) una vez.")
            sent = sent or ok
        if sent:
            from datetime import datetime, timezone
            store.kv_set(key, datetime.now(timezone.utc).isoformat())
    except Exception:
        log.warning("No se pudo avisar de la caducidad de la sesión de Teams", exc_info=True)


def _teams_result(res: dict, rc: dict) -> dict:
    return {"channel": "teams", "target": rc.get("teams_chat_name") or "chat de Teams", "ok": bool(res.get("ok")),
            "verified": bool(res.get("verified")), "code": res.get("code"), "error": res.get("error", ""),
            "marker": res.get("marker"), "proof": res.get("proof", ""), "attempts": res.get("attempts", 0)}


def test_teams(site_id: int) -> dict:
    """Envia un mensaje de prueba REAL al chat y verifica que aparece. Devuelve el resultado completo."""
    rc = cfgmod.get_site_config(site_id)["report"]
    marker = teams_browser.new_marker("SAAF-PRUEBA")
    res = teams_browser.send_message(
        rc["teams_chat_url"], rc["teams_chat_name"],
        ["✅ SAAF Pro — prueba de conexión con Teams",
         "Si ves este mensaje, los reportes de esta campaña llegarán a este chat."], marker=marker)
    _notify_session_problem(site_id, res)
    return _teams_result(res, rc)


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
        ok_t, why = teams_ready(site_id)
        if not ok_t:
            results.append({"channel": "teams", "target": cfg.get("teams_chat_name") or "chat de Teams", "ok": False,
                            "verified": False, "code": "CONFIG", "error": why})
        else:
            res = teams_browser.send_message(cfg["teams_chat_url"], cfg["teams_chat_name"], reporting.teams_lines(report))
            _notify_session_problem(site_id, res)
            results.append(_teams_result(res, cfg))
    if cfg["email_enabled"] and cfg["emails"]:
        subj, text, html = reporting.subject(report), reporting.render_text(report), reporting.render_html(report)
        for to in cfg["emails"]:
            ok, err = send_email(to, subj, text, html)
            results.append({"channel": "email", "target": to, "ok": ok, "error": err})
    for r in results:
        log.info("Reporte campaña %s -> %s %s: %s", site_id, r["channel"], r["target"] if r["channel"] == "email" else "",
                 ("ok" + (" (verificado en Teams)" if r.get("verified") else "")) if r["ok"] else r["error"])
    return results
