#!/home/admin_ubuntu/Desktop/proyecto_saaf/opt/saaf/venv/bin/python
# =============================================================
# SAAF Pro — alerts.py  (extendido Fase 4)
# Envio de emails de alerta con detalle de amenazas.
# Extiende el alerts.py original con:
#   - send_threat_alert() — email con tabla de amenazas
#   - send_site_down_alert() — email cuando un sitio cae
#   - send_daily_report() — resumen diario del ciclo
#   - should_send_alert() — decide si enviar segun config
# Ruta: /home/admin_ubuntu/Desktop/proyecto_saaf/opt/saaf/scripts/python/alerts.py
# =============================================================

import os
import re
import smtplib
import logging
from datetime import datetime, timezone
from email.message import EmailMessage
from collections import Counter

try:
    from database import COLOMBIA_TZ
except ImportError:
    COLOMBIA_TZ = None


def _now_str(fmt: str = "%Y-%m-%d %H:%M") -> str:
    """Hora actual formateada en hora de Colombia (con fallback a UTC si
    database.py no esta disponible en el path)."""
    now_utc = datetime.now(timezone.utc)
    if COLOMBIA_TZ is not None:
        return now_utc.astimezone(COLOMBIA_TZ).strftime(fmt) + " (hora de Colombia)"
    return now_utc.strftime(fmt) + " UTC"

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

# Timeout (segundos) de SMTP y Twilio. Sin el, una conexion colgada bloqueaba el
# hilo de la auditoria indefinidamente (quedaba RUNNING sin ninguna señal de error).
NETWORK_TIMEOUT_S = float(os.environ.get("SAAF_NETWORK_TIMEOUT", "30"))

# Regex RFC 5321 para validar emails
_EMAIL_RE = re.compile(
    r"^(?!.*\.\.)(?!^\.)(?!.*\.$)[a-zA-Z0-9!#$%&'*+/=?^_`{|}~\-]{1,64}"
    r"(?:\.[a-zA-Z0-9!#$%&'*+/=?^_`{|}~\-]{1,64})*"
    r"@[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*"
    r"\.[a-zA-Z]{2,}$"
)

# Regex E.164 para validar números de teléfono internacionales
_PHONE_RE = re.compile(r"^\+[1-9]\d{7,14}$")

# Severidades: fuente unica en severity.py (CRITICAL/HIGH/MEDIUM/LOW/INFO).
# normalize_severity() tambien entiende los nombres antiguos (CRITICO/ALTO...).
try:
    from severity import SEVERITY_ICON, SEVERITY_ORDER, normalize_severity
except ImportError:  # ejecucion aislada sin opt/saaf en el path
    SEVERITY_ICON = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢", "INFO": "🔵"}
    SEVERITY_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
    _LEGACY = {"CRITICO": "CRITICAL", "ALTO": "HIGH", "MEDIO": "MEDIUM", "BAJO": "LOW"}

    def normalize_severity(value):
        v = str(value or "").strip().upper()
        return v if v in SEVERITY_ORDER else _LEGACY.get(v)

THREAT_TYPE_LABEL = {
    "casino_pharma_adult": "URL spam (casino/pharma/adult)",
    "hidden_spam_link": "Link spam oculto",
    "external_script": "Script externo desconocido",
    "hidden_iframe": "iFrame oculto",
    "obfuscated_js": "JavaScript ofuscado",
    "claude_anomaly": "Anomalia detectada por Claude API",
}



def _sev(threat):
    """Severidad canonica de un Threat (o None)."""
    return normalize_severity(getattr(threat, "severity", None))


def _max_sev(threats):
    """Severidad maxima (canonica) de una lista de amenazas."""
    return max((_sev(t) or "INFO" for t in threats), key=lambda v: SEVERITY_ORDER.get(v, 0))


# =============================================================
# Configuracion
# =============================================================
def get_config():
    return {
        "email_enabled": os.environ.get("SAAF_EMAIL_ENABLED", "0"),
        "smtp_server": os.environ.get("SAAF_SMTP_SERVER", ""),
        "smtp_port": os.environ.get("SAAF_SMTP_PORT", "587"),
        "smtp_tls": os.environ.get("SAAF_SMTP_TLS", "1"),
        "smtp_from": os.environ.get("SAAF_SMTP_FROM", ""),
        "smtp_user": os.environ.get("SAAF_SMTP_USER", ""),
        "smtp_password": os.environ.get("SAAF_SMTP_PASSWORD", ""),
        "alert_on_critical": os.environ.get("SAAF_ALERT_CRITICAL", "1"),
        "alert_on_high": os.environ.get("SAAF_ALERT_HIGH", "1"),
        "alert_on_down": os.environ.get("SAAF_ALERT_DOWN", "1"),
        "sms_enabled": os.environ.get("SAAF_SMS_ENABLED", "0"),
        "twilio_sid": os.environ.get("SAAF_TWILIO_ACCOUNT_SID", ""),
        "twilio_token": os.environ.get("SAAF_TWILIO_AUTH_TOKEN", ""),
        "twilio_from": os.environ.get("SAAF_TWILIO_FROM_NUMBER", ""),
        "sms_critical_only": os.environ.get("SAAF_SMS_CRITICAL_ONLY", "1"),
    }


def get_email_recipients() -> list:
    """
    Lee destinatarios desde variable de entorno o desde la BD.
    SAAF_ALERT_RECIPIENTS puede ser una lista separada por comas.
    """
    env = os.environ.get("SAAF_ALERT_RECIPIENTS", "")
    if env:
        return [e.strip() for e in env.split(",") if e.strip()]

    # Sin variable de entorno configurada: no hay destinatarios
    # FIX: load_config() no existe en config_loader.py — fallback eliminado
    return []


def get_sms_recipients() -> list:
    """
    Lee números de teléfono desde SAAF_SMS_RECIPIENTS (separados por coma).
    Valida formato E.164 (+XXXXXXXXXXX). Ignora los inválidos con un warning.
    """
    env = os.environ.get("SAAF_SMS_RECIPIENTS", "")
    if not env:
        return []
    valid = []
    for raw in env.split(","):
        number = raw.strip()
        if _PHONE_RE.match(number):
            valid.append(number)
        else:
            logger.warning(
                "Número de teléfono inválido ignorado: %r (formato requerido: +XXXXXXXXXXX)",
                number,
            )
    return valid


def should_send_alert(severity: str) -> bool:
    """Decide si enviar alerta segun severidad y configuracion."""
    cfg = get_config()
    if cfg.get("email_enabled") != "1":
        return False
    severity = normalize_severity(severity)
    if severity == "CRITICAL" and cfg.get("alert_on_critical") == "1":
        return True
    if severity == "HIGH" and cfg.get("alert_on_high") == "1":
        return True
    return False


def should_send_sms(severity: str) -> bool:
    """Decide si enviar SMS según severidad y configuración."""
    cfg = get_config()
    if cfg.get("sms_enabled") != "1":
        return False
    severity = normalize_severity(severity)
    if cfg.get("sms_critical_only") == "1":
        return severity == "CRITICAL"
    return severity in ("CRITICAL", "HIGH")


# =============================================================
# SMS — Twilio
# =============================================================


def send_sms(to: str, body: str) -> bool:
    """
    Envía un SMS via Twilio a un número en formato E.164.

    Args:
        to:   Número destino en formato E.164 (ej: +573001234567)
        body: Texto del mensaje (máximo 160 caracteres recomendado)

    Returns:
        True si el SMS se envió correctamente, False si falló.

    Variables de entorno requeridas:
        SAAF_TWILIO_ACCOUNT_SID   — Account SID (empieza con AC...)
        SAAF_TWILIO_AUTH_TOKEN    — Auth Token
        SAAF_TWILIO_FROM_NUMBER   — Número Twilio en E.164 (+1XXXXXXXXXX)
        SAAF_SMS_ENABLED          — "1" para activar
    """
    cfg = get_config()

    if cfg.get("sms_enabled") != "1":
        logger.debug("SMS deshabilitado (SAAF_SMS_ENABLED != 1)")
        return False

    # Validar número destino
    if not _PHONE_RE.match(to):
        logger.error("Número de teléfono inválido: %r", to)
        return False

    # Verificar credenciales
    sid = cfg.get("twilio_sid", "")
    token = cfg.get("twilio_token", "")
    from_ = cfg.get("twilio_from", "")

    if not sid or not sid.startswith("AC"):
        logger.error(
            "SAAF_TWILIO_ACCOUNT_SID no configurado o inválido (debe empezar con 'AC')"
        )
        return False
    if not token:
        logger.error("SAAF_TWILIO_AUTH_TOKEN no configurado")
        return False
    if not from_ or not _PHONE_RE.match(from_):
        logger.error("SAAF_TWILIO_FROM_NUMBER no configurado o inválido: %r", from_)
        return False

    # Truncar a 1600 chars (límite Twilio, aunque se recomienda < 160 por SMS)
    body_truncated = body[:1600]

    try:
        from twilio.rest import Client

        from twilio.http.http_client import TwilioHttpClient

        client = Client(sid, token, http_client=TwilioHttpClient(timeout=NETWORK_TIMEOUT_S))
        message = client.messages.create(
            body=body_truncated,
            from_=from_,
            to=to,
        )
        logger.info(
            "SMS enviado a %s: SID=%s status=%s", to, message.sid, message.status
        )
        return True

    except ImportError:
        logger.error("twilio no instalado. Instalar con: pip install twilio")
        return False

    except Exception as e:
        # Twilio lanza TwilioRestException con código de error útil
        error_code = getattr(e, "code", "N/A")
        logger.error(
            "Error enviando SMS a %s (código Twilio %s): %s", to, error_code, e
        )
        return False


def send_sms_to_all(body: str) -> int:
    """
    Envía un SMS a todos los números configurados en SAAF_SMS_RECIPIENTS.

    Returns:
        Número de SMS enviados exitosamente.
    """
    recipients = get_sms_recipients()
    if not recipients:
        logger.warning(
            "No hay números SMS configurados. "
            "Configurar: export SAAF_SMS_RECIPIENTS=+57300XXXXXXX,+1212XXXXXXX"
        )
        return 0
    sent = sum(1 for r in recipients if send_sms(r, body))
    return sent


# =============================================================
# Construcción de mensajes SMS
# =============================================================


def _build_sms_threat_body(site: dict, threats: list) -> str:
    """
    Construye el mensaje SMS de alerta de amenazas.
    Formato compacto (spec sección 6.2), máximo ~320 chars (2 SMS).

    Ejemplo de salida:
        🚨 ALERTA SAAF — Boxmark Digital
        Severidad: CRITICAL
        Amenazas: 3 nuevas
        - Link spam oculto (gist.github.com)
        - iFrame oculto (malware.com)
        Ver dashboard: http://10.0.0.117:8501
    """
    site_name = site.get("name", site.get("url", "Sitio desconocido"))
    now = datetime.now(timezone.utc).strftime("%d/%m/%Y %H:%M UTC")

    # Severidad máxima
    max_sev = _max_sev(threats)
    icon = SEVERITY_ICON.get(max_sev, "⚠️")

    lines = [
        f"{icon} ALERTA SAAF — {site_name}",
        f"Severidad: {max_sev}",
        f"Amenazas nuevas: {len(threats)}",
        f"Detectado: {now}",
    ]

    # Hasta 3 amenazas con detalle breve
    for t in threats[:3]:
        label = THREAT_TYPE_LABEL.get(
            getattr(t, "threat_type", ""), getattr(t, "threat_type", "")
        )
        url = getattr(t, "url_found", "") or ""
        # Acortar URL para que quepa en SMS
        url_short = url[:60] + "..." if len(url) > 60 else url
        lines.append(f"• {label}")
        if url_short:
            lines.append(f"  {url_short}")

    if len(threats) > 3:
        lines.append(f"... y {len(threats) - 3} más")

    dashboard_url = os.environ.get("SAAF_DASHBOARD_URL", "http://10.0.0.117:8501")
    lines.append(f"Dashboard: {dashboard_url}")

    return "\n".join(lines)


def _build_sms_down_body(site: dict, error_msg: str = None) -> str:
    """Construye mensaje SMS de sitio caído."""
    site_name = site.get("name", site.get("url", "Sitio desconocido"))
    site_url = site.get("url", "")
    now = datetime.now(timezone.utc).strftime("%d/%m/%Y %H:%M UTC")

    lines = [
        f"🔴 SITIO CAÍDO — {site_name}",
        f"URL: {site_url}",
        f"Detectado: {now}",
    ]
    if error_msg:
        lines.append(f"Error: {error_msg[:80]}")
    dashboard_url = os.environ.get("SAAF_DASHBOARD_URL", "http://10.0.0.117:8501")
    lines.append(f"Dashboard: {dashboard_url}")
    return "\n".join(lines)


# =============================================================
# Envio base
# =============================================================


def send_email(to: str, subject: str, body: str) -> bool:
    """
    Envia un email de texto plano.
    Retorna True si se envio correctamente, False si no.
    """
    if not isinstance(to, str) or not _EMAIL_RE.match(to.strip()):
        logger.error("Dirección de email inválida: %r", to)
        return False
    to = to.strip()

    cfg = get_config()
    if cfg.get("email_enabled") != "1":
        logger.warning("Email deshabilitado. Configurar SAAF_EMAIL_ENABLED=1")
        return False

    smtp_server = cfg.get("smtp_server", "")
    if not smtp_server:
        logger.error("SMTP no configurado. Configurar SAAF_SMTP_SERVER")
        return False

    if not cfg.get("smtp_user") or not cfg.get("smtp_password"):
        logger.error("Credenciales SMTP faltantes.")
        return False

    msg = EmailMessage()
    msg.set_content(body)
    msg["Subject"] = subject
    msg["From"] = cfg.get("smtp_from", "")
    msg["To"] = to

    try:
        port = int(cfg.get("smtp_port", 587))
        with smtplib.SMTP(smtp_server, port, timeout=NETWORK_TIMEOUT_S) as s:
            if cfg.get("smtp_tls") == "1":
                s.starttls()
            s.login(cfg.get("smtp_user"), cfg.get("smtp_password"))
            s.send_message(msg)
        logger.info("Email enviado a %s: %s", to, subject)
        return True
    except Exception as e:
        logger.error("Error enviando email a %s: %s", to, e)
        return False


def send_to_all(subject: str, body: str) -> int:
    """
    Envia el email a todos los destinatarios configurados.
    Retorna el numero de envios exitosos.
    """
    recipients = get_email_recipients()
    if not recipients:
        logger.warning("No hay destinatarios configurados para alertas.")
        return 0
    sent = sum(1 for r in recipients if send_email(r, subject, body))
    return sent


# =============================================================
# Cuerpo de emails especializados
# =============================================================


def _build_threat_body(site: dict, threats: list, cycle_started_at: str = None) -> str:
    """
    Construye el cuerpo del email de alerta de amenazas.
    Incluye tabla con tipo, severidad, URL y snippet de codigo.
    """
    now = _now_str("%Y-%m-%d %H:%M")
    lines = []

    lines.append("=" * 60)
    lines.append("SAAF Pro — Alerta de seguridad")
    lines.append("=" * 60)
    lines.append(f"Sitio    : {site.get('name', '')} ({site.get('url', '')})")
    lines.append(f"Nicho    : {site.get('niche', 'general')}")
    lines.append(f"Fecha    : {now}")
    lines.append(f"Amenazas : {len(threats)} nueva(s) detectada(s)")
    lines.append("")

    # Contar por severidad
    sev_count = Counter(_sev(t) or "?" for t in threats)
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        if sev_count.get(sev, 0) > 0:
            icon = SEVERITY_ICON.get(sev, "")
            lines.append(f"  {icon} {sev}: {sev_count[sev]}")
    lines.append("")
    lines.append("-" * 60)
    lines.append("DETALLE DE AMENAZAS")
    lines.append("-" * 60)

    for i, threat in enumerate(threats, 1):
        sev = _sev(threat) or "?"
        icon = SEVERITY_ICON.get(sev, "")
        label = THREAT_TYPE_LABEL.get(
            getattr(threat, "threat_type", ""), getattr(threat, "threat_type", "")
        )
        lines.append(f"\n[{i}] {icon} {sev} — {label}")
        lines.append(f"    Pagina  : {getattr(threat, 'url_found', None) or 'N/A'}")
        resource = getattr(threat, "resource_url", None)
        if resource:
            lines.append(f"    Recurso : {resource}")
        sigs = [getattr(s, "label", None) or (s.get("label") if isinstance(s, dict) else "")
                for s in (getattr(threat, "signals", None) or [])]
        sigs = [x for x in sigs if x]
        if sigs:
            lines.append("    Señales : " + "; ".join(sigs[:6]))
        lines.append(f"    Detalle : {getattr(threat, 'description', '')}")
        snippet = getattr(threat, "code_snippet", "") or ""
        if snippet:
            lines.append(f"    Codigo  : {snippet[:200].replace(chr(10), ' ')}")

    lines.append("")
    lines.append("-" * 60)
    lines.append("Acciones recomendadas:")
    lines.append("  1. Revisar el fragmento de codigo reportado")
    lines.append("  2. Verificar si el sitio fue comprometido")
    lines.append("  3. Marcar como resuelto en el dashboard una vez limpiado")
    dashboard_url = os.environ.get("SAAF_DASHBOARD_URL", "http://10.0.0.117:8501")
    lines.append(f"  4. Dashboard: {dashboard_url}")
    lines.append("-" * 60)
    lines.append("SAAF Pro — Security Audit & Alert Framework")

    return "\n".join(lines)


def _build_down_body(site: dict, error_msg: str = None) -> str:
    """Construye el cuerpo del email de sitio caido."""
    now = _now_str("%Y-%m-%d %H:%M")
    lines = []
    lines.append("=" * 60)
    lines.append("SAAF Pro — Alerta: Sitio CAIDO")
    lines.append("=" * 60)
    lines.append(f"Sitio  : {site.get('name', '')} ({site.get('url', '')})")
    lines.append(f"Estado : CAIDO")
    lines.append(f"Fecha  : {now}")
    if error_msg:
        lines.append(f"Error  : {error_msg}")
    lines.append("")
    lines.append("El sitio no responde a las verificaciones de uptime.")
    lines.append("Verificar manualmente el servidor y el hosting.")
    lines.append("-" * 60)
    lines.append("SAAF Pro — Security Audit & Alert Framework")
    return "\n".join(lines)


def _build_daily_report_body(summary: dict, site_results: list) -> str:
    """
    Construye el cuerpo del reporte diario consolidado.
    summary: dict con totales del ciclo
    site_results: lista de dicts con resultado por sitio
    """
    now = _now_str("%Y-%m-%d %H:%M")
    lines = []
    lines.append("=" * 60)
    lines.append("SAAF Pro — Reporte Diario")
    lines.append("=" * 60)
    lines.append(f"Fecha         : {now}")
    lines.append(f"Sitios totales: {summary.get('sites_total', 0)}")
    lines.append(f"Sin problemas : {summary.get('sites_ok', 0)}")
    lines.append(f"Con problemas : {summary.get('sites_issues', 0)}")
    lines.append(f"Caidos        : {summary.get('sites_down', 0)}")
    lines.append(f"Con errores   : {summary.get('sites_error', 0)}")
    lines.append(f"Duracion      : {summary.get('duration_sec', 0):.0f} segundos")
    lines.append("")
    lines.append("-" * 60)
    lines.append("ESTADO POR SITIO")
    lines.append("-" * 60)

    for r in site_results:
        site = r.get("site", {})
        status = r.get("status", "unknown")
        sev_max = r.get("severity_max")
        threats = r.get("threats", [])
        is_up = r.get("is_up", True)

        st = str(status).upper()
        if is_up is False:
            icon = "🔴"
        elif st in ("FAILED", "ERROR"):
            icon = "❌"
        elif st == "CANCELLED":
            icon = "⛔"
        elif r.get("has_issues") or st == "ISSUES" or st == "COMPLETED_WITH_WARNINGS":
            icon = "⚠️"
        else:
            icon = "✅"
        sev_max = normalize_severity(sev_max) if sev_max else None
        sev_str = f" [{sev_max}]" if sev_max else ""
        lines.append(f"\n{icon} {site.get('name', '')} — {site.get('url', '')}")
        lines.append(f"   Estado : {st}{sev_str}")
        if r.get("error"):
            lines.append(f"   Motivo : {r['error']}")
        if r.get("warnings"):
            for w in str(r["warnings"]).splitlines()[:3]:
                lines.append(f"   Aviso  : {w}")
        if threats:
            lines.append(f"   Amenazas nuevas: {len(threats)}")
            for t in threats[:3]:  # Mostrar max 3 en el reporte
                t_sev = _sev(t) or ""
                t_icon = SEVERITY_ICON.get(t_sev, "")
                t_lab = THREAT_TYPE_LABEL.get(
                    getattr(t, "threat_type", ""), getattr(t, "threat_type", "")
                )
                lines.append(f"     {t_icon} {t_sev} — {t_lab}")
            if len(threats) > 3:
                lines.append(f"     ... y {len(threats)-3} mas")

    lines.append("")
    lines.append("-" * 60)
    lines.append("SAAF Pro — Security Audit & Alert Framework")
    return "\n".join(lines)


# =============================================================
# Funciones publicas de alerta
# =============================================================


def send_threat_alert(
    site: dict, new_threats: list, cycle_started_at: str = None
) -> int:
    """
    Envía alerta por email Y SMS si hay amenazas CRITICAL o HIGH nuevas.

    El SMS se envía solo para CRITICAL (configurable con SAAF_SMS_CRITICAL_ONLY).
    El email se envía para CRITICAL y HIGH.

    Args:
        site:             Dict del sitio auditado.
        new_threats:      Lista de objetos Threat con is_new=True.
        cycle_started_at: ISO timestamp del inicio del ciclo (para el email).

    Returns:
        Dict con claves 'emails_sent' y 'sms_sent'.
    """

    result = {"emails_sent": 0, "sms_sent": 0}
    if not new_threats:
        return result

    # Filtrar solo CRITICAL y HIGH — se confia en que new_threats ya son nuevas
    # (el caller en orchestrator.py ya filtra por is_new antes de llamar aqui)
    cfg = get_config()

    alertable_email = []
    alertable_sms = []

    for t in new_threats:
        sev = _sev(t)
        if sev == "CRITICAL" and cfg.get("alert_on_critical") == "1":
            alertable_email.append(t)
            if should_send_sms(sev):
                alertable_sms.append(t)
        elif sev == "HIGH" and cfg.get("alert_on_high") == "1":
            alertable_email.append(t)
            # SMS para HIGH solo si SAAF_SMS_CRITICAL_ONLY != "1"
            if should_send_sms(sev):
                alertable_sms.append(t)

    if not alertable_email:
        logger.info(
            "[%s] Sin amenazas alertables (CRITICAL/HIGH nuevas)", site.get("name")
        )
        return result

    # Determinar severidad maxima para el asunto
    max_sev = _max_sev(alertable_email)
    icon = SEVERITY_ICON.get(max_sev, "")

    # ── Email ─────────────────────────────────────────────────
    subject = (
        f"{icon} SAAF Pro [{max_sev}] — {len(alertable_email)} amenaza(s) en "
        f"{site.get('name', site.get('url', ''))}"
    )
    body_email = _build_threat_body(site, alertable_email, cycle_started_at)
    result["emails_sent"] = send_to_all(subject, body_email)
    logger.info(
        "[%s] Email de alerta: %d enviado(s) (%s)",
        site.get("name"),
        result["emails_sent"],
        max_sev,
    )

    # ── SMS ───────────────────────────────────────────────────
    if alertable_sms:
        body_sms = _build_sms_threat_body(site, alertable_sms)
        result["sms_sent"] = send_sms_to_all(body_sms)
        logger.info(
            "[%s] SMS de alerta: %d enviado(s) (%s)",
            site.get("name"),
            result["sms_sent"],
            max_sev,
        )
    else:
        logger.debug(
            "[%s] SMS no enviado (solo CRITICAL activa SMS, max_sev=%s)",
            site.get("name"),
            max_sev,
        )

    return result


def send_site_down_alert(site: dict, error_msg: str = None) -> int:
    """
    Envía email + SMS cuando un sitio está caído.

    Returns:
        Dict con claves 'emails_sent' y 'sms_sent'.
    """
    result = {"emails_sent": 0, "sms_sent": 0}

    cfg = get_config()
    if cfg.get("alert_on_down") != "1":
        return 0

    site_name = site.get("name", site.get("url", ""))

    # ── Email ─────────────────────────────────────────────────
    subject = f"🔴 SAAF Pro [CAIDO] — {site_name}"
    body_email = _build_down_body(site, error_msg)
    result["emails_sent"] = send_to_all(subject, body_email)
    logger.info("[%s] Email de caída: %d enviado(s)", site_name, result["emails_sent"])

    # ── SMS — siempre cuando el sitio cae, independiente de CRITICAL_ONLY ──
    if cfg.get("sms_enabled") == "1":
        body_sms = _build_sms_down_body(site, error_msg)
        result["sms_sent"] = send_sms_to_all(body_sms)
        logger.info("[%s] SMS de caída: %d enviado(s)", site_name, result["sms_sent"])

    return result


def send_daily_report(summary: dict, site_results: list) -> int:
    """
    Envia el reporte diario consolidado a todos los destinatarios.

    Returns:
        Numero de emails enviados exitosamente.
    """
    date_str = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    subject = f"SAAF Pro — Reporte diario {date_str}"
    body = _build_daily_report_body(summary, site_results)

    sent = send_to_all(subject, body)
    logger.info("Reporte diario enviado a %d destinatario(s)", sent)
    return sent


# =============================================================
# Entrypoint
# ============================================================
if __name__ == "__main__":
    print("\n=== SAAF Pro — alerts.py (diagnóstico de configuración) ===\n")

    cfg = get_config()

    print("── EMAIL ──────────────────────────────────────────────")
    print(
        f"  Habilitado   : {cfg['email_enabled']} {'✅' if cfg['email_enabled']=='1' else '❌ (SAAF_EMAIL_ENABLED=1 para activar)'}"
    )
    print(
        f"  SMTP server  : {cfg['smtp_server'] or '⚠️  no configurado (SAAF_SMTP_SERVER)'}"
    )
    print(f"  SMTP port    : {cfg['smtp_port']}")
    print(
        f"  SMTP from    : {cfg['smtp_from'] or '⚠️  no configurado (SAAF_SMTP_FROM)'}"
    )
    print(
        f"  SMTP user    : {cfg['smtp_user'] or '⚠️  no configurado (SAAF_SMTP_USER)'}"
    )
    print(
        f"  SMTP pass    : {'***' if cfg['smtp_password'] else '⚠️  no configurado (SAAF_SMTP_PASSWORD)'}"
    )
    email_recipients = get_email_recipients()
    print(
        f"  Destinatarios: {email_recipients or '⚠️  ninguno (SAAF_ALERT_RECIPIENTS)'}"
    )
    print(f"  Alerta CRITICAL: {cfg['alert_on_critical']}")
    print(f"  Alerta HIGH   : {cfg['alert_on_high']}")
    print(f"  Alerta DOWN  : {cfg['alert_on_down']}")

    print()
    print("── SMS (TWILIO) ───────────────────────────────────────")
    print(
        f"  Habilitado   : {cfg['sms_enabled']} {'✅' if cfg['sms_enabled']=='1' else '❌ (SAAF_SMS_ENABLED=1 para activar)'}"
    )
    sid_display = (
        (cfg["twilio_sid"][:6] + "***")
        if cfg["twilio_sid"]
        else "⚠️  no configurado (SAAF_TWILIO_ACCOUNT_SID)"
    )
    print(f"  Account SID  : {sid_display}")
    print(
        f"  Auth Token   : {'***' if cfg['twilio_token'] else '⚠️  no configurado (SAAF_TWILIO_AUTH_TOKEN)'}"
    )
    print(
        f"  From number  : {cfg['twilio_from'] or '⚠️  no configurado (SAAF_TWILIO_FROM_NUMBER)'}"
    )
    sms_recipients = get_sms_recipients()
    print(f"  Destinatarios: {sms_recipients or '⚠️  ninguno (SAAF_SMS_RECIPIENTS)'}")
    print(
        f"  Solo CRITICAL : {cfg['sms_critical_only']} {'(SMS solo en CRITICAL)' if cfg['sms_critical_only']=='1' else '(SMS en CRITICAL y HIGH)'}"
    )

    print()
    print("── DASHBOARD ──────────────────────────────────────────")
    dashboard_url = os.environ.get("SAAF_DASHBOARD_URL", "http://10.0.0.117:8501")
    print(f"  URL          : {dashboard_url} (SAAF_DASHBOARD_URL)")

    print()
    print("── CONFIGURAR EN EL SERVIDOR ──────────────────────────")
    if cfg["email_enabled"] != "1":
        print("  export SAAF_EMAIL_ENABLED=1")
    if not cfg["smtp_server"]:
        print("  export SAAF_SMTP_SERVER=smtp.gmail.com")
        print("  export SAAF_SMTP_PORT=587")
        print("  export SAAF_SMTP_FROM=tu@email.com")
        print("  export SAAF_SMTP_USER=tu@email.com")
        print("  export SAAF_SMTP_PASSWORD=tu_contrasena_app")
        print("  export SAAF_ALERT_RECIPIENTS=daniel@empresa.com,otro@empresa.com")
    if cfg["sms_enabled"] != "1":
        print("  export SAAF_SMS_ENABLED=1")
        print("  export SAAF_TWILIO_ACCOUNT_SID=ACxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
        print("  export SAAF_TWILIO_AUTH_TOKEN=tu_auth_token")
        print("  export SAAF_TWILIO_FROM_NUMBER=+1XXXXXXXXXX")
        print("  export SAAF_SMS_RECIPIENTS=+57300XXXXXXX,+1212XXXXXXX")
        print("  export SAAF_SMS_CRITICAL_ONLY=1   # 1=solo CRITICAL, 0=CRITICAL y HIGH")
    print()

    # Test de SMS si está configurado
    if cfg["sms_enabled"] == "1" and cfg["twilio_sid"] and cfg["twilio_token"]:
        import sys

        if "--test-sms" in sys.argv:
            test_number = (
                os.environ.get("SAAF_SMS_RECIPIENTS", "").split(",")[0].strip()
            )
            if test_number:
                print(f"Enviando SMS de prueba a {test_number}...")
                ok = send_sms(
                    test_number, "🛡️ SAAF Pro — SMS de prueba. Sistema funcionando."
                )
                print("✅ SMS enviado" if ok else "❌ SMS falló (ver logs arriba)")
            else:
                print(
                    "⚠️  Sin número destino para test. Configurar SAAF_SMS_RECIPIENTS"
                )
