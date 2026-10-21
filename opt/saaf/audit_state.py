#!/home/admin_ubuntu/Desktop/proyecto_saaf/opt/saaf/venv/bin/python
# =============================================================
# SAAF Pro — audit_state.py
# Vocabulario y reglas PURAS del ciclo de vida de una auditoria
# (sin BD, sin Streamlit): estados, excepciones de control, y la
# clasificacion de errores de servicios externos en mensajes claros.
#
# Estados (ver Mejoras_auditoria_y_alertas, punto 3):
#   PENDING                 creada, aun no empieza
#   RUNNING                 ejecutandose realmente
#   COMPLETED               termino correctamente
#   COMPLETED_WITH_WARNINGS termino, pero alguna parte tuvo problemas que
#                           no impidieron obtener resultados
#   FAILED                  no pudo completarse (se guarda el motivo)
#   CANCELLED               cancelada manualmente
# =============================================================

PENDING = "PENDING"
RUNNING = "RUNNING"
COMPLETED = "COMPLETED"
COMPLETED_WITH_WARNINGS = "COMPLETED_WITH_WARNINGS"
FAILED = "FAILED"
CANCELLED = "CANCELLED"

ALL_STATUSES = (
    PENDING, RUNNING, COMPLETED, COMPLETED_WITH_WARNINGS, FAILED, CANCELLED,
)
ACTIVE_STATUSES = (PENDING, RUNNING)
TERMINAL_STATUSES = (COMPLETED, COMPLETED_WITH_WARNINGS, FAILED, CANCELLED)

# Valores que usaba la version anterior del sistema -> nuevos
LEGACY_STATUS_MAP = {
    "running": RUNNING,
    "ok": COMPLETED,
    "issues": COMPLETED,  # "issues" = hallo amenazas; la auditoria SI termino bien
    "error": FAILED,
}

STATUS_ICON = {
    PENDING: "⏳",
    RUNNING: "🔄",
    COMPLETED: "✅",
    COMPLETED_WITH_WARNINGS: "⚠️",
    FAILED: "❌",
    CANCELLED: "⛔",
}

STATUS_COLOR = {
    PENDING: "#64748B",
    RUNNING: "#2563EB",
    COMPLETED: "#16A34A",
    COMPLETED_WITH_WARNINGS: "#CA8A04",
    FAILED: "#DC2626",
    CANCELLED: "#6B7280",
}


def normalize_status(value):
    """
    Devuelve el estado canonico (PENDING, RUNNING...) o None si no es valido.
    Acepta mayusculas/minusculas y los valores legados ('ok', 'issues', 'error').
    """
    if value is None:
        return None
    v = str(value).strip()
    if v.upper() in ALL_STATUSES:
        return v.upper()
    return LEGACY_STATUS_MAP.get(v.lower())


def is_active(status) -> bool:
    return normalize_status(status) in ACTIVE_STATUSES


def is_terminal(status) -> bool:
    return normalize_status(status) in TERMINAL_STATUSES


def status_label(status) -> str:
    st = normalize_status(status)
    return f"{STATUS_ICON.get(st, '')} {st}".strip() if st else str(status)


def classify_result(result: dict) -> str:
    """
    Clasifica el resultado de audit_site() para los contadores del ciclo:
    'down' | 'error' | 'cancelled' | 'issues' | 'ok'.
    (Reemplaza a los antiguos status 'ok'/'issues'/'error' en scheduler.py.)
    """
    if result.get("is_up") is False:
        return "down"
    st = normalize_status(result.get("status"))
    if st == FAILED or st is None:
        return "error"
    if st == CANCELLED:
        return "cancelled"
    return "issues" if result.get("has_issues") else "ok"


# =============================================================
# Excepciones de control del flujo
# =============================================================


class AuditCancelled(Exception):
    """El usuario pidio cancelar la auditoria (cancelacion cooperativa)."""
    
    
class AuditAborted(Exception):
    """
    La auditoria ya no esta RUNNING en la BD (p. ej. el watchdog la marco como
    FAILED por falta de actividad). El proceso debe detenerse sin sobrescribir.
    """


class AuditError(Exception):
    """Error de auditoria con codigo + mensaje claro para el usuario."""

    def __init__(self, message: str, code: str = "internal"):
        super().__init__(message)
        self.code = code
        
        
# =============================================================
# Clasificacion de errores de servicios externos
# =============================================================

# Codigos estables (se guardan/loguean; la UI muestra el mensaje)
ERR_CREDITS = "credits"
ERR_AUTH = "auth"
ERR_PERMISSION = "permission"
ERR_RATE_LIMIT = "rate_limit"
ERR_TIMEOUT = "timeout"
ERR_CONNECTION = "connection"
ERR_PROVIDER = "provider"
ERR_INVALID_RESPONSE = "invalid_response"
ERR_INTERRUPTED = "interrupted"
ERR_INTERNAL = "internal"

_CREDIT_HINTS = (
    "credit balance",
    "credit_balance",
    "insufficient_quota",
    "insufficient quota",
    "insufficient funds",
    "out of credits",
    "billing",
    "payment required",
    "exceeded your current quota",
    "quota exceeded",
)


def classify_exception(exc, service: str = "Claude") -> tuple:
    """
    Convierte una excepcion en (codigo, mensaje_claro_en_español).
    Funciona por 'duck typing' (nombre de clase, status_code, texto) para no
    depender de tener instalado anthropic/requests/twilio.

    Ejemplos de salida:
        (credits,    'Créditos insuficientes en el proveedor de IA.')
        (timeout,    'La API externa no respondió después del tiempo máximo permitido.')
    """
    if isinstance(exc, AuditError):
        return exc.code, str(exc)

    name = type(exc).__name__.lower()
    text = str(exc) or type(exc).__name__
    low = text.lower()
    status = getattr(exc, "status_code", None)
    if status is None:
        resp = getattr(exc, "response", None)
        status = getattr(resp, "status_code", None)
    
    # 1) Creditos / facturacion (puede venir como 400, 402 o 429 segun proveedor)
    if status == 402 or any(h in low for h in _CREDIT_HINTS):
        return ERR_CREDITS, f"Créditos insuficientes en {service}."

    # 2) Credenciales
    if status == 401 or "authentication" in name or "invalid x-api-key" in low or "invalid api key" in low:
        return ERR_AUTH, f"Autenticación inválida con {service} (revisar la API key)."
    if status == 403 or "permissiondenied" in name:
        return ERR_PERMISSION, f"Acceso denegado por {service} (permisos de la API key)."

    # 3) Limite de solicitudes
    if status == 429 or "ratelimit" in name or "rate limit" in low or "rate_limit" in low:
        return ERR_RATE_LIMIT, f"Límite de solicitudes alcanzado en {service}."

    # 4) Timeout y conexion
    if "timeout" in name or "timed out" in low or isinstance(exc, TimeoutError):
        return ERR_TIMEOUT, "La API externa no respondió después del tiempo máximo permitido."
    if "connection" in name or isinstance(exc, ConnectionError) or "connection" in low and "error" in low:
        return ERR_CONNECTION, f"No se pudo conectar con {service}."
    
    # 5) Errores del proveedor (5xx / sobrecarga)
    if (isinstance(status, int) and status >= 500) or "internalserver" in name or "overloaded" in low:
        return ERR_PROVIDER, f"Error en {service} (HTTP {status or '5xx'})."
    if "apistatus" in name and isinstance(status, int):
        return ERR_PROVIDER, f"Error en {service} (HTTP {status}): {text[:150]}"

    # 6) Respuesta inesperada
    if "jsondecode" in name or isinstance(exc, (ValueError, KeyError, TypeError)) and "json" in low:
        return ERR_INVALID_RESPONSE, f"Respuesta inválida del servicio externo ({service})."

    # 7) Interrupcion del proceso
    if isinstance(exc, (KeyboardInterrupt, SystemExit)):
        return ERR_INTERRUPTED, "El proceso de auditoría fue interrumpido (reinicio del servicio o Ctrl+C)."

    return ERR_INTERNAL, f"Excepción no controlada: {type(exc).__name__}: {text[:200]}"


# =============================================================
# Formato de tiempos
# =============================================================


def fmt_duration(seconds) -> str:
    """90 -> '1m 30s' · 3725 -> '1h 02m 05s' · None -> '—'."""
    if seconds is None:
        return "—"
    s = max(0, int(seconds))
    h, rem = divmod(s, 3600)
    m, sec = divmod(rem, 60)
    if h:
        return f"{h}h {m:02d}m {sec:02d}s"
    if m:
        return f"{m}m {sec:02d}s"
    return f"{sec}s"