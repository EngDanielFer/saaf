# =============================================================
# SAAF Pro — enhancements/config.py
# Configuracion de las mejoras:
#   * GLOBAL  (app_settings['enh_global'])  : umbral de confianza, IA, limites.
#   * POR CAMPANIA (tabla enh_site_config)  : programacion propia, reportes
#     (Teams + correos), contexto para la IA, conexion y permisos de WordPress.
# Los secretos (contrasena WP, webhook de Teams) viven en secrets_store.
# =============================================================

import copy
import json
import os
import re

from database import get_setting, set_setting, get_conn
from . import store
from .secrets_store import has_secret, set_secret, get_secret, delete_secret

WEEKDAYS = ("mon", "tue", "wed", "thu", "fri", "sat", "sun")
WEEKDAY_LABELS = {
    "mon": "Lunes", "tue": "Martes", "wed": "Miércoles", "thu": "Jueves",
    "fri": "Viernes", "sat": "Sábado", "sun": "Domingo",
}

DEFAULT_THRESHOLD = 70  # % de confianza minimo para corregir automaticamente

# Acciones que el bot sabe hacer en WordPress.
#   sensitive=True -> NUNCA se aplican solas: siempre piden autorizacion,
#   sin importar la confianza (la confianza no autoriza por si sola).
ACTIONS = {
    "trash_post": {
        "label": "Enviar página/post a la papelera",
        "sensitive": False,
        "help": "Reversible: WordPress lo conserva en la papelera.",
    },
    "remove_link": {
        "label": "Retirar enlace inyectado del contenido",
        "sensitive": False,
        "help": "Edita el contenido de la página; se guarda copia para revertir.",
    },
    "remove_code": {
        "label": "Retirar script/iframe inyectado del contenido",
        "sensitive": True,
        "help": "Sensible: siempre requiere autorización.",
    },
}

GLOBAL_DEFAULTS = {
    "enabled": True,              # interruptor general de las mejoras
    "threshold": DEFAULT_THRESHOLD,
    "ai_enabled": True,           # usar IA (si hay ANTHROPIC_API_KEY)
    "max_auto_actions": 25,       # freno de seguridad por auditoria
    "min_auth_confidence": 50,    # por debajo no se pide ni autorizacion
    "apply_legit_to_alerts": False,  # marcar como omitidas las alertas originales juzgadas legitimas
}

SITE_DEFAULTS = {
    "schedule": {
        "mode": "global",         # global = ciclo general ; custom = programacion propia
        "auto_enabled": True,     # False = no se audita automaticamente
        "days": list(WEEKDAYS),
        "hour": 8,
        "minute": 0,
    },
    "report": {
        "teams_enabled": False,
        "emails": [],
        "email_enabled": False,
        "mode": "after_each_audit",   # after_each_audit | scheduled
        "days": ["mon"],
        "hour": 9,
        "minute": 0,
        "only_if_important": False,
    },
    "ai": {
        "expected_languages": [],     # [] = se infiere de la pagina de inicio
        "business_context": "",       # texto libre para la IA
        "trusted_services": [],       # dominios de terceros que la campania declara usar (CRM, chat, analitica...)
        "threshold": None,            # None = usa el global
    },
    "wp": {
        "enabled": False,
        "base_url": "",
        "username": "",
        "auto_fix": False,            # corregir automaticamente (si confianza >= umbral)
        "dry_run": True,              # simulacion: registra pero no cambia nada
        "allowed_actions": ["trash_post", "remove_link"],
    },
}

_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-']+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")


def killed() -> bool:
    """Interruptor de emergencia por entorno: SAAF_ENHANCEMENTS=0 apaga todo."""
    return os.environ.get("SAAF_ENHANCEMENTS", "1").strip() == "0"


def _deep_merge(base: dict, over: dict) -> dict:
    out = copy.deepcopy(base)
    for k, v in (over or {}).items():
        if isinstance(v, dict) and isinstance(out.get(k), dict):
            out[k] = _deep_merge(out[k], v)
        else:
            out[k] = v
    return out


# ------------------------------------------------------------------
# GLOBAL
# ------------------------------------------------------------------
def get_global() -> dict:
    cfg = dict(GLOBAL_DEFAULTS)
    try:
        raw = get_setting("enh_global")
        if raw:
            cfg.update({k: v for k, v in json.loads(raw).items() if k in GLOBAL_DEFAULTS})
    except (ValueError, TypeError):
        pass
    cfg["threshold"] = _clamp_int(cfg.get("threshold"), 0, 100, DEFAULT_THRESHOLD)
    cfg["max_auto_actions"] = _clamp_int(cfg.get("max_auto_actions"), 0, 500, 25)
    cfg["min_auth_confidence"] = _clamp_int(cfg.get("min_auth_confidence"), 0, 100, 50)
    return cfg


def set_global(**fields) -> dict:
    cur = get_global()
    for k, v in fields.items():
        if k in GLOBAL_DEFAULTS:
            cur[k] = v
    cur["threshold"] = _clamp_int(cur["threshold"], 0, 100, DEFAULT_THRESHOLD)
    cur["max_auto_actions"] = _clamp_int(cur["max_auto_actions"], 0, 500, 25)
    cur["min_auth_confidence"] = _clamp_int(cur["min_auth_confidence"], 0, 100, 50)
    set_setting("enh_global", json.dumps(cur))
    return cur


def _clamp_int(v, lo, hi, default):
    try:
        return max(lo, min(hi, int(v)))
    except (TypeError, ValueError):
        return default


# ------------------------------------------------------------------
# POR CAMPANIA
# ------------------------------------------------------------------
def get_site_config(site_id: int) -> dict:
    store.ensure_schema()
    with get_conn() as conn:
        row = conn.execute(
            "SELECT config FROM enh_site_config WHERE site_id=?", (site_id,)
        ).fetchone()
    stored = store.jload(row["config"], {}) if row else {}
    return normalize_site_config(_deep_merge(SITE_DEFAULTS, stored))


def has_custom_config(site_id: int) -> bool:
    store.ensure_schema()
    with get_conn() as conn:
        return conn.execute(
            "SELECT 1 FROM enh_site_config WHERE site_id=?", (site_id,)
        ).fetchone() is not None


def set_site_config(site_id: int, partial: dict) -> dict:
    """Guarda (fusionando) la configuracion de una campania. Valida y normaliza."""
    cur = get_site_config(site_id)
    merged = normalize_site_config(_deep_merge(cur, partial or {}))
    store.ensure_schema()
    with get_conn() as conn:
        conn.execute(
            """INSERT INTO enh_site_config (site_id, config, updated_at) VALUES (?,?,?)
               ON CONFLICT(site_id) DO UPDATE SET config=excluded.config, updated_at=excluded.updated_at""",
            (site_id, store.jdump(merged), store.now_iso()),
        )
    return merged


def _norm_days(days, default):
    out = [d for d in WEEKDAYS if d in set(days or [])]
    return out or list(default)


def normalize_site_config(cfg: dict) -> dict:
    s, r, a, w = cfg["schedule"], cfg["report"], cfg["ai"], cfg["wp"]

    s["mode"] = s.get("mode") if s.get("mode") in ("global", "custom") else "global"
    s["auto_enabled"] = bool(s.get("auto_enabled", True))
    s["days"] = _norm_days(s.get("days"), WEEKDAYS)
    s["hour"] = _clamp_int(s.get("hour"), 0, 23, 8)
    s["minute"] = _clamp_int(s.get("minute"), 0, 59, 0)

    r["teams_enabled"] = bool(r.get("teams_enabled"))
    r["email_enabled"] = bool(r.get("email_enabled"))
    r["emails"] = parse_emails(r.get("emails"))
    r["mode"] = r.get("mode") if r.get("mode") in ("after_each_audit", "scheduled") else "after_each_audit"
    r["days"] = _norm_days(r.get("days"), ["mon"])
    r["hour"] = _clamp_int(r.get("hour"), 0, 23, 9)
    r["minute"] = _clamp_int(r.get("minute"), 0, 59, 0)
    r["only_if_important"] = bool(r.get("only_if_important"))

    langs = a.get("expected_languages") or []
    if isinstance(langs, str):
        langs = re.split(r"[,\s;]+", langs)
    a["expected_languages"] = sorted({l.strip().lower()[:2] for l in langs if l and l.strip()})
    a["business_context"] = (a.get("business_context") or "").strip()[:1000]
    a["trusted_services"] = parse_domains(a.get("trusted_services"))
    t = a.get("threshold")
    a["threshold"] = None if t in (None, "") else _clamp_int(t, 0, 100, DEFAULT_THRESHOLD)

    w["enabled"] = bool(w.get("enabled"))
    w["base_url"] = (w.get("base_url") or "").strip().rstrip("/")
    w["username"] = (w.get("username") or "").strip()
    w["auto_fix"] = bool(w.get("auto_fix"))
    w["dry_run"] = bool(w.get("dry_run", True))
    w["allowed_actions"] = [x for x in (w.get("allowed_actions") or []) if x in ACTIONS]
    return cfg


def parse_emails(value) -> list:
    if isinstance(value, str):
        value = re.split(r"[,;\s]+", value)
    out, seen = [], set()
    for e in value or []:
        e = (e or "").strip()
        if e and _EMAIL_RE.match(e) and e.lower() not in seen:
            seen.add(e.lower())
            out.append(e)
    return out


def parse_domains(value, limit: int = 60) -> list:
    """Texto/lista -> dominios en minusculas sin esquema, ruta ni www (maximo `limit`)."""
    if isinstance(value, str):
        value = re.split(r"[,;\s]+", value)
    out, seen = [], set()
    for d in value or []:
        d = (d or "").strip().lower()
        d = re.sub(r"^[a-z]+://", "", d).split("/")[0].split("?")[0].split(":")[0].lstrip("*.")
        if d.startswith("www."):
            d = d[4:]
        if d and re.match(r"^[a-z0-9][a-z0-9.\-]*\.[a-z]{2,}$", d) and d not in seen:
            seen.add(d)
            out.append(d)
    return out[:limit]


def invalid_emails(value) -> list:
    if isinstance(value, str):
        value = re.split(r"[,;\s]+", value)
    return [e.strip() for e in value or [] if e and e.strip() and not _EMAIL_RE.match(e.strip())]


def effective_threshold(site_cfg: dict, glob: dict = None) -> int:
    glob = glob or get_global()
    t = site_cfg.get("ai", {}).get("threshold")
    return glob["threshold"] if t is None else int(t)


# ------------------------------------------------------------------
# Secretos por campania
# ------------------------------------------------------------------
def _wp_key(site_id):
    return f"wp_password:{site_id}"


def _teams_key(site_id):
    return f"teams_webhook:{site_id}"


def set_wp_password(site_id, value):
    set_secret(_wp_key(site_id), value)


def get_wp_password(site_id):
    return get_secret(_wp_key(site_id))


def has_wp_password(site_id) -> bool:
    return has_secret(_wp_key(site_id))


def clear_wp_password(site_id):
    delete_secret(_wp_key(site_id))


def set_teams_webhook(site_id, value):
    set_secret(_teams_key(site_id), value)


def get_teams_webhook(site_id):
    return get_secret(_teams_key(site_id))


def has_teams_webhook(site_id) -> bool:
    return has_secret(_teams_key(site_id))


def clear_teams_webhook(site_id):
    delete_secret(_teams_key(site_id))
