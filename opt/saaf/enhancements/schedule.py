# =============================================================
# SAAF Pro — enhancements/schedule.py
# Programacion POR CAMPANIA (punto 6) y calendario de reportes (punto 7).
#
# Convivencia con el ciclo original (no se reemplaza):
#   * Campania en modo "global" (valor por defecto)  -> la audita el ciclo
#     general del scheduler, EXACTAMENTE como antes.
#   * Campania en modo "custom"                      -> tiene dias/hora propios:
#     el ciclo general la omite y la lanza el "ticker" de este modulo.
#   * Campania con auditoria automatica desactivada  -> ningun disparo
#     automatico (la auditoria manual desde el Dashboard sigue funcionando).
#
# El ticker es un hilo propio (NO un job de APScheduler) para no generar la
# linea "Job completado exitosamente" en la consola cada minuto.
# =============================================================

import os
import threading
import time
from datetime import datetime, timedelta

from database import COLOMBIA_TZ, get_all_sites

from . import config as cfgmod
from . import store
from .log import get_logger

log = get_logger()

GRACE_MIN = float(os.environ.get("SAAF_ENH_GRACE_MIN", "90"))
TICK_SECONDS = float(os.environ.get("SAAF_ENH_TICK_SECONDS", "60"))
_DAY_KEYS = cfgmod.WEEKDAYS


def _active() -> bool:
    if cfgmod.killed():
        return False
    try:
        return bool(cfgmod.get_global()["enabled"])
    except Exception:
        return False


# ------------------------------------------------------------------
# Ciclo general: que campanias le tocan
# ------------------------------------------------------------------
def filter_sites_for_cycle(sites: list) -> list:
    """Quita del ciclo GENERAL las campanias con programacion propia o auditoria automatica apagada."""
    if not sites or not _active():
        return sites
    try:
        out = []
        for s in sites:
            sid = s["id"] if "id" in s else None
            if sid is None:
                out.append(s)
                continue
            sch = cfgmod.get_site_config(sid)["schedule"]
            if not sch["auto_enabled"] or sch["mode"] == "custom":
                log.info("Ciclo general: se omite «%s» (%s)", s.get("name"),
                         "auditoría automática desactivada" if not sch["auto_enabled"] else "programación propia")
                continue
            out.append(s)
        return out
    except Exception:
        log.warning("filter_sites_for_cycle falló; se auditan todos los sitios", exc_info=True)
        return sites


def all_sites_self_scheduled() -> bool:
    """True si hay sitios activos pero ninguno le corresponde al ciclo general."""
    try:
        sites = [dict(s) for s in get_all_sites(active_only=True)]
        return bool(sites) and not filter_sites_for_cycle(sites)
    except Exception:
        return False


# ------------------------------------------------------------------
# Calculo de "le toca ahora"
# ------------------------------------------------------------------
def is_due(days: list, hour: int, minute: int, now: datetime, last_fired: str, grace_min: float = None) -> bool:
    grace_min = GRACE_MIN if grace_min is None else grace_min
    if _DAY_KEYS[now.weekday()] not in days:
        return False
    at = now.replace(hour=hour, minute=minute, second=0, microsecond=0)
    if now < at or (now - at).total_seconds() > grace_min * 60:
        return False
    return last_fired != now.strftime("%Y-%m-%d")


def describe_days(days: list) -> str:
    days = [d for d in _DAY_KEYS if d in days]
    if len(days) == 7:
        return "todos los días"
    names = [cfgmod.WEEKDAY_LABELS[d] for d in days]
    return names[0] if len(names) == 1 else ", ".join(names[:-1]) + " y " + names[-1]


def next_due(days: list, hour: int, minute: int, now: datetime = None):
    """Proxima fecha/hora en que toca, mirando los proximos 7 dias. None si nunca."""
    now = now or datetime.now(COLOMBIA_TZ)
    days = list(days) or list(_DAY_KEYS)
    for d in range(0, 8):
        cand = (now + timedelta(days=d)).replace(hour=int(hour), minute=int(minute), second=0, microsecond=0)
        if _DAY_KEYS[cand.weekday()] not in days or cand <= now:
            continue
        return cand
    return None


def next_audit_at(site_id: int, sch: dict, now: datetime = None):
    """Proxima auditoria de ESTA campania, o None si la lanza el ciclo general o esta apagada."""
    if not sch.get("auto_enabled") or sch.get("mode") != "custom":
        return None
    return next_due(sch.get("days"), sch.get("hour", 8), sch.get("minute", 0), now)


def next_report_at(site_id: int, rep: dict, now: datetime = None):
    """Proximo envio programado del reporte, o None si va tras cada auditoria o esta apagado."""
    if rep.get("mode") != "scheduled" or not (rep.get("teams_enabled") or (rep.get("email_enabled") and rep.get("emails"))):
        return None
    return next_due(rep.get("days"), rep.get("hour", 9), rep.get("minute", 0), now)


def last_audit_fired(site_id: int):
    """Ultimo dia (YYYY-MM-DD) en que el ticker lanzo la auditoria de esta campania."""
    return store.kv_get(f"sched_fired:{site_id}") or ""


def last_report_fired(site_id: int):
    return store.kv_get(f"report_fired:{site_id}") or ""


def pending_setup(sites: list) -> list:
    """Campanias que nunca se configuraron: siguen el ciclo general por defecto."""
    out = []
    for s in sites or []:
        sid = s["id"] if "id" in s else None
        if sid is None:
            continue
        try:
            if not cfgmod.has_custom_config(sid):
                out.append(s)
        except Exception:
            pass
    return out


def describe_schedule(sch: dict) -> str:
    if not sch["auto_enabled"]:
        return "Auditoría automática desactivada"
    if sch["mode"] == "global":
        return "Sigue el ciclo general del scheduler"
    return f"{describe_days(sch['days'])} a las {sch['hour']:02d}:{sch['minute']:02d} (hora de Colombia)"


# ------------------------------------------------------------------
# Disparos
# ------------------------------------------------------------------
def run_due_audits(now: datetime = None) -> list:
    now = now or datetime.now(COLOMBIA_TZ)
    launched = []
    for s in get_all_sites(active_only=True):
        sch = cfgmod.get_site_config(s["id"])["schedule"]
        if not (sch["auto_enabled"] and sch["mode"] == "custom"):
            continue
        key = f"sched_fired:{s['id']}"
        if not is_due(sch["days"], sch["hour"], sch["minute"], now, store.kv_get(key)):
            continue
        store.kv_set(key, now.strftime("%Y-%m-%d"))  # primero se marca: un reinicio no lo repite
        try:
            from audit_runner import start_site_audit

            started, msg, aid = start_site_audit(s)
            log.info("Programación propia «%s»: %s (auditoría %s)", s["name"], msg, aid)
            launched.append((s["id"], started, aid))
        except Exception:
            log.error("No se pudo lanzar la auditoría programada de «%s»", s["name"], exc_info=True)
    return launched


def run_due_reports(now: datetime = None) -> list:
    """Reportes con calendario propio (dias/hora), independientes de la frecuencia de auditoria."""
    from . import distribution, pipeline

    now = now or datetime.now(COLOMBIA_TZ)
    sent = []
    for s in get_all_sites(active_only=False):
        rep = cfgmod.get_site_config(s["id"])["report"]
        if rep["mode"] != "scheduled" or not (rep["teams_enabled"] or (rep["email_enabled"] and rep["emails"])):
            continue
        key = f"report_fired:{s['id']}"
        if not is_due(rep["days"], rep["hour"], rep["minute"], now, store.kv_get(key)):
            continue
        store.kv_set(key, now.strftime("%Y-%m-%d"))
        row = pipeline.get_report(site_id=s["id"])
        if not row:
            log.info("Reporte programado de «%s»: aún no hay auditorías analizadas", s["name"])
            continue
        try:
            res = distribution.dispatch(s["id"], row["report"])
            if res:
                from database import get_conn

                with get_conn() as conn:
                    conn.execute("UPDATE enh_reports SET dispatch=? WHERE id=?", (store.jdump(res), row["id"]))
            sent.append((s["id"], res))
        except Exception:
            log.error("No se pudo enviar el reporte programado de «%s»", s["name"], exc_info=True)
    return sent


def tick(now: datetime = None) -> dict:
    out = {"audits": [], "reports": []}
    if not _active():
        return out
    try:
        store.ensure_schema()
        out["audits"] = run_due_audits(now)
    except Exception:
        log.error("tick/auditorías falló", exc_info=True)
    try:
        out["reports"] = run_due_reports(now)
    except Exception:
        log.error("tick/reportes falló", exc_info=True)
    return out


# ------------------------------------------------------------------
# Hilo ticker (lo inicia scheduler.py)
# ------------------------------------------------------------------
_ticker = None


def start_ticker():
    global _ticker
    if _ticker and _ticker.is_alive():
        return _ticker

    def _loop():
        log.info("Ticker de programación por campaña iniciado (cada %.0f s)", TICK_SECONDS)
        while True:
            try:
                tick()
            except Exception:
                log.error("ticker", exc_info=True)
            time.sleep(TICK_SECONDS)

    _ticker = threading.Thread(target=_loop, name="saaf-enh-ticker", daemon=True)
    _ticker.start()
    return _ticker
