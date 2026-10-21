# =============================================================
# SAAF Pro — enhancements (mejoras de auditoria, IA, remediacion y reportes)
#
# Paquete ADITIVO: se engancha al proyecto en tres puntos minimos y todos
# estan aislados con try/except; si algo falla aqui, la auditoria original y
# la consola siguen exactamente como antes.
#
#   orchestrator.audit_site()  -> run_after_audit()          (post-proceso)
#   orchestrator.run_cycle()   -> filter_sites_for_cycle()   (solo ciclo programado)
#   scheduler.start()          -> start_ticker()             (programacion por campania)
#   app.py                     -> views/enhancements.py      (nueva pagina del menu)
#
# Interruptor de emergencia: SAAF_ENHANCEMENTS=0 en saaf.env desactiva todo.
# Registro propio: logs/enhancements.log (no escribe en la consola).
# =============================================================

from .log import get_logger


def run_after_audit(*args, **kwargs):
    from .pipeline import run_after_audit as _run

    return _run(*args, **kwargs)


def filter_sites_for_cycle(sites):
    from .schedule import filter_sites_for_cycle as _f

    return _f(sites)


def all_sites_self_scheduled():
    from .schedule import all_sites_self_scheduled as _f

    return _f()


def start_ticker():
    from .schedule import start_ticker as _s

    return _s()


__all__ = ["run_after_audit", "filter_sites_for_cycle", "all_sites_self_scheduled", "start_ticker", "get_logger"]
