#!/home/admin_ubuntu/Desktop/proyecto_saaf/opt/saaf/venv/bin/python
# =============================================================
# SAAF Pro — audit_runner.py
# Lanza auditorias desde el Dashboard SIN bloquear la UI, y de forma
# que su estado sea siempre visible y veraz.
#
# Antes las vistas arrancaban un hilo y guardaban "ya hay una auditoria en
# curso" en st.session_state DESDE EL HILO (donde Streamlit no tiene contexto
# de sesion, asi que el guardia no funcionaba y el doble clic lanzaba dos
# auditorias). Ademas un error dentro del hilo se tragaba en silencio.
#
# Ahora:
#   * El guardia es la BD: si hay auditorias PENDING/RUNNING vivas, no se lanza otra.
#   * La auditoria se crea en PENDING ANTES de lanzar el hilo -> la UI la ve de inmediato.
#   * Si el hilo falla, la auditoria queda FAILED con el motivo (nunca RUNNING).
#   * Sin dependencias de Streamlit: se puede probar y reutilizar.
# =============================================================

import logging
import sys
import threading

sys.path.insert(0, "/home/admin_ubuntu/Desktop/proyecto_saaf/opt/saaf")
sys.path.insert(0, "/home/admin_ubuntu/Desktop/proyecto_saaf/opt/saaf/scripts/python")

from audit_state import FAILED, PENDING, classify_exception
from database import (
    finish_audit,
    get_active_audits,
    get_audit,
    reap_stale_audits,
    start_audit,
)

logger = logging.getLogger("audit_runner")

# Evita la carrera "comprobar -> lanzar" si llegan dos clics a la vez
_launch_lock = threading.Lock()


def _active_after_reap(site_id=None):
    """Cierra primero las colgadas (para no bloquear por una auditoria muerta)."""
    try:
        reap_stale_audits()
    except Exception as e:
        logger.warning("Vigilante de auditorias fallo: %s", e)
    return get_active_audits(site_id)


def start_site_audit(site):
    """
    Lanza la auditoria de UN sitio en segundo plano.
    Returns: (iniciada: bool, mensaje: str, audit_id | None)
    """
    with _launch_lock:
        active = _active_after_reap(site["id"])
        if active:
            return False, "Ya hay una auditoría en curso para este sitio.", active[0]["id"]
        audit_id = start_audit(site["id"], status=PENDING)

    site_dict = dict(site)
    
    def _run():
        try:
            from orchestrator import audit_site

            audit_site(site_dict, audit_id=audit_id)
        except BaseException as e:  # noqa — nunca dejar la auditoria abierta
            code, msg = classify_exception(e)
            logger.error("Auditoria %s fallo en el hilo (%s): %s", audit_id, code, e, exc_info=True)
            finish_audit(audit_id, "none", 0, FAILED, error_msg=msg)

    threading.Thread(target=_run, daemon=True, name=f"saaf-audit-{audit_id}").start()
    return True, "Auditoría iniciada en segundo plano.", audit_id


def start_cycle():
    """
    Lanza una auditoria de TODOS los sitios activos en segundo plano.
    run_cycle() crea de entrada una auditoria PENDING por sitio.
    Returns: (iniciado: bool, mensaje: str)
    """
    with _launch_lock:
        active = _active_after_reap()
        if active:
            return False, f"Ya hay {len(active)} auditoría(s) en curso o en cola."

    def _run():
        try:
            from orchestrator import run_cycle

            run_cycle()
        except BaseException as e:  # noqa
            logger.error("Ciclo manual fallo: %s", e, exc_info=True)

    threading.Thread(target=_run, daemon=True, name="saaf-cycle").start()
    return True, "Ciclo iniciado en segundo plano."