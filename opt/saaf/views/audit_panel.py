#!/home/admin_ubuntu/Desktop/proyecto_saaf/opt/saaf/venv/bin/python
# =============================================================
# SAAF Pro — views/audit_panel.py
# Panel con el ESTADO REAL de las auditorias (Dashboard y detalle de sitio):
# estado, fecha de inicio, tiempo transcurrido, etapa, progreso, ultima
# actividad, errores/avisos y fecha de fin (Mejoras_auditoria_y_alertas, #3).
#
# Streamlit 1.28 no tiene st.fragment: el auto-refresco se hace con
# sleep + st.rerun() al FINAL de la pagina (auto_refresh_tail()).
# =============================================================

import sys
import time
from datetime import datetime, timezone

import streamlit as st

sys.path.insert(0, "/home/admin_ubuntu/Desktop/proyecto_saaf/opt/saaf")
sys.path.insert(0, "/home/admin_ubuntu/Desktop/proyecto_saaf/opt/saaf/scripts/python")

from audit_state import (
    PENDING, RUNNING, COMPLETED_WITH_WARNINGS, FAILED, CANCELLED,
    STATUS_COLOR, STATUS_ICON, fmt_duration, normalize_status,
)
from database import (
    get_active_audits,
    get_recent_audits,
    get_site_audits,
    parse_ts,
    reap_stale_audits,
    request_cancel_audits,
    to_local_str,
)
from severity import SEVERITY_ICON

_HAS_ACTIVE_KEY = "saaf_has_active_audits"
_AUTO_KEY = "saaf_auto_refresh_audits"
_FORCE_KEY = "saaf_force_refresh_until"
REFRESH_SECONDS = 3
# Mostrar un aviso si una auditoria RUNNING lleva este tiempo sin actividad
IDLE_WARN_SECONDS = 120


def status_badge_html(status) -> str:
    st_ = normalize_status(status) or str(status)
    color = STATUS_COLOR.get(st_, "#64748B")
    icon = STATUS_ICON.get(st_, "")
    return (
        f'<span style="background:{color};color:#fff;padding:2px 8px;border-radius:4px;'
        f'font-size:11px;font-weight:600;white-space:nowrap">{icon} {st_}</span>'
    )


def _now():
    return datetime.now(timezone.utc)


def _seconds(a_from, a_to=None):
    t0, t1 = parse_ts(a_from), (parse_ts(a_to) if a_to else _now())
    return (t1 - t0).total_seconds() if t0 and t1 else None


def _render_active(a, show_site, key):
    status = normalize_status(a["status"])
    head = f"**{a['site_name']}** · " if show_site else ""
    c_info, c_btn = st.columns([6, 1])
    with c_info:
        st.markdown(
            f"{status_badge_html(status)} &nbsp; {head}**{a['current_stage'] or '—'}**",
            unsafe_allow_html=True,
        )
        pct = int(a["progress"] or 0)
        if status == RUNNING:
            st.progress(pct / 100, text=f"{pct}%")
        idle = _seconds(a["last_activity_at"])
        if status == PENDING:
            st.caption(f"En cola desde {to_local_str(a['started_at'], '%H:%M:%S')} · "
                       f"esperando su turno en el ciclo")
        else:
            pages = (f" · páginas {a['pages_done']}/{a['pages_total']}" if a["pages_total"] else "")
            st.caption(
                f"Inicio: {to_local_str(a['started_at'], '%Y-%m-%d %H:%M:%S')} · "
                f"Transcurrido: **{fmt_duration(_seconds(a['started_at']))}**{pages} · "
                f"Última actividad: {to_local_str(a['last_activity_at'], '%H:%M:%S')} "
                f"(hace {fmt_duration(idle)})"
            )
            if idle is not None and idle > IDLE_WARN_SECONDS:
                st.warning(
                    f"Sin actividad desde hace {fmt_duration(idle)}. Si el proceso ya no está "
                    "activo, esta auditoría se marcará como FAILED automáticamente.",
                    icon="⚠️",
                )
        if a["warnings"]:
            for w in str(a["warnings"]).splitlines():
                st.caption(f"⚠️ {w}")
        if a["cancel_requested"]:
            st.caption("⛔ Cancelación solicitada: se detendrá en cuanto termine el paso actual.")
    with c_btn:
        if not a["cancel_requested"] and st.button("⛔ Cancelar", key=f"{key}_cancel_{a['id']}", use_container_width=True):
            request_cancel_audits(audit_id=a["id"])
            st.rerun()
            

def render_audit_result(a, show_site=True):
    """Resumen de una auditoria TERMINADA (estado, fechas, duracion, motivo/avisos)."""
    status = normalize_status(a["status"])
    sev = a["severity_max"]
    head = f"**{a['site_name']}** · " if show_site and "site_name" in a.keys() else ""
    sev_txt = f" · {SEVERITY_ICON.get(sev, '')} {sev}" if sev and sev != "INFO" else ""
    st.markdown(
        f"{status_badge_html(status)} &nbsp; {head}"
        f"{to_local_str(a['started_at'], '%Y-%m-%d %H:%M')} → "
        f"{to_local_str(a['finished_at'], '%H:%M:%S') if a['finished_at'] else '—'} "
        f"({fmt_duration(_seconds(a['started_at'], a['finished_at']))}){sev_txt}",
        unsafe_allow_html=True,
    )
    if status in (FAILED, CANCELLED) and a["error_msg"]:
        (st.error if status == FAILED else st.info)(f"{status} — {a['error_msg']}")
    if a["warnings"]:
        for w in str(a["warnings"]).splitlines():
            st.caption(f"⚠️ {w}")
    if "allowlisted_count" in a.keys() and a["allowlisted_count"]:
        st.caption(f"✅ {a['allowlisted_count']} recurso(s) reconocidos por la lista permitida")


def render_audit_panel(site_id=None, key="audit_panel", recent_limit=5):
    """
    Panel de estado. site_id=None -> todas las auditorias (Dashboard);
    con site_id -> solo las de ese sitio. Cierra primero las colgadas para que
    lo que se muestra sea el estado real.
    """
    try:
        reap_stale_audits()
    except Exception:
        pass
    
    active = get_active_audits(site_id)
    st.session_state[_HAS_ACTIVE_KEY] = bool(active)
    show_site = site_id is None
    
    if active:
        n_run = sum(1 for a in active if normalize_status(a["status"]) == RUNNING)
        n_pend = len(active) - n_run
        title = f"🔄 Auditoría en curso — {n_run} ejecutándose" + (f", {n_pend} en cola" if n_pend else "")
        with st.container():
            st.markdown(f"#### {title}")
            hdr_a, hdr_b = st.columns([3, 2])
            with hdr_a:
                st.checkbox("Actualizar automáticamente", value=True, key=_AUTO_KEY)
            with hdr_b:
                if len(active) > 1 and st.button("⛔ Cancelar todas", key=f"{key}_cancel_all"):
                    request_cancel_audits(site_id=site_id)
                    st.rerun()
            # RUNNING primero; las PENDING se listan resumidas
            running = [a for a in active if normalize_status(a["status"]) == RUNNING]
            pending = [a for a in active if normalize_status(a["status"]) == PENDING]
            for a in running:
                _render_active(a, show_site, key)
                st.divider()
            if pending:
                if site_id is None and len(pending) > 3:
                    st.caption(f"{PENDING_ICON} En cola ({len(pending)}): " + ", ".join(p["site_name"] for p in pending[:6]) + ("…" if len(pending) > 6 else ""))
                else:
                    for a in pending:
                        _render_active(a, show_site, key)
    
    # --- resultados recientes ---
    recent_rows = (get_site_audits(site_id, limit=recent_limit + 5) if site_id is not None
                   else get_recent_audits(recent_limit + 30))
    recent = [r for r in recent_rows if normalize_status(r["status"]) not in (PENDING, RUNNING)][:recent_limit]
    if recent:
        last = recent[0]
        with st.expander(
            f"{STATUS_ICON.get(normalize_status(last['status']), '')} Última auditoría finalizada: {normalize_status(last['status'])}"
            f" · {to_local_str(last['finished_at'] or last['started_at'], '%Y-%m-%d %H:%M')}",
            expanded=not active and normalize_status(last["status"]) in (FAILED, COMPLETED_WITH_WARNINGS),
        ):
            for r in recent:
                render_audit_result(r, show_site=site_id is None)
                st.divider()
    elif not active:
        st.caption("Aún no hay auditorías registradas.")


PENDING_ICON = STATUS_ICON[PENDING]


def request_refresh(seconds=10):
    """
    Pide mantener el auto-refresco unos segundos aunque aun no haya filas
    activas: tras lanzar una auditoria, el hilo tarda ~1 s en crearlas.
    """
    st.session_state[_FORCE_KEY] = time.time() + seconds
    
    
def auto_refresh_tail(interval=REFRESH_SECONDS):
    """
    Llamar al FINAL de la pagina. Si hay auditorias activas (o se acaba de
    lanzar una) y el usuario no desactivo el auto-refresco, espera unos
    segundos y re-ejecuta el script.
    """
    active = st.session_state.get(_HAS_ACTIVE_KEY)
    forced = time.time() < st.session_state.get(_FORCE_KEY, 0)
    if (active or forced) and st.session_state.get(_AUTO_KEY, True):
        time.sleep(interval)
        st.rerun()
