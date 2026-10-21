#!/home/admin_ubuntu/Desktop/proyecto_saaf/opt/saaf/venv/bin/python
# =============================================================
# SAAF Pro — views/dashboard.py
# Vista principal: tabla de sitios, uptime, severidad, badges
# =============================================================

import streamlit as st
import pandas as pd
from datetime import datetime, timezone, time as dtime

import sys

sys.path.insert(0, "/home/admin_ubuntu/Desktop/proyecto_saaf/opt/saaf")
sys.path.insert(0, "/home/admin_ubuntu/Desktop/proyecto_saaf/opt/saaf/scripts/python")

from database import (
    get_all_sites,
    get_dashboard_summary,
    init_db,
    get_conn,
    get_schedule_config,
    set_schedule_config,
    get_once_run,
    set_once_run,
    clear_once_run,
    COLOMBIA_TZ,
    WEEKDAY_LABELS,
    to_local_str,
)
from audit_runner import start_cycle
from audit_state import STATUS_ICON, normalize_status
from severity import SEVERITY_LEVELS
from views.audit_panel import render_audit_panel, auto_refresh_tail, request_refresh

# =============================================================
# Batch query — evita N+1 queries por sitio
# =============================================================


def _get_all_sites_data() -> list:
    """
    Carga datos de todos los sitios en una sola pasada de queries
    agrupadas — evita el patron N+1 (5 queries por sitio).
    """
    sites = get_all_sites(active_only=False)
    if not sites:
        return []

    site_ids = [s["id"] for s in sites]
    id_str = ",".join("?" * len(site_ids))

    with get_conn() as conn:
        # Ultimo uptime por sitio
        uptime_rows = conn.execute(
            f"""SELECT u.site_id, u.is_up, u.status_code, u.response_time_ms
                FROM uptime u
                JOIN (SELECT site_id, MAX(checked_at) as last FROM uptime
                      WHERE site_id IN ({id_str}) GROUP BY site_id) latest
                ON u.site_id=latest.site_id AND u.checked_at=latest.last""",
            site_ids,
        ).fetchall()

        # Uptime 7 dias
        uptime7_rows = conn.execute(
            f"""SELECT site_id,
                    ROUND(100.0*SUM(is_up)/COUNT(*), 1) as pct
               FROM uptime
               WHERE site_id IN ({id_str})
                 AND checked_at >= datetime('now','-7 days')
               GROUP BY site_id""",
            site_ids,
        ).fetchall()

        # Uptime 30 dias
        uptime30_rows = conn.execute(
            f"""SELECT site_id,
                    ROUND(100.0*SUM(is_up)/COUNT(*), 1) as pct
               FROM uptime
               WHERE site_id IN ({id_str})
                 AND checked_at >= datetime('now','-30 days')
               GROUP BY site_id""",
            site_ids,
        ).fetchall()

        # Ultima auditoria (cualquier estado: para mostrar el estado REAL)
        audit_rows = conn.execute(
            f"""SELECT a.site_id, a.started_at, a.status, a.crawl_method,
                       a.urls_analyzed, a.severity_max, a.error_msg, a.current_stage
               FROM audits a
               JOIN (SELECT site_id, MAX(id) as mid FROM audits
                     WHERE site_id IN ({id_str}) GROUP BY site_id) latest
               ON a.id=latest.mid""",
            site_ids,
        ).fetchall()
        
        # Severidad: de la ultima auditoria TERMINADA. Una auditoria en curso
        # tiene severity_max NULL y antes pintaba el sitio como "OK" mientras corria.
        sev_rows = conn.execute(
            f"""SELECT a.site_id, a.severity_max
               FROM audits a
               JOIN (SELECT site_id, MAX(id) as mid FROM audits
                     WHERE site_id IN ({id_str})
                       AND status IN ('COMPLETED','COMPLETED_WITH_WARNINGS','FAILED')
                     GROUP BY site_id) latest
               ON a.id=latest.mid""",
            site_ids,
        ).fetchall()

        # Conteo de alertas abiertas
        # NOTA: se excluye ignored=1 (falsos positivos omitidos) — de lo
        # contrario un falso positivo ya descartado sigue sumando en la
        # columna "Alertas" del Dashboard cada vez que se re-detecta.
        # INFO es informativo (no es una alerta): tampoco cuenta.
        alerts_rows = conn.execute(
            f"""SELECT site_id, COUNT(*) as cnt
               FROM threats
               WHERE site_id IN ({id_str}) AND resolved=0 AND ignored=0
                 AND severity != 'INFO'
               GROUP BY site_id""",
            site_ids,
        ).fetchall()

    # Indexar por site_id
    uptime_map = {r["site_id"]: r for r in uptime_rows}
    uptime7_map = {r["site_id"]: r["pct"] for r in uptime7_rows}
    uptime30_map = {r["site_id"]: r["pct"] for r in uptime30_rows}
    audit_map = {r["site_id"]: r for r in audit_rows}
    sev_map = {r["site_id"]: r["severity_max"] for r in sev_rows}
    alerts_map = {r["site_id"]: r["cnt"] for r in alerts_rows}

    result = []
    for s in sites:
        sid = s["id"]
        up_row = uptime_map.get(sid)
        aud_row = audit_map.get(sid)
        result.append(
            {
                "site": s,
                "is_up": bool(up_row["is_up"]) if up_row else None,
                "uptime7": uptime7_map.get(sid),
                "uptime30": uptime30_map.get(sid),
                "last_audit": aud_row,
                "open_alerts": alerts_map.get(sid, 0),
                "sev_max": sev_map.get(sid),
            }
        )
    return result


# =============================================================
# Helpers visuales
# =============================================================


def _sev_badge(sev):
    if not sev:
        return '<span class="badge-ok">OK</span>'
    m = {
        "CRITICAL": "badge-critico",
        "HIGH": "badge-alto",
        "MEDIUM": "badge-medio",
        "LOW": "badge-bajo",
        "INFO": "badge-info",
    }
    css = m.get(sev, "badge-ok")
    return f'<span class="{css}">{sev}</span>'


def _status_badge(is_up, sev_max=None):
    if is_up is False:
        return '<span class="badge-caido">CAIDO</span>'
    if sev_max:
        return _sev_badge(sev_max)
    return '<span class="badge-ok">OK</span>'


def _uptime_bar(pct):
    if pct is None:
        return "Sin datos"
    color = "#16A34A" if pct >= 99 else ("#CA8A04" if pct >= 95 else "#DC2626")
    return f'<div style="background:#E2E8F0;border-radius:4px;height:8px;width:100%"><div style="background:{color};border-radius:4px;height:8px;width:{pct}%"></div></div><small>{pct}%</small>'


# =============================================================
# Vista principal
# =============================================================


# =============================================================
# Configuración de frecuencia del ciclo automático
# =============================================================

_WEEKDAY_ORDER = ["mon", "tue", "wed", "thu", "fri", "sat", "sun"]


def _render_schedule_config():
    """
    Panel para configurar si el ciclo automático (scheduler.py) corre
    diaria o semanalmente, y a qué hora. Se guarda en la BD (app_settings)
    y scheduler.py la relee automáticamente cada pocos minutos — no hace
    falta reiniciar el servicio systemd para que el cambio tome efecto.
    """
    with st.container():
        st.markdown("#### 🕐 Frecuencia del ciclo automático")

        try:
            current = get_schedule_config()
        except Exception as e:
            st.error(f"Error leyendo configuración: {e}")
            return

        freq_options = ["Diaria", "Semanal"]
        freq_index = 1 if current["frequency"] == "weekly" else 0

        col1, col2, col3 = st.columns([1.3, 1, 1])
        with col1:
            freq_label = st.selectbox(
                "Frecuencia", freq_options, index=freq_index, key="saaf_sched_freq"
            )
        with col2:
            hour = st.selectbox(
                "Hora (Colombia)",
                list(range(24)),
                index=current["hour"],
                key="saaf_sched_hour",
                format_func=lambda h: f"{h:02d}:00",
            )
        with col3:
            minute = st.selectbox(
                "Minuto",
                [0, 15, 30, 45],
                index=[0, 15, 30, 45].index(current["minute"])
                if current["minute"] in (0, 15, 30, 45)
                else 0,
                key="saaf_sched_minute",
            )

        weekday_code = current.get("weekday", "mon")
        if freq_label == "Semanal":
            weekday_labels = [WEEKDAY_LABELS[d] for d in _WEEKDAY_ORDER]
            wd_index = (
                _WEEKDAY_ORDER.index(weekday_code)
                if weekday_code in _WEEKDAY_ORDER
                else 0
            )
            weekday_choice = st.selectbox(
                "Día de la semana", weekday_labels, index=wd_index, key="saaf_sched_weekday"
            )
            weekday_code = _WEEKDAY_ORDER[weekday_labels.index(weekday_choice)]

        # Resumen de la config activa
        if current["frequency"] == "weekly":
            resumen = (
                f"Actualmente: **Semanal** — cada **{WEEKDAY_LABELS.get(current.get('weekday','mon'))}** "
                f"a las **{current['hour']:02d}:{current['minute']:02d}** (hora de Colombia)"
            )
        else:
            resumen = f"Actualmente: **Diaria** — todos los días a las **{current['hour']:02d}:{current['minute']:02d}** (hora de Colombia)"
        st.caption(resumen)

        col_save, col_close = st.columns([1, 1])
        with col_save:
            if st.button("💾 Guardar frecuencia", type="primary", use_container_width=True):
                try:
                    frequency = "weekly" if freq_label == "Semanal" else "daily"
                    set_schedule_config(
                        frequency=frequency,
                        hour=hour,
                        minute=minute,
                        weekday=weekday_code,
                    )
                    st.success(
                        "Frecuencia guardada. El scheduler la aplica automáticamente "
                        "en un máximo de 5 minutos (no requiere reiniciar el servicio)."
                    )
                except Exception as e:
                    st.error(f"Error guardando: {e}")
        with col_close:
            if st.button("Cerrar", use_container_width=True):
                st.session_state["saaf_show_schedule_cfg"] = False
                st.rerun()


def render():
    _render_impl()
    # Auto-refresco: debe ser lo ULTIMO de la pagina (sleep + st.rerun)
    auto_refresh_tail()


def _render_impl():
    init_db()
    st.markdown("## 🏠 Dashboard")

    # --- Métricas globales ---
    try:
        summary = get_dashboard_summary()
        c1, c2, c3, c4, c5 = st.columns(5)
        c1.metric("Sitios activos", summary["total_sites"])
        c2.metric(
            "🔴 Sitios caídos",
            summary["sites_down"],
            delta=None if summary["sites_down"] == 0 else f"-{summary['sites_down']}",
        )
        c3.metric("🔴 Crítico", summary["open_critical"])
        c4.metric("🟠 Alto", summary["open_high"])
        c5.metric("⚠️ Total alertas", summary["open_total"])
    except Exception as e:
        st.error(f"Error cargando métricas: {e}")

    st.markdown("---")

    # --- Controles ---
    col_search, col_filter, col_refresh, col_sched, col_audit = st.columns(
        [3, 2, 1, 1.3, 1]
    )
    with col_search:
        search = st.text_input(
            "🔍 Buscar sitio",
            placeholder="nombre o URL...",
            label_visibility="collapsed",
        )
    with col_filter:
        filtro = st.selectbox(
            "Filtrar por",
            ["Todos", "Con problemas", "Caídos", "OK"],
            label_visibility="collapsed",
        )
    with col_refresh:
        if st.button("🔄 Actualizar", use_container_width=True):
            st.rerun()
    with col_sched:
        if st.button("🕐 Frecuencia", use_container_width=True):
            st.session_state["saaf_show_schedule_cfg"] = not st.session_state.get(
                "saaf_show_schedule_cfg", False
            )
    with col_audit:
        if st.button("▶ Auditar todos", use_container_width=True, type="primary"):
            _trigger_all_audits()

    if st.session_state.get("saaf_show_schedule_cfg"):
        _render_schedule_config()
        _render_once_config()

    # --- Estado real de las auditorías (en curso, en cola y recientes) ---
    render_audit_panel(key="dash_audits")
    
    st.markdown("---")

    # --- Tabla de sitios ---
    # sites se carga dentro de _get_all_sites_data() via batch
    # Solo verificamos si hay sitios antes de continuar

    # Cargar datos de todos los sitios en batch (sin N+1 queries)
    try:
        all_data = _get_all_sites_data()
    except Exception as e:
        st.error(f"Error cargando datos: {e}")
        return

    # Construir filas
    rows = []
    for item in all_data:
        s = item["site"]
        is_up = item["is_up"]
        uptime7 = item["uptime7"]
        uptime30 = item["uptime30"]
        last_audit = item["last_audit"]
        open_issues = [None] * item["open_alerts"]  # solo necesitamos el conteo
        sev_max = item["sev_max"]

        if search and search.lower() not in (s["name"] + s["url"]).lower():
            continue

        # Aplicar filtro
        if filtro == "Con problemas" and not open_issues:
            continue
        if filtro == "Caídos" and is_up is not False:
            continue
        if filtro == "OK" and (open_issues or is_up is False):
            continue
        
        rows.append(
            {
                "_id": s["id"],
                "Estado": _status_badge(is_up, sev_max),
                "Sitio": f"**{s['name']}**",
                "URL": s["url"],
                "Nicho": s["niche"],
                "Prioridad": s["priority"],
                "Uptime 7d": _uptime_bar(uptime7),
                "Uptime 30d": _uptime_bar(uptime30),
                "Alertas": len(open_issues),
                "Ult. auditoría": (
                    to_local_str(last_audit["started_at"]) if last_audit else "—"
                ),
                "_audit_status": normalize_status(last_audit["status"]) if last_audit else None,
            }
        )
    
    if not all_data:
        st.info(
            "No hay sitios configurados. Ve a ⚙️ Configuración → Sitios para agregar el primero."
        )
        st.markdown("**Primeros pasos:**")
        st.markdown("1. Ve a ⚙️ Configuración")
        st.markdown("2. Agrega tus sitios con nombre, URL y nicho")
        st.markdown("3. Vuelve aquí y haz clic en **▶ Auditar todos**")
        return

    if not rows:
        st.info("No hay sitios que coincidan con el filtro.")
        return

    # Renderizar tabla con HTML
    st.markdown(f"**{len(rows)} sitios**")
    
    # Encabezados de la tabla
    with st.container():
        h1, h2, h3, h4, h5, h6, h7, h8 = st.columns([1.2, 2, 2.5, 1.2, 1, 1.5, 1.5, 1])
        h1.markdown("**Estado**")
        h2.markdown("**Sitio**")
        h3.markdown("**URL**")
        h4.markdown("**Nicho / Prioridad**")
        h5.markdown("**Alertas**")
        h6.markdown("**Uptime 7d**")
        h7.markdown("**Última auditoría**")
        h8.markdown("")
    st.divider()
    
    for row in rows:
        with st.container():
            c1, c2, c3, c4, c5, c6, c7, c8 = st.columns(
                [1.2, 2, 2.5, 1.2, 1, 1.5, 1.5, 1]
            )
            with c1:
                st.markdown(row["Estado"], unsafe_allow_html=True)
            with c2:
                st.markdown(row["Sitio"])
            with c3:
                st.caption(row["URL"])
            with c4:
                st.caption(f"{row['Nicho']} · {row['Prioridad']}")
            with c5:
                color = "🔴" if row["Alertas"] > 0 else "✅"
                st.caption(f"{color} {row['Alertas']} alertas")
            with c6:
                st.markdown(row["Uptime 7d"], unsafe_allow_html=True)
            with c7:
                st.caption(row["Ult. auditoría"])
                if row["_audit_status"]:
                    st.caption(f"{STATUS_ICON.get(row['_audit_status'], '')} {row['_audit_status']}")
            with c8:
                if st.button(
                    "Ver", key=f"detail_{row['_id']}", use_container_width=True
                ):
                    st.session_state["saaf_selected_site"] = row["_id"]
                    st.rerun()
        st.divider()


def _render_once_config():
    """
    Programa UNA ejecucion puntual (fecha + hora de Colombia), independiente
    de la frecuencia diaria/semanal. scheduler.py la detecta en un maximo de
    5 minutos, la ejecuta una sola vez y la borra.
    """
    with st.container():
        st.markdown("#### 📅 Ejecución única")
        now_co = datetime.now(COLOMBIA_TZ)

        try:
            pending = get_once_run()
        except Exception as e:
            st.error(f"Error leyendo ejecución única: {e}")
            return

        if pending:
            st.info(
                f"Pendiente: **{pending['date']}** a las "
                f"**{pending['hour']:02d}:{pending['minute']:02d}** (hora de Colombia)"
            )
            if st.button("🗑 Cancelar ejecución única", key="saaf_once_cancel"):
                try:
                    clear_once_run()
                    st.success("Ejecución única cancelada.")
                    st.rerun()
                except Exception as e:
                    st.error(f"Error cancelando: {e}")

        col1, col2, col3 = st.columns([1.3, 1, 1])
        with col1:
            once_date = st.date_input(
                "Fecha (Colombia)",
                value=now_co.date(),
                min_value=now_co.date(),
                key="saaf_once_date",
            )
        with col2:
            once_hour = st.selectbox(
                "Hora",
                list(range(24)),
                index=now_co.hour,
                key="saaf_once_hour",
                format_func=lambda h: f"{h:02d}:00",
            )
        with col3:
            once_minute = st.selectbox(
                "Minuto", [0, 15, 30, 45], key="saaf_once_minute"
            )

        if st.button("📅 Programar ejecución única", use_container_width=True):
            run_at = datetime.combine(
                once_date, dtime(once_hour, once_minute), tzinfo=COLOMBIA_TZ
            )
            if run_at <= now_co:
                st.error(
                    "Esa fecha y hora ya pasaron (hora de Colombia: "
                    f"{now_co.strftime('%Y-%m-%d %H:%M')}). Elige una futura."
                )
            else:
                try:
                    set_once_run(once_date.strftime("%Y-%m-%d"), once_hour, once_minute)
                    st.success(
                        "Ejecución única guardada. El scheduler la toma "
                        "automáticamente en un máximo de 5 minutos. No cambia la "
                        "frecuencia diaria/semanal."
                    )
                    st.rerun()
                except Exception as e:
                    st.error(f"Error guardando: {e}")


def _trigger_all_audits():
    """
    Lanza la auditoría de todos los sitios en segundo plano (audit_runner).
    El guardia "ya hay un ciclo en curso" ahora consulta la BD (antes usaba
    st.session_state desde un hilo, donde no funcionaba) y el progreso se ve
    en el panel de estado de arriba.
    """
    started, msg = start_cycle()
    if not started:
        st.warning(msg)
        return
    request_refresh()  # el hilo tarda ~1 s en crear las filas PENDING
    st.info("⏳ **" + msg + "** El estado y el progreso se muestran en el panel de abajo.", icon="ℹ️")
    return