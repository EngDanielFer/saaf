#!/home/admin_ubuntu/Desktop/proyecto_saaf/opt/saaf/venv/bin/python
# =============================================================
# SAAF Pro — views/alerts.py
# Vista de alertas activas: resolver, omitir, filtrar y AGREGAR A LISTA
# PERMITIDA (pestaña "Lista permitida" para administrar las exclusiones).
# =============================================================

import streamlit as st
import sys
import html as _html

sys.path.insert(0, "/home/admin_ubuntu/Desktop/proyecto_saaf/opt/saaf")
sys.path.insert(0, "/home/admin_ubuntu/Desktop/proyecto_saaf/opt/saaf/scripts/python")

from database import (
    get_open_threats,
    get_all_sites,
    resolve_threat,
    ignore_threat,
    to_local_str,
    init_db,
)
from risk_signals import signals_from_json
from severity import SEVERITY_COLOR as SEV_COLOR, SEVERITY_ICON as SEV_ICON, SEVERITY_LEVELS
from views.allowlist_ui import (
    can_allowlist,
    render_allow_from_threat,
    render_allowlist_manager,
    show_flash,
)

THREAT_LABELS = {
    "casino_pharma_adult": "URL spam (casino/pharma/adult)",
    "hidden_spam_link": "Link spam oculto",
    "external_script": "Script externo desconocido",
    "hidden_iframe": "iFrame oculto",
    "obfuscated_js": "JavaScript ofuscado",
    "claude_anomaly": "Anomalía Claude API",
    "broken_internal_link": "Enlace a dominio antiguo",
}


def render():
    init_db()
    tab_alerts, tab_allow = st.tabs(["🚨 Alertas activas", "✅ Lista permitida"])
    with tab_alerts:
        _render_active_alerts()
    with tab_allow:
        render_allowlist_manager()
        

def _signals_caption(t):
    sigs = signals_from_json(t["signals"]) if "signals" in t.keys() else []
    if not sigs:
        return None
    parts = [("★ " if s.get("strong") else "") + s.get("label", "") for s in sigs if s.get("points", 0) > 0]
    trust = [s.get("label", "") for s in sigs if s.get("points", 0) < 0]
    txt = ""
    if parts:
        txt += "Señales de riesgo: " + "; ".join(parts[:6])
    if trust:
        txt += (" · " if txt else "") + "; ".join(trust)
    return txt or None


def _render_active_alerts():
    st.markdown("## 🚨 Alertas activas")
    show_flash()

    # Controles
    col_f1, col_f2, col_btn = st.columns([2, 2, 1])
    with col_f1:
        sev_filter = st.multiselect(
            "Severidad",
            list(reversed(SEVERITY_LEVELS)),
            default=["CRITICAL", "HIGH"],
        )
    with col_f2:
        sites = get_all_sites(active_only=True)
        site_names = ["Todos los sitios"] + [s["name"] for s in sites]
        site_sel = st.selectbox("Sitio", site_names, label_visibility="collapsed")
    with col_btn:
        if st.button("🔄 Actualizar", use_container_width=True):
            st.rerun()
    
    # Obtener alertas
    site_id_filter = None
    if site_sel != "Todos los sitios":
        match = next((s for s in sites if s["name"] == site_sel), None)
        if match:
            site_id_filter = match["id"]

    all_threats = get_open_threats(site_id_filter)
    filtered = (
        [t for t in all_threats if t["severity"] in sev_filter]
        if sev_filter
        else all_threats
    )

    # Métricas rápidas (INFO es informativo: no cuenta como alerta abierta)
    real = [t for t in all_threats if t["severity"] != "INFO"]
    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Total abiertas", len(real))
    c2.metric("🔴 Critical", sum(1 for t in all_threats if t["severity"] == "CRITICAL"))
    c3.metric("🟠 High", sum(1 for t in all_threats if t["severity"] == "HIGH"))
    c4.metric("🔵 Info", sum(1 for t in all_threats if t["severity"] == "INFO"))
    c5.metric("Mostrando", len(filtered))
    st.markdown("---")
    
    if not filtered:
        st.success("✅ No hay alertas activas con los filtros seleccionados.")
        return

    # Acciones en bloque
    col_sel, col_resolve = st.columns([3, 1])
    with col_resolve:
        if st.button("✅ Resolver todas visibles", use_container_width=True):
            for t in filtered:
                resolve_threat(t["id"])
            st.success(f"{len(filtered)} alertas resueltas")
            st.rerun()
            
    PAGE_SIZE = 25
    total = len(filtered)
    total_pages = max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE)
    if total > PAGE_SIZE:
        col_pg, col_info = st.columns([1, 3])
        with col_pg:
            page = st.number_input(
                "Página", min_value=1, max_value=total_pages, value=1, step=1,
                key="alerts_page",
            )
        with col_info:
            start_n = (page - 1) * PAGE_SIZE + 1
            end_n = min(page * PAGE_SIZE, total)
            st.caption(f"Mostrando {start_n}–{end_n} de {total} · página {page}/{total_pages}")
        start = (page - 1) * PAGE_SIZE
        page_alerts = filtered[start : start + PAGE_SIZE]
    else:
        page_alerts = filtered
    
    # Lista de alertas
    for t in page_alerts:
        sev = t["severity"]
        icon = SEV_ICON.get(sev, "⚪")
        color = SEV_COLOR.get(sev, "#666")
        label = THREAT_LABELS.get(t["threat_type"], t["threat_type"])
        allow_flag = f"allow_{t['id']}_open"

        with st.container():
            col_icon, col_site, col_sev, col_desc, col_actions = st.columns(
                [0.4, 1.8, 1.5, 3.5, 1.9]
            )

            with col_icon:
                st.markdown(
                    f"<span style='font-size:20px'>{icon}</span>",
                    unsafe_allow_html=True,
                )

            with col_site:
                st.markdown(f"**{t['site_name']}**")
                st.caption(to_local_str(t["detected_at"]))

            with col_sev:
                st.markdown(
                    f"<span style='color:{color};font-weight:600'>{sev}</span>",
                    unsafe_allow_html=True,
                )
                st.caption(label)
            
            with col_desc:
                st.caption(t["description"])
                if t["resource_url"]:
                    st.caption(f"📎 Recurso: {t['resource_url'][:110]}")
                if t["url_found"]:
                    st.caption(f"🔗 Página: {t['url_found'][:100]}")
                sig_txt = _signals_caption(t)
                if sig_txt:
                    st.caption(f"🔍 {sig_txt}")

            with col_actions:
                # Botón Aceptar (resolver — problema corregido)
                if st.button(
                    "✅ Aceptar",
                    key=f"res_{t['id']}",
                    help="Marcar como resuelto (problema corregido)",
                    use_container_width=True,
                ):
                    resolve_threat(t["id"])
                    st.rerun()

                # Botón Omitir (falso positivo — ignorar sin resolver)
                if st.button(
                    "🔕 Omitir",
                    key=f"ign_{t['id']}",
                    help="Omitir (falso positivo — no volverá a alertar)",
                    use_container_width=True,
                ):
                    ignore_threat(t["id"])
                    st.rerun()
                
                # Botón Agregar a lista permitida (solo si hay un recurso comparable)
                if can_allowlist(t) and st.button(
                    "➕ Agregar a lista permitida",
                    key=f"allowbtn_{t['id']}",
                    help="Marcar este recurso como legítimo: solo esta campaña o todas",
                    use_container_width=True,
                ):
                    # (sin st.rerun: el formulario se dibuja mas abajo en esta misma pasada)
                    st.session_state[allow_flag] = not st.session_state.get(allow_flag, False)

                # Botón Ver sitio
                if st.button(
                    "🔍 Ver",
                    key=f"view_{t['id']}",
                    help="Ver detalle del sitio",
                    use_container_width=True,
                ):
                    st.session_state["saaf_selected_site"] = t["site_id"]
                    st.session_state["saaf_page"] = "dashboard"
                    st.rerun()
                    
            if st.session_state.get(allow_flag):
                render_allow_from_threat(t)

            # Código sospechoso expandible — muestra el HTML exacto del hack
            if t["code_snippet"]:
                with st.expander("🔎 Ver código sospechoso detectado"):
                    safe = _html.escape(t["code_snippet"][:500])
                    st.markdown(
                        f'<div class="code-snippet">{safe}</div>',
                        unsafe_allow_html=True,
                    )

        st.divider()