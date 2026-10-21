#!/home/admin_ubuntu/Desktop/proyecto_saaf/opt/saaf/venv/bin/python
# =============================================================
# SAAF Pro — views/site_detail.py
# Detalle por sitio: historial, uptime, inspector de codigo,
# analisis Claude, metodo de rastreo, URLs analizadas
# =============================================================

import html as _html
import streamlit as st
import pandas as pd
from datetime import datetime
import re
import sys

sys.path.insert(0, "/home/admin_ubuntu/Desktop/proyecto_saaf/opt/saaf")
sys.path.insert(0, "/home/admin_ubuntu/Desktop/proyecto_saaf/opt/saaf/scripts/python")

from database import (
    get_site,
    get_site_audits,
    get_uptime_stats,
    get_uptime_history,
    get_all_threats,
    get_open_threats,
    is_site_currently_up,
    resolve_threat,
    ignore_threat,
    resolve_threats_bulk,
    ignore_threats_bulk,
    to_local_str,
    init_db,
)
from audit_runner import start_site_audit
from audit_state import STATUS_ICON, normalize_status
from risk_signals import signals_from_json
from severity import SEVERITY_COLOR as SEV_COLOR, SEVERITY_ICON as SEV_ICON
from views.allowlist_ui import can_allowlist, render_allow_from_threat, show_flash
from views.audit_panel import (
    auto_refresh_tail, render_audit_panel, request_refresh,
)

THREAT_LABELS = {
    "casino_pharma_adult": "URL spam",
    "hidden_spam_link": "Link spam oculto",
    "external_script": "Script externo",
    "hidden_iframe": "iFrame oculto",
    "obfuscated_js": "JS ofuscado",
    "claude_anomaly": "Anomalía Claude API",
    "broken_internal_link": "Enlace a dominio antiguo",
}

# =============================================================
# Helpers — interpretar amenazas en lenguaje claro
# =============================================================


def _extract_domain(url: str) -> str:
    """Extrae solo el dominio de una URL para mostrarlo compacto."""
    if not url:
        return ""
    try:
        from urllib.parse import urlparse

        parsed = urlparse(url)
        return parsed.netloc or url
    except Exception:
        return url


def _interpret_threat(t: dict) -> dict:
    """
    Convierte los campos técnicos de una amenaza en texto legible
    para las columnas Hallazgo y Detalle de la tabla de auditoría.

    Returns:
        dict con claves: hallazgo, detalle, codigo
    """
    ttype = t.get("threat_type", "")
    description = t.get("description", "")
    snippet = t.get("code_snippet", "") or ""
    url_found = t.get("url_found", "") or ""

    # ── Link spam oculto ─────────────────────────────────────
    if ttype == "hidden_spam_link":
        # Extraer dominio destino del campo description
        m_domain = re.search(r"dominio='([^']+)'", description)
        m_href = re.search(r"href='([^']+)'", description)
        m_texto = re.search(r"texto='([^']+)'", description)

        domain_str = (
            m_domain.group(1)
            if m_domain
            else _extract_domain(m_href.group(1) if m_href else "")
        )
        texto_str = m_texto.group(1) if m_texto else ""

        # Clasificar por categoría del dominio
        cat = _classify_domain(domain_str)
        hallazgo = f"Spam links de {cat} inyectados en footer"
        detalle = domain_str
        if texto_str:
            detalle += f' — texto: "{texto_str}"'

        return {"hallazgo": hallazgo, "detalle": detalle, "codigo": snippet[:300]}

    # ── URL spam en sitemap ───────────────────────────────────
    if ttype == "casino_pharma_adult":
        m_pat = re.search(r"Patron detectado: '([^']+)'", description)
        m_cat = re.search(r"Categoria: (.+)$", description, re.MULTILINE)
        patron = m_pat.group(1) if m_pat else ""
        cat = m_cat.group(1).strip() if m_cat else "spam"
        hallazgo = f"URL indexada con contenido spam ({cat})"
        detalle = f"Patrón detectado: '{patron}'" if patron else description[:80]
        return {"hallazgo": hallazgo, "detalle": detalle, "codigo": ""}

    # ── Script externo ────────────────────────────────────────
    if ttype == "external_script":
        m_dom = re.search(r"dominio (spam|unknown): ([^\s(]+)", description)
        m_src = re.search(r"src='([^']+)'", description)
        domain_str = m_dom.group(2) if m_dom else ""
        tipo = (
            "spam conocido" if (m_dom and m_dom.group(1) == "spam") else "desconocido"
        )
        hallazgo = f"Script externo de dominio {tipo}"
        detalle = domain_str or (m_src.group(1)[:80] if m_src else description[:80])
        return {"hallazgo": hallazgo, "detalle": detalle, "codigo": snippet[:200]}

    # ── iFrame oculto ─────────────────────────────────────────
    if ttype == "hidden_iframe":
        m_src = re.search(r"src='([^']+)'", description)
        src = m_src.group(1) if m_src else ""
        hallazgo = "iFrame oculto detectado"
        detalle = _extract_domain(src) if src else description[:80]
        return {"hallazgo": hallazgo, "detalle": detalle, "codigo": snippet[:200]}

    # ── JS ofuscado ───────────────────────────────────────────
    if ttype == "obfuscated_js":
        m_pat = re.search(r"patrones detectados: (.+)$", description)
        pats = m_pat.group(1) if m_pat else ""
        hallazgo = "JavaScript ofuscado / código sospechoso"
        detalle = f"Patrones: {pats}" if pats else description[:80]
        return {"hallazgo": hallazgo, "detalle": detalle, "codigo": snippet[:200]}

    # ── Anomalía Claude ───────────────────────────────────────
    if ttype == "claude_anomaly":
        hallazgo = "Anomalía detectada por análisis IA"
        detalle = description[:100]
        return {"hallazgo": hallazgo, "detalle": detalle, "codigo": snippet[:200]}
    
    # ── External script con dominio que parece el antiguo del sitio ────
    if ttype == "broken_internal_link":
        m_dest = re.search(r"dominio='([^']+)'", description)
        m_count = re.search(r"([0-9]+) enlaces?", description)
        domain_str = m_dest.group(1) if m_dest else description[:60]
        count_str  = f"{m_count.group(1)} enlaces de footer apuntan a" if m_count else "Enlace interno roto a"
        hallazgo = "Enlaces internos rotos a dominio antiguo"
        detalle  = f"{count_str} {domain_str} en lugar del dominio actual"
        return {"hallazgo": hallazgo, "detalle": detalle, "codigo": snippet[:200]}

    # Fallback genérico
    return {
        "hallazgo": THREAT_LABELS.get(ttype, ttype),
        "detalle": description[:100],
        "codigo": snippet[:200],
    }


def _classify_domain(domain: str) -> str:
    """Clasifica un dominio en una categoría legible."""
    d = domain.lower()
    if any(w in d for w in ["dreamword", "dreamsword", "thinkdream"]):
        return 'red "dreamwords"'
    if any(
        w in d
        for w in [
            "casino",
            "jackpot",
            "bet",
            "poker",
            "slot",
            "gambl",
            "spinamba",
            "dream",
        ]
    ):
        return "casino/gambling"
    if any(w in d for w in ["pharma", "viagra", "cialis", "pills", "meds", "drug"]):
        return "pharma"
    if any(w in d for w in ["porn", "xxx", "adult", "sex", "nude"]):
        return "adulto"
    if any(w in d for w in ["loan", "payday", "cash"]):
        return "préstamos"
    return "spam (link externo inyectado)"


def render(site_id: int):
    _render_impl(site_id)
    # Auto-refresco: debe ser lo ULTIMO de la pagina (sleep + st.rerun)
    auto_refresh_tail()


def _render_impl(site_id: int):
    init_db()

    site = get_site(site_id)
    if not site:
        st.error("Sitio no encontrado.")
        if st.button("← Volver al dashboard"):
            st.session_state["saaf_selected_site"] = None
            st.rerun()
        return

    # Header
    col_back, col_title, col_audit = st.columns([1, 6, 2])
    with col_back:
        if st.button("← Volver"):
            st.session_state["saaf_selected_site"] = None
            st.rerun()
    with col_title:
        is_up = is_site_currently_up(site_id)
        status = (
            "🟢 ACTIVO" if is_up else ("🔴 CAÍDO" if is_up is False else "⚪ Sin datos")
        )
        st.markdown(f"## {site['name']}")
        st.caption(f"{site['url']} · {site['niche']} · {status}")
    with col_audit:
        if st.button("▶ Auditar ahora", type="primary", use_container_width=True):
            _run_site_audit(site)

    show_flash()

    # --- Estado real de la auditoría de este sitio ---
    render_audit_panel(site_id=site_id, key=f"site_audit_{site_id}")

    st.markdown("---")

    # Tabs principales
    tab1, tab2, tab3, tab4 = st.tabs(
        ["📊 Resumen", "🔍 Amenazas", "📈 Uptime", "🕒 Auditorías"]
    )

    with tab1:
        _render_summary(site_id)

    with tab2:
        _render_threats(site_id)

    with tab3:
        _render_uptime(site_id)

    with tab4:
        _render_audits(site_id)


def _render_summary(site_id):
    uptime7 = get_uptime_stats(site_id, days=7)
    uptime30 = get_uptime_stats(site_id, days=30)
    open_t = get_open_threats(site_id)
    audits = get_site_audits(site_id, limit=1)
    last = audits[0] if audits else None

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Uptime 7 días", f"{uptime7}%" if uptime7 else "Sin datos")
    c2.metric("Uptime 30 días", f"{uptime30}%" if uptime30 else "Sin datos")
    c3.metric("Alertas abiertas", len(open_t))
    c4.metric("Última auditoría", to_local_str(last["started_at"]) if last else "Nunca")

    if last:
        st.markdown("**Última auditoría:**")
        cols = st.columns(4)
        cols[0].caption(f"Método: **{last['crawl_method'] or '—'}**")
        cols[1].caption(f"URLs analizadas: **{last['urls_analyzed']}**")
        cols[2].caption(f"Estado: **{STATUS_ICON.get(normalize_status(last['status']), '')} {last['status']}**")
        cols[3].caption(f"Severidad máx: **{last['severity_max'] or 'ninguna'}**")


# =============================================================
# Amenazas — tabla estilo imagen 2
# =============================================================


def _render_threats(site_id):
    # Controles
    col_filter, col_toggle, col_btns = st.columns([2, 2, 2])
    with col_filter:
        show = st.radio("Mostrar", ["Solo abiertas", "Todas"], horizontal=True)
    with col_toggle:
        view_mode = st.radio("Vista", ["📋 Tabla", "🔍 Detalle"], horizontal=True)
    with col_btns:
        st.caption("Haz clic en 'Resolver' para marcar una amenaza como corregida.")

    threats = (
        get_open_threats(site_id)
        if show == "Solo abiertas"
        else get_all_threats(site_id)
    )

    if not threats:
        st.success(
            "✅ No hay amenazas"
            + (" abiertas" if show == "Solo abiertas" else "")
            + " para este sitio."
        )
        return

    # Título del resultado con el dominio
    site = get_site(site_id)
    site_domaim = (
        site["url"].replace("https://", "").replace("http://", "").rstrip("/")
        if site
        else ""
    )
    criticos = sum(1 for t in threats if t["severity"] == "CRITICAL")
    altos = sum(1 for t in threats if t["severity"] == "HIGH")

    # Badges de resumen
    badge_html = ""
    if criticos:
        badge_html += f"<span style='background:#DC2626;color:white;padding:3px 10px;border-radius:12px;font-size:12px;font-weight:700;margin-right:6px'>🔴 {criticos} CRITICAL</span>"
    if altos:
        badge_html += f"<span style='background:#EA580C;color:white;padding:3px 10px;border-radius:12px;font-size:12px;font-weight:700;margin-right:6px'>🟠 {altos} HIGH</span>"
    otros = len(threats) - criticos - altos
    if otros:
        badge_html += f"<span style='background:#6B7280;color:white;padding:3px 10px;border-radius:12px;font-size:12px;font-weight:700'>{otros} otros</span>"
    if badge_html:
        st.markdown(badge_html, unsafe_allow_html=True)
    st.markdown("")

    # ── Selección en lote — aceptar/omitir varias amenazas a la vez ───
    # Disponible tanto en la vista Tabla como en Detalle, y con cualquier
    # filtro ("Solo abiertas"/"Todas") — la selección considera TODAS las
    # amenazas abiertas que coinciden con el filtro actual, no solo las
    # de la página visible.
    _render_bulk_actions(site_id, threats)
    st.markdown("")

    # ── Paginación — evita renderizar cientos de filas de golpe ───
    PAGE_SIZE = 25
    total = len(threats)
    total_pages = max(1, (total + PAGE_SIZE - 1) // PAGE_SIZE)

    if total > PAGE_SIZE:
        col_pg, col_info = st.columns([1, 3])
        with col_pg:
            page = st.number_input(
                "Página",
                min_value=1,
                max_value=total_pages,
                value=1,
                step=1,
                key=f"threat_page_{site_id}",
            )
        with col_info:
            start_n = (page - 1) * PAGE_SIZE + 1
            end_n = min(page * PAGE_SIZE, total)
            st.caption(f"Mostrando {start_n}–{end_n} de {total} amenazas · página {page}/{total_pages}")
        start = (page - 1) * PAGE_SIZE
        page_threats = threats[start : start + PAGE_SIZE]
    else:
        page_threats = threats

    # ── VISTA TABLA (imagen 2) ────────────────────────────────
    if view_mode == "📋 Tabla":
        _render_threats_table(page_threats, site_id)

    # ── VISTA DETALLE (imagen 1 mejorada) ────────────────────
    else:
        _render_threats_detail(page_threats, site_id)


def _render_bulk_actions(site_id, threats: list):
    """
    Barra de selección en lote: permite marcar varias amenazas abiertas
    (checkboxes en la tabla/detalle) y luego aceptarlas u omitirlas
    (falso positivo) todas de una sola vez.
    """
    sel_key = f"saaf_sel_threats_{site_id}"
    if sel_key not in st.session_state:
        st.session_state[sel_key] = set()
    selected = st.session_state[sel_key]

    # ids de amenazas abiertas (no resueltas ni ya omitidas) que coinciden
    # con el filtro actual — son las unicas seleccionables/accionables
    # NOTA: 'threats' llega como sqlite3.Row (no dict) — sqlite3.Row no
    # soporta .get(), solo indexado por clave (t["campo"]). Ambas columnas
    # son NOT NULL DEFAULT 0, asi que el indexado directo es seguro.
    open_ids = {t["id"] for t in threats if not t["resolved"] and not t["ignored"]}
    # Limpiar de la seleccion cualquier id que ya no este abierto (p.ej. se
    # resolvio desde otra pestaña/sesion, o cambio el filtro)
    selected.intersection_update(open_ids)

    st.caption("Selección en lote")
    with st.container():
        col_all, col_count, col_res, col_ign = st.columns([1.6, 1.6, 1.6, 2.2])
        with col_all:
            all_selected = bool(open_ids) and open_ids.issubset(selected)
            toggle_all = st.checkbox(
                f"Seleccionar todas ({len(open_ids)})",
                value=all_selected,
                key=f"saaf_selall_{site_id}",
            )
            if toggle_all and not all_selected:
                selected.update(open_ids)
                for tid in open_ids:
                    st.session_state[f"saaf_chk_{site_id}_{tid}"] = True
                st.rerun()
            elif not toggle_all and all_selected and open_ids:
                selected.clear()
                for tid in open_ids:
                    st.session_state[f"saaf_chk_{site_id}_{tid}"] = False
                st.rerun()
        with col_count:
            st.caption(f"**{len(selected)}** seleccionada(s)")
        with col_res:
            if st.button(
                "✅ Aceptar seleccionadas",
                use_container_width=True,
                disabled=not selected,
                key=f"saaf_bulk_res_{site_id}",
            ):
                resolve_threats_bulk(list(selected))
                selected.clear()
                st.success("Amenazas seleccionadas marcadas como corregidas.")
                st.rerun()
        with col_ign:
            if st.button(
                "🔕 Omitir seleccionadas (falso positivo)",
                use_container_width=True,
                disabled=not selected,
                key=f"saaf_bulk_ign_{site_id}",
            ):
                ignore_threats_bulk(list(selected))
                selected.clear()
                st.success(
                    "Amenazas seleccionadas omitidas — no volverán a aparecer en próximas ejecuciones."
                )
                st.rerun()



def _render_threats_table(threats: list, site_id):
    """
    Tabla estilo imagen 2:
    ☐ | Severidad | Hallazgo | URL afectada | Detalle | Acciones
    """
    sel_key = f"saaf_sel_threats_{site_id}"
    if sel_key not in st.session_state:
        st.session_state[sel_key] = set()
    selected = st.session_state[sel_key]

    # Cabecera
    hcols = st.columns([0.5, 1.1, 2.2, 2.0, 2.6, 1.5])
    headers = ["", "Severidad", "Hallazgo", "URL afectada", "Detalle", "Acciones"]
    for col, h in zip(hcols, headers):
        col.markdown(
            f"<span style='color:#94A3B8;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.05em'>{h}</span>",
            unsafe_allow_html=True,
        )
    st.markdown(
        "<hr style='border:none;border-top:2px solid #334155;margin:4px 0 0 0'>",
        unsafe_allow_html=True,
    )

    for _row in threats:
        t = dict(_row)
        interp = _interpret_threat(dict(t))
        sev = t["severity"]
        icon = SEV_ICON.get(sev, "")
        color = SEV_COLOR.get(sev, "#666")
        url = t["url_found"] or "—"
        url_short = url.replace("https://", "").replace("http://", "")
        url_display = url_short[:55] + "…" if len(url_short) > 55 else url_short
        resolved = t.get("resolved", 0)
        ignored = t.get("ignored", 0)

        st.markdown(
            "<hr style='border:none;border-top:1px solid #1E293B;margin:2px 0'>",
            unsafe_allow_html=True,
        )
        row = st.columns([0.5, 1.1, 2.2, 2.0, 2.6, 1.5])

        # Col 0 — checkbox de selección (solo para amenazas abiertas)
        with row[0]:
            if not resolved and not ignored:
                checked = st.checkbox(
                    "Seleccionar",
                    value=(t["id"] in selected),
                    key=f"saaf_chk_{site_id}_{t['id']}",
                    label_visibility="collapsed",
                )
                if checked:
                    selected.add(t["id"])
                else:
                    selected.discard(t["id"])

        # Col 1 — Severidad
        with row[1]:
            st.markdown(
                f"<div style='background:{color};color:white;padding:3px 8px;border-radius:6px;"
                f"font-size:11px;font-weight:700;display:inline-block;margin-top:4px'>"
                f"{icon} {sev}</div>",
                unsafe_allow_html=True,
            )
            if resolved:
                st.markdown(
                    "<small style='color:#16A34A'>✅ Resuelto</small>",
                    unsafe_allow_html=True,
                )
            elif ignored:
                st.markdown(
                    "<small style='color:#6B7280'>🔕 Omitido</small>",
                    unsafe_allow_html=True,
                )

        # Col 2 — Hallazgo
        with row[2]:
            st.markdown(
                f"<span style='font-size:13px;color:#E2E8F0'>{_html.escape(interp['hallazgo'])}</span>",
                unsafe_allow_html=True,
            )

        # Col 3 — URL afectada
        with row[3]:
            st.markdown(
                f"<code style='font-size:11px;background:#0F172A;color:#7DD3FC;"
                f"padding:2px 6px;border-radius:4px;word-break:break-all'>{_html.escape(url_display)}</code>",
                unsafe_allow_html=True,
            )

        # Col 4 — Detalle
        with row[4]:
            st.markdown(
                f"<span style='font-size:12px;color:#CBD5E1'>{_html.escape(interp['detalle'])}</span>",
                unsafe_allow_html=True,
            )
            if interp["codigo"]:
                codigo_short = interp["codigo"][:70]
                st.markdown(
                    f"<code style='font-size:10px;background:#0F172A;color:#93C5FD;"
                    f"padding:1px 5px;border-radius:3px;display:block;margin-top:4px;"
                    f"overflow:hidden;text-overflow:ellipsis;white-space:nowrap'>"
                    f"{_html.escape(codigo_short)}</code>",
                    unsafe_allow_html=True,
                )

        # Col 5 — Acciones
        with row[5]:
            if not resolved and not ignored:
                b1, b2, b3 = st.columns(3)
                with b1:
                    if st.button(
                        "✅",
                        key=f"tbl_res_{t['id']}",
                        help="Aceptar — problema corregido",
                    ):
                        resolve_threat(t["id"])
                        st.rerun()
                with b2:
                    if st.button(
                        "🔕", key=f"tbl_ign_{t['id']}", help="Omitir — falso positivo"
                    ):
                        ignore_threat(t["id"])
                        st.rerun()
                with b3:
                    if st.button(
                        "🔍", key=f"tbl_exp_{t['id']}", help="Ver código completo"
                    ):
                        key_exp = f"expand_{t['id']}"
                        st.session_state[key_exp] = not st.session_state.get(
                            key_exp, False
                        )

        # Código expandido bajo la fila
        if st.session_state.get(f"expand_{t['id']}") and interp["codigo"]:
            safe_code = _html.escape(interp["codigo"][:600])
            st.markdown(
                f"<div style='background:#0F172A;border:1px solid #334155;border-radius:6px;"
                f"padding:10px 14px;font-family:monospace;font-size:11px;color:#7DD3FC;"
                f"margin:4px 0 8px 0;overflow-x:auto;white-space:pre-wrap'>{safe_code}</div>",
                unsafe_allow_html=True,
            )

    st.markdown("")
    st.markdown(
        "<small style='color:#475569'>✅ Aceptar = problema corregido &nbsp;·&nbsp; "
        "🔕 Omitir = falso positivo &nbsp;·&nbsp; "
        "🔍 Ver código HTML exacto detectado</small>",
        unsafe_allow_html=True,
    )


def _render_threats_detail(threats: list, site_id):
    """
    Vista de detalle expandible por amenaza (mejorada respecto a imagen 1).
    Muestra todos los campos de forma estructurada.
    """
    sel_key = f"saaf_sel_threats_{site_id}"
    if sel_key not in st.session_state:
        st.session_state[sel_key] = set()
    selected = st.session_state[sel_key]

    for _row in threats:
        t = dict(_row)
        sev = t["severity"]
        color = SEV_COLOR.get(sev, "#666")
        icon = SEV_ICON.get(sev, "")
        label = THREAT_LABELS.get(t["threat_type"], t["threat_type"])
        resolved = t.get("resolved", 0)
        ignored = t.get("ignored", 0)
        interp = _interpret_threat(dict(t))

        prefix = "✅ " if resolved else ("🔕 " if ignored else "")
        with st.expander(
            f"{prefix}{label} — {icon} {sev} — {to_local_str(t['detected_at'])}",
            expanded=(not resolved and not ignored and sev in ("CRITICAL", "HIGH")),
        ):
            col_info, col_btn = st.columns([4, 1])

            with col_info:
                # Severidad badge
                st.markdown(
                    f"**Severidad:** "
                    f"<span style='color:{color};font-weight:700'>{icon} {sev}</span>",
                    unsafe_allow_html=True,
                )
                st.markdown(f"**Hallazgo:** {interp['hallazgo']}")
                st.markdown(f"**URL afectada:** `{t['url_found'] or '—'}`")
                if t.get("resource_url"):
                    st.markdown(f"**Recurso:** `{t['resource_url']}`")
                st.markdown(f"**Detalle:** {interp['detalle']}")
                _sigs = signals_from_json(t.get("signals"))
                if _sigs:
                    st.markdown("**Por qué esta severidad:**")
                    for _s in _sigs:
                        _mark = "★ " if _s.get("strong") else ""
                        _sign = "➖" if _s.get("points", 0) < 0 else "➕"
                        st.caption(f"{_sign} {_mark}{_s.get('label', '')} ({_s.get('points', 0):+d})")

                if interp["codigo"]:
                    st.markdown("**Código sospechoso detectado:**")
                    safe = _html.escape(interp["codigo"][:500])
                    st.markdown(
                        f'<div class="code-snippet">{safe}</div>',
                        unsafe_allow_html=True,
                    )

            if not resolved and not ignored and can_allowlist(t):
                _flag = f"allow_{t['id']}_open"
                if st.button("➕ Agregar a lista permitida", key=f"sd_allowbtn_{site_id}_{t['id']}"):
                    st.session_state[_flag] = not st.session_state.get(_flag, False)
                if st.session_state.get(_flag):
                    render_allow_from_threat(t, key_prefix=f"sd_allow_{site_id}")

            with col_btn:
                if not resolved and not ignored:
                    checked = st.checkbox(
                        "Seleccionar",
                        value=(t["id"] in selected),
                        key=f"saaf_chk_{site_id}_{t['id']}",
                    )
                    if checked:
                        selected.add(t["id"])
                    else:
                        selected.discard(t["id"])
                    if st.button(
                        "✅ Aceptar",
                        key=f"det_res_{t['id']}",
                        help="Problema corregido",
                        use_container_width=True,
                    ):
                        resolve_threat(t["id"])
                        st.rerun()
                    if st.button(
                        "🔕 Omitir",
                        key=f"det_ign_{t['id']}",
                        help="Falso positivo",
                        use_container_width=True,
                    ):
                        ignore_threat(t["id"])
                        st.rerun()
                elif resolved:
                    st.caption(
                        f"Resuelto: {to_local_str(t.get('resolved_at'), '%Y-%m-%d') if t.get('resolved_at') else '—'}"
                    )
                else:
                    st.caption(
                        f"Omitido: {to_local_str(t.get('ignored_at'), '%Y-%m-%d') if t.get('ignored_at') else '—'}"
                    )


# =============================================================
# Uptime
# =============================================================


def _render_uptime(site_id):
    st.markdown("### Historial de uptime")

    history = get_uptime_history(site_id, limit=100)
    if not history:
        st.info("No hay registros de uptime para este sitio.")
        return

    # Métricas rápidas
    up_count = sum(1 for h in history if h["is_up"])
    down_count = len(history) - up_count
    avg_rt = [h["response_time_ms"] for h in history if h["response_time_ms"]]
    avg_rt_val = round(sum(avg_rt) / len(avg_rt)) if avg_rt else None

    c1, c2, c3 = st.columns(3)
    c1.metric("Verificaciones UP", up_count)
    c2.metric("Verificaciones DOWN", down_count)
    c3.metric("Tiempo resp. promedio", f"{avg_rt_val}ms" if avg_rt_val else "—")

    # Tabla
    df = pd.DataFrame(
        [
            {
                "Fecha": to_local_str(h["checked_at"]),
                "Estado": "🟢 UP" if h["is_up"] else "🔴 DOWN",
                "Status code": str(h["status_code"]) if h["status_code"] else "—",
                "Resp. time (ms)": str(h["response_time_ms"]) if h["response_time_ms"] else "—",
                "Error": (h["error_msg"] or "")[:60],
            }
            for h in history
        ]
    )
    st.dataframe(df, use_container_width=True, hide_index=True)


# =============================================================
# Auditorías anteriores
# =============================================================


def _render_audits(site_id):
    st.markdown("### Historial de auditorías")

    audits = get_site_audits(site_id, limit=50)
    if not audits:
        st.info("No hay auditorías registradas para este sitio.")
        return

    PAGE_SIZE = 10
    total_pages = max(1, (len(audits) + PAGE_SIZE - 1) // PAGE_SIZE)
    page = st.number_input(
        "Página",
        min_value=1,
        max_value=total_pages,
        value=1,
        step=1,
        label_visibility="collapsed",
    )
    st.caption(f"Página {page} de {total_pages} ({len(audits)} auditorías)")

    start = (page - 1) * PAGE_SIZE
    for a in audits[start : start + PAGE_SIZE]:
        st_ = normalize_status(a["status"]) or a["status"]
        sev = a["severity_max"]
        label = (
            f"{STATUS_ICON.get(st_, '')} {a['started_at'][:16]} — {st_} — "
            f"{(SEV_ICON.get(sev, '') + ' ' + sev) if sev and sev != 'INFO' else 'sin amenazas'}"
        )
        with st.expander(label):
            cols = st.columns(4)
            cols[0].caption(f"Método: **{a['crawl_method'] or '—'}**")
            cols[1].caption(f"URLs: **{a['urls_analyzed']}**")
            cols[2].caption(f"Estado: **{st_}**")
            cols[3].caption(
                f"Fin: {a['finished_at'][:16] if a['finished_at'] else '—'}"
            )
            if st_ in ("PENDING", "RUNNING"):
                st.info(f"En curso — etapa: {a['current_stage'] or '—'} ({a['progress'] or 0}%)")
            if a["error_msg"]:
                (st.info if st_ == "CANCELLED" else st.error)(f"{st_} — {a['error_msg']}")
            if a["warnings"]:
                for w in str(a["warnings"]).splitlines():
                    st.warning(w)
            if a["allowlisted_count"]:
                st.caption(f"✅ {a['allowlisted_count']} recurso(s) reconocidos por la lista permitida")


# =============================================================
# Lanzar auditoría en background
# =============================================================


def _run_site_audit(site):
    """
    Lanza la auditoría en segundo plano (audit_runner). El guardia consulta la
    BD y la auditoría queda visible de inmediato (PENDING -> RUNNING) en el
    panel de estado; si algo falla queda FAILED con el motivo, nunca RUNNING.
    """
    started, msg, _aid = start_site_audit(site)
    if not started:
        st.warning(msg)
        return
    request_refresh()  # el hilo tarda ~1 s en pasar a RUNNING
    st.info(f"⏳ **{msg}** El progreso se muestra abajo y se actualiza solo.", icon="ℹ️")
