#!/home/admin_ubuntu/Desktop/proyecto_saaf/opt/saaf/venv/bin/python
# =============================================================
# SAAF Pro — views/allowlist_ui.py
# Interfaz de la LISTA PERMITIDA (exclusiones) — Mejoras_auditoria_y_alertas, #1
#   * render_allow_from_threat(): "Agregar a lista permitida" desde una alerta
#   * render_allowlist_manager(): alta / edicion / desactivar / eliminar
# Compatible con Streamlit 1.28 (sin st.dialog / st.popover).
# =============================================================

import sys

import streamlit as st

sys.path.insert(0, "/home/admin_ubuntu/Desktop/proyecto_saaf/opt/saaf")
sys.path.insert(0, "/home/admin_ubuntu/Desktop/proyecto_saaf/opt/saaf/scripts/python")

from allowlist import (
    MATCH_TYPES, MATCH_URL, SCOPE_GLOBAL, SCOPE_SITE, extract_resource_url,
)
from database import (
    add_allowlist_rule,
    apply_rule_to_open_threats,
    delete_allowlist_rule,
    get_all_sites,
    get_allowlist_rule,
    get_allowlist_rules,
    set_allowlist_rule_active,
    to_local_str,
    update_allowlist_rule,
)
from url_utils import split_url

THREAT_TYPE_LABELS = {
    "external_script": "Script externo",
    "hidden_iframe": "iFrame oculto",
    "hidden_spam_link": "Link oculto",
    "casino_pharma_adult": "URL spam",
    "broken_internal_link": "Enlace a dominio antiguo",
}
ANY_TYPE = "(cualquier tipo)"
_FLASH = "saaf_allowlist_flash"


def flash(msg, kind="success"):
    st.session_state[_FLASH] = (kind, msg)
    
    
def show_flash():
    item = st.session_state.pop(_FLASH, None)
    if item:
        getattr(st, item[0], st.info)(item[1])


def threat_resource(t):
    """Recurso (src/href) de una amenaza; reconstruido si es una amenaza antigua."""
    return t["resource_url"] or extract_resource_url(
        t["threat_type"], t["description"], t["code_snippet"], t["url_found"]
    )


def can_allowlist(t) -> bool:
    return bool(threat_resource(t))


def suggest_pattern(resource_url) -> str:
    """host + ruta, sin esquema ni query: 'm.me/lopezylopezabogado'."""
    host, path, _ = split_url(resource_url)
    if not host:
        return resource_url or ""
    return host + (path if path != "/" else "")


def _site_options():
    """{site_id: etiqueta unica}. El id evita ambiguedad si hay nombres repetidos."""
    sites = get_all_sites(active_only=False)
    return {s["id"]: f"{s['name']} (#{s['id']})" for s in sites}


def _labeled_select(label, options: dict, current=None, key=None, **kw):
    """
    selectbox que muestra etiquetas y devuelve la CLAVE elegida.
    Las opciones del widget son las etiquetas (sin format_func): es mas simple
    y AppTest de Streamlit 1.28 no reconstruye bien widgets con format_func.
    """
    keys, labels = list(options), list(options.values())
    idx = keys.index(current) if current in keys else 0
    chosen = st.selectbox(label, labels, index=idx, key=key, **kw)
    return keys[labels.index(chosen)]


def _type_select(key, current=None):
    """Devuelve el threat_type elegido o None (cualquier tipo)."""
    options = {None: ANY_TYPE, **THREAT_TYPE_LABELS}
    return _labeled_select(
        "Aplicar a", options, current=current, key=key,
        help="Opcional: limita la regla a un tipo de alerta.",
    )
    
    
# =============================================================
# Desde una alerta
# =============================================================


def render_allow_from_threat(t, key_prefix="allow"):
    """Mini-formulario para convertir una alerta en una exclusion."""
    res = threat_resource(t)
    key = f"{key_prefix}_{t['id']}"
    flag = f"{key}_open"
    with st.form(key):
        st.markdown("**Agregar a lista permitida**")
        st.caption(f"Recurso detectado: `{res}`")
        scope_label = st.radio(
            "¿Dónde se permite?",
            [f"Solo esta campaña ({t['site_name']})", "Todas las campañas"],
            key=f"{key}_scope",
            help="Una exclusión de campaña NO afecta a las demás campañas.",
        )
        c1, c2 = st.columns([1, 3])
        with c1:
            mtype = _labeled_select("Tipo", MATCH_TYPES, current=MATCH_URL, key=f"{key}_type")
        with c2:
            pattern = st.text_input(
                "URL, dominio, fragmento o patrón a ignorar",
                value=suggest_pattern(res), key=f"{key}_pattern",
                help="Puedes acortarlo para permitir toda una ruta o dominio, "
                     "p. ej. google.com/recaptcha/",
            )
        reason = st.text_input("Motivo (por qué es legítimo)", key=f"{key}_reason")
        same_type = st.checkbox(
            f"Solo para alertas de tipo «{THREAT_TYPE_LABELS.get(t['threat_type'], t['threat_type'])}»",
            value=False, key=f"{key}_samet",
        )
        apply_open = st.checkbox(
            "Aplicar también a las alertas abiertas que ya coinciden", value=True, key=f"{key}_apply"
        )
        b1, b2 = st.columns(2)
        save = b1.form_submit_button("💾 Guardar exclusión", type="primary", use_container_width=True)
        cancel = b2.form_submit_button("Cancelar", use_container_width=True)
    if cancel:
        st.session_state.pop(flag, None)
        st.rerun()
    if save:
        scope = SCOPE_SITE if scope_label.startswith("Solo") else SCOPE_GLOBAL
        try:
            rid = add_allowlist_rule(
                scope, pattern, mtype, site_id=t["site_id"] if scope == SCOPE_SITE else None,
                threat_type=t["threat_type"] if same_type else None,
                reason=reason, created_by="desde alerta", source_threat_id=t["id"],
            )
        except ValueError as e:
            st.error(str(e))
            return
        n = apply_rule_to_open_threats(rid) if apply_open else 0
        st.session_state.pop(flag, None)
        flash(
            f"Exclusión guardada ({'esta campaña' if scope == SCOPE_SITE else 'todas las campañas'})."
            + (f" {n} alerta(s) abierta(s) dejaron de mostrarse." if n else "")
            + " Las próximas auditorías reconocerán este recurso como permitido."
        )
        st.rerun()


# =============================================================
# Gestor completo
# =============================================================


def _rule_form(prefix, rule=None):
    """Formulario de alta/edicion. Devuelve (enviado, cancelado, datos)."""
    sites = _site_options()
    is_edit = rule is not None
    with st.form(f"{prefix}_form"):
        c1, c2 = st.columns([1, 1])
        with c1:
            # Opciones = etiquetas directas (sin format_func): AppTest 1.28 no
            # reconstruye bien un radio con format_func y claves crudas.
            lbl_global, lbl_site = "Todas las campañas (global)", "Una campaña concreta"
            scope_label = st.radio(
                "Alcance", [lbl_global, lbl_site],
                index=0 if not is_edit or rule["scope"] == SCOPE_GLOBAL else 1, key=f"{prefix}_scope",
            )
            scope = SCOPE_GLOBAL if scope_label == lbl_global else SCOPE_SITE
        with c2:
            site_id = _labeled_select(
                "Campaña (si el alcance es por campaña)", sites or {None: "—"},
                current=rule["site_id"] if is_edit else None, key=f"{prefix}_site",
            )
        c3, c4 = st.columns([1, 3])
        with c3:
            mtype = _labeled_select(
                "Tipo", MATCH_TYPES, current=rule["match_type"] if is_edit else MATCH_URL,
                key=f"{prefix}_mtype",
            )
        with c4:
            pattern = st.text_input(
                "URL, dominio, fragmento o patrón a ignorar",
                value=rule["pattern"] if is_edit else "", key=f"{prefix}_pattern",
                placeholder="google.com/recaptcha/   ·   https://m.me/mi-pagina",
            )
        c5, c6 = st.columns([1, 2])
        with c5:
            threat_type = _type_select(f"{prefix}_ttype", rule["threat_type"] if is_edit else None)
        with c6:
            reason = st.text_input(
                "Motivo (por qué se considera permitido)",
                value=(rule["reason"] or "") if is_edit else "", key=f"{prefix}_reason",
            )
        if mtype != MATCH_URL:
            st.caption("⚠️ Los fragmentos y patrones son más amplios que un dominio: úsalos solo si hace falta.")
        b1, b2 = st.columns(2)
        ok = b1.form_submit_button("💾 Guardar cambios" if is_edit else "➕ Agregar exclusión", type="primary", use_container_width=True)
        cancel = b2.form_submit_button("Cancelar", use_container_width=True) if is_edit else False
    return ok, cancel, dict(
        scope=scope, site_id=site_id if scope == SCOPE_SITE else None, match_type=mtype,
        pattern=pattern, threat_type=threat_type, reason=reason,
    )
    

def render_allowlist_manager():
    st.markdown("### ✅ Lista permitida")
    st.caption(
        "Recursos legítimos ya aprobados (Google, YouTube, reCAPTCHA, Messenger…). "
        "El auditor **sigue detectándolos**, pero al reconocerlos como aprobados ya no los "
        "presenta como riesgo. *Global* = todas las campañas · *Campaña* = solo ese sitio."
    )
    show_flash()
    
    with st.expander("➕ Agregar una exclusión", expanded=False):
        ok, _cancel, data = _rule_form("allow_new")
        if ok:
            try:
                rid = add_allowlist_rule(created_by="manual", **data)
                n = apply_rule_to_open_threats(rid)
                flash("Exclusión agregada." + (f" {n} alerta(s) abierta(s) dejaron de mostrarse." if n else ""))
                st.rerun()
            except ValueError as e:
                st.error(str(e))
    
    edit_id = st.session_state.get("allow_edit_id")
    if edit_id:
        rule = get_allowlist_rule(edit_id)
        if rule:
            st.markdown(f"#### ✏️ Editando exclusión #{edit_id}")
            ok, cancel, data = _rule_form("allow_edit", rule)
            if cancel:
                st.session_state.pop("allow_edit_id", None)
                st.rerun()
            if ok:
                try:
                    update_allowlist_rule(edit_id, **data)
                    st.session_state.pop("allow_edit_id", None)
                    flash("Exclusión actualizada.")
                    st.rerun()
                except ValueError as e:
                    st.error(str(e))
            st.divider()
            
    # --- filtros ---
    sites = _site_options()
    f1, f2, f3, f4 = st.columns([1.2, 1.6, 1.2, 2])
    with f1:
        scope_f = st.selectbox("Alcance", ["Todos", "Globales", "Por campaña"], key="allow_f_scope")
    with f2:
        site_f = _labeled_select("Campaña", {None: "Todas", **sites}, key="allow_f_site")
    with f3:
        state_f = st.selectbox("Estado", ["Todas", "Activas", "Desactivadas"], key="allow_f_state")
    with f4:
        q = st.text_input("Buscar", placeholder="dominio, motivo…", key="allow_f_q", label_visibility="visible")

    rules = get_allowlist_rules()
    rules = [r for r in rules if (
        (scope_f == "Todos" or (scope_f == "Globales") == (r["scope"] == SCOPE_GLOBAL))
        and (site_f is None or r["site_id"] == site_f)
        and (state_f == "Todas" or (state_f == "Activas") == bool(r["active"]))
        and (not q or q.lower() in f"{r['pattern']} {r['reason'] or ''} {r['site_name'] or ''}".lower())
    )]
    
    if not rules:
        st.info("No hay exclusiones con estos filtros. Agrega una arriba o desde una alerta con **Agregar a lista permitida**.")
        return
    
    st.caption(f"{len(rules)} exclusión(es)")
    for r in rules[:100]:
        rid = r["id"]
        with st.container():
            c_pat, c_scope, c_stats, c_act = st.columns([3.2, 2, 1.6, 2.4])
            with c_pat:
                badge = "🟢" if r["active"] else "⚪"
                st.markdown(f"{badge} `{r['pattern']}`")
                st.caption(
                    f"{MATCH_TYPES[r['match_type']]}"
                    + (f" · solo «{THREAT_TYPE_LABELS.get(r['threat_type'], r['threat_type'])}»" if r["threat_type"] else "")
                    + (f" · 📝 {r['reason']}" if r["reason"] else "")
                )
            with c_scope:
                st.markdown("🌐 **Global**" if r["scope"] == SCOPE_GLOBAL else f"🎯 **{r['site_name'] or 'campaña eliminada'}**")
                st.caption(f"Creada {to_local_str(r['created_at'])} · {r['created_by'] or 'manual'}")
            with c_stats:
                st.markdown(f"**{r['hit_count']}** aciertos")
                st.caption(f"Último: {to_local_str(r['last_hit_at']) if r['last_hit_at'] else 'nunca'}")
            with c_act:
                a1, a2, a3 = st.columns(3)
                with a1:
                    if st.button("⏸" if r["active"] else "▶", key=f"allow_tg_{rid}",
                                 help="Desactivar" if r["active"] else "Activar", use_container_width=True):
                        set_allowlist_rule_active(rid, not r["active"])
                        st.rerun()
                with a2:
                    if st.button("✏️", key=f"allow_ed_{rid}", help="Editar", use_container_width=True):
                        st.session_state["allow_edit_id"] = rid
                        st.rerun()
                with a3:
                    if st.button("🗑", key=f"allow_dl_{rid}", help="Eliminar", use_container_width=True):
                        st.session_state[f"allow_confirm_{rid}"] = True
                        st.rerun()
            if st.session_state.get(f"allow_confirm_{rid}"):
                st.warning("¿Eliminar esta exclusión? Las alertas que permitía volverán a mostrarse.")
                y, n = st.columns(2)
                if y.button("Sí, eliminar", key=f"allow_yes_{rid}", type="primary"):
                    delete_allowlist_rule(rid)
                    st.session_state.pop(f"allow_confirm_{rid}", None)
                    flash("Exclusión eliminada.")
                    st.rerun()
                if n.button("No", key=f"allow_no_{rid}"):
                    st.session_state.pop(f"allow_confirm_{rid}", None)
                    st.rerun()
        st.divider()
    if len(rules) > 100:
        st.caption("Mostrando las primeras 100. Usa los filtros para acotar.")