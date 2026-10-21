# =============================================================
# SAAF Pro — views/enhancements.py
# Pagina "Auditoría IA": reportes agrupados, autorizaciones de correccion,
# configuracion por campania (programacion, Teams/correo, IA, WordPress)
# y configuracion general (umbral de confianza).
#
# Pagina NUEVA: no modifica ninguna pantalla existente.
# =============================================================

import datetime as _dt
import re
import sys
from pathlib import Path

import streamlit as st

_BASE = Path(__file__).resolve().parent.parent
for _p in (str(_BASE), str(_BASE / "scripts" / "python")):
    if _p not in sys.path:
        sys.path.insert(0, _p)

from database import get_all_sites, init_db, to_local_str  # noqa: E402

from enhancements import config as cfgmod  # noqa: E402
from enhancements import distribution, history, pipeline, remediation, reporting, secrets_store, store  # noqa: E402
from enhancements import schedule as sched  # noqa: E402
from enhancements.wordpress import WPClient, WPError  # noqa: E402

SEV_ICON = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "⚪"}
STATE_UI = {"limpio": ("🟢", "Sin hallazgos relevantes"),
            "atencion": ("🟠", "Requiere atención"),
            "comprometido": ("🔴", "Posible compromiso")}
_MD_SPECIAL = re.compile(r"([\\`*_{}\[\]()#+!|<>~$])")


def _esc(text) -> str:
    """Texto proveniente del sitio auditado -> markdown inerte (sin enlaces ni formato)."""
    return _MD_SPECIAL.sub(r"\\\1", str(text or ""))


def _flash(kind: str = None, msg: str = None):
    """Mensaje que sobrevive a st.rerun()."""
    if kind:
        st.session_state["enh_flash"] = (kind, msg)
        return
    item = st.session_state.pop("enh_flash", None)
    if item:
        getattr(st, item[0], st.info)(item[1])


def _site_picker(key: str, sites):
    names = {s["id"]: f"{s['name']} — {s['url']}" for s in sites}
    sid = st.selectbox("Campaña", list(names), format_func=lambda i: names[i], key=key)
    return next(s for s in sites if s["id"] == sid)


# =============================================================
def render():
    init_db()
    st.markdown("## 🧠 Auditoría IA")
    if cfgmod.killed():
        st.warning("Las mejoras están desactivadas por el interruptor SAAF_ENHANCEMENTS=0 en saaf.env.")
        return
    try:
        store.ensure_schema()
    except Exception as e:  # noqa
        st.error(f"No se pudo preparar el almacenamiento de las mejoras: {e.__class__.__name__}")
        return

    _flash()
    sites = [dict(s) for s in get_all_sites()]
    if not sites:
        st.info("Aún no hay campañas registradas.")
        return

    try:
        n_pending = len(remediation.list_remediations(statuses=[remediation.PENDING]))
    except Exception:
        n_pending = 0
    tabs = st.tabs(["📊 Reportes", f"⏳ Autorizaciones ({n_pending})", "🏢 Campañas", "⚙️ General"])
    with tabs[0]:
        _tab_reports(sites)
    with tabs[1]:
        _tab_authorizations()
    with tabs[2]:
        _tab_campaigns(sites)
    with tabs[3]:
        _tab_general(sites)


# =============================================================
# Reportes
# =============================================================
def _tab_reports(sites):
    site = _site_picker("enh_rep_site", sites)
    rows = pipeline.list_reports(site_id=site["id"], limit=30)
    if not rows:
        st.info("Esta campaña todavía no tiene reportes. Se generan automáticamente al terminar cada auditoría.")
        return
    labels = {r["id"]: f"Auditoría #{r['audit_id']} — {to_local_str(r['created_at'])}" for r in rows}
    rid = st.selectbox("Reporte", list(labels), format_func=lambda i: labels[i], key="enh_rep_id")
    row = pipeline.get_report(report_id=rid)
    if not row:
        return
    rep = row["report"]
    f, an = rep["facts"], rep["analysis"]

    icon, text = STATE_UI.get(f["site_state"], ("🟠", ""))
    st.markdown(f"### {icon} {text}")
    s = f["summary"]
    cols = st.columns(6)
    for col, (k, lbl) in zip(cols, reporting.SUMMARY_LINES):
        col.metric(lbl, s.get(k, 0))
    extra = [f"{lbl}: **{s[k]}**" for k, lbl in reporting.EXTRA_LINES if s.get(k)]
    if extra:
        st.caption(" · ".join(extra))

    st.markdown("#### Análisis general")
    st.markdown(_esc(an.get("text", "")))
    for r in an.get("relationships") or []:
        st.markdown("• " + _esc(r))
    if an.get("error_human"):
        st.info(an["error_human"])
    st.caption("Redactado con IA" if an.get("ai_used") else "Análisis automático (reglas)")

    st.markdown("#### Problemas agrupados")
    if not f["groups"]:
        st.success("No hay alertas en esta auditoría.")
    for g in f["groups"]:
        head = (f"{SEV_ICON.get(g['severity'], '')} {g['label']} — {g['items']} elemento(s) · "
                f"{g['pages']} página(s) · confianza {g['confidence']}%")
        with st.expander(head):
            sts = " · ".join(f"{history.STATE_ICON.get(k, '')} {history.STATE_LABEL.get(k, k)}: {v}"
                             for k, v in g["statuses"].items() if k)
            if sts:
                st.caption(sts)
            st.dataframe(
                [{"Página": e["page"], "Recurso": reporting.defang(e["resource"]), "Confianza %": e["confidence"],
                  "Estado": history.STATE_LABEL.get(e["lifecycle"], e["lifecycle"] or ""),
                  "Corrección": remediation.STATUS_LABEL.get(e["action"], e["action"] or "—")}
                 for e in g["examples"]],
                hide_index=True, use_container_width=True)
            if g["items"] > len(g["examples"]):
                st.caption(f"Se muestran los {len(g['examples'])} de mayor confianza.")

    ext = f["external_links"]
    st.markdown("#### Enlaces externos")
    if ext["total"]:
        st.write(f"Se analizaron **{ext['total']}** dominios externos: **{ext['legit']}** coherentes con la "
                 f"actividad del sitio (registrados como válidos) y **{ext['review']}** requieren revisión.")
        if ext["review_list"]:
            st.dataframe([{"Dominio": reporting.defang(r["host"]), "Motivo": r["reason"],
                           "Confianza %": r["confidence"], "Páginas": ", ".join(r["pages"])}
                          for r in ext["review_list"]], hide_index=True, use_container_width=True)
        if ext["legit_hosts"]:
            with st.expander("Dominios reconocidos como válidos"):
                st.write(", ".join(reporting.defang(h) for h in ext["legit_hosts"]))
    else:
        st.caption("No se encontraron enlaces externos.")

    h = f["history"]
    st.markdown("#### Comparación con la auditoría anterior")
    if h.get("previous_audit_id"):
        st.caption(f"Comparado con la auditoría #{h['previous_audit_id']}.")
    else:
        st.caption("Es la primera auditoría analizada de esta campaña: todo se considera nuevo.")
    for key, lbl in (("new_examples", "🆕 Nuevos"), ("persistent_examples", "♻️ Persistentes"),
                     ("reopened_examples", "🔁 Reabiertos"), ("resolved_examples", "✅ Resueltos")):
        if h.get(key):
            st.markdown(f"**{lbl}:** " + _esc(", ".join(h[key])))
    if s.get("unverified"):
        st.caption(f"{s['unverified']} hallazgo(s) no aparecieron esta vez pero no se pudo verificar la página, "
                   "así que no se cuentan como resueltos.")

    if f["pending"]:
        st.markdown("#### Pendientes de autorización")
        st.dataframe([{"Página": p["page"], "Categoría": p["category"], "Confianza %": p["confidence"],
                       "Acción": cfgmod.ACTIONS.get(p["action"], {}).get("label", p["action"]), "Motivo": p["reason"]}
                      for p in f["pending"]], hide_index=True, use_container_width=True)
        st.caption("Se resuelven en la pestaña «Autorizaciones».")

    st.markdown("#### Envío del reporte")
    if row["dispatch"]:
        for d in row["dispatch"]:
            st.write(("✅ " if d["ok"] else "❌ ") + f"{d['channel']} {d['target'] if d['channel'] == 'email' else ''}"
                     + (f" — {_esc(d['error'])}" if d.get("error") else ""))
    else:
        st.caption("Este reporte no se envió (la campaña no tiene Teams/correo configurados o se envía en un día programado).")

    c1, c2, _ = st.columns([1, 1, 2])
    with c1:
        if st.button("📤 Enviar este reporte ahora", key=f"enh_send_{rid}"):
            res = distribution.dispatch(site["id"], rep, force=True)
            if not res:
                _flash("warning", "La campaña no tiene Teams ni correos configurados (pestaña «Campañas» → Reportes).")
            else:
                from database import get_conn
                with get_conn() as conn:
                    conn.execute("UPDATE enh_reports SET dispatch=? WHERE id=?", (store.jdump(res), rid))
                bad = [d for d in res if not d["ok"]]
                _flash("error" if bad else "success",
                       "Hubo errores en el envío; revisa el detalle." if bad else "Reporte enviado.")
            st.rerun()
    with c2:
        st.download_button("⬇️ Descargar (HTML)", data=reporting.render_html(rep),
                           file_name=f"reporte_saaf_auditoria_{row['audit_id']}.html", mime="text/html",
                           key=f"enh_dl_{rid}")

    log = remediation.list_remediations(site_id=site["id"], limit=50)
    if log:
        with st.expander(f"Registro de correcciones de esta campaña ({len(log)})"):
            st.dataframe([{"Fecha": to_local_str(r["updated_at"]),
                           "Acción": cfgmod.ACTIONS.get(r["action"], {}).get("label", r["action"]),
                           "Página": r["target_url"], "Confianza %": r["confidence"],
                           "Resultado": remediation.STATUS_LABEL.get(r["status"], r["status"]),
                           "Detalle": r["message"]} for r in log], hide_index=True, use_container_width=True)


# =============================================================
# Autorizaciones
# =============================================================
def _tab_authorizations():
    st.caption("La confianza de la IA y el permiso para actuar son cosas distintas: aquí aparece todo lo que el "
               "sistema NO se atreve a corregir solo. Nada se modifica en WordPress hasta que lo autorices.")
    pend = remediation.list_remediations(statuses=[remediation.PENDING])
    if not pend:
        st.success("No hay correcciones pendientes de autorización.")
    for r in pend:
        label = cfgmod.ACTIONS.get(r["action"], {}).get("label", r["action"])
        with st.container(border=True):
            st.markdown(f"**{_esc(r['site_name'])}** — {label}  \n"
                        f"Página: `{r['target_url']}`" + (f"  \nRecurso: `{reporting.defang(r['resource_url'])}`" if r["resource_url"] else ""))
            st.caption(f"Confianza {r['confidence']}% (umbral {r['threshold']}%) · {_esc(r['message'])}")
            c1, c2, _ = st.columns([1, 1, 3])
            if c1.button("✅ Autorizar", key=f"enh_auth_{r['id']}"):
                res = remediation.authorize(r["id"])
                _flash("success" if res["ok"] else "error", res["message"])
                st.rerun()
            if c2.button("🚫 Rechazar", key=f"enh_rej_{r['id']}"):
                res = remediation.reject(r["id"])
                _flash("success" if res["ok"] else "error", res["message"])
                st.rerun()

    st.markdown("#### Correcciones aplicadas (se pueden revertir)")
    done = remediation.list_remediations(statuses=[remediation.APPLIED], limit=50)
    if not done:
        st.caption("Todavía no se ha aplicado ninguna corrección.")
    for r in done:
        c1, c2 = st.columns([5, 1])
        c1.markdown(f"{_esc(r['site_name'])} · {cfgmod.ACTIONS.get(r['action'], {}).get('label', r['action'])} · "
                    f"`{r['target_url']}` · {to_local_str(r['updated_at'])}")
        if c2.button("↩️ Revertir", key=f"enh_rev_{r['id']}"):
            res = remediation.revert(r["id"])
            _flash("success" if res["ok"] else "error", res["message"])
            st.rerun()


# =============================================================
# Campanias
# =============================================================
def _time_to_hm(t):
    return t.hour, t.minute


def _tab_campaigns(sites):
    site = _site_picker("enh_cfg_site", sites)
    sid = site["id"]
    cfg = cfgmod.get_site_config(sid)
    t_sched, t_rep, t_ai, t_wp = st.tabs(["🗓️ Programación", "📨 Reportes", "🤖 IA", "🔧 WordPress"])

    # ---------------- Programacion
    with t_sched:
        sc = cfg["schedule"]
        st.caption("Define cuándo se audita ESTA campaña. Con «ciclo general» todo sigue como antes.")
        with st.form(f"enh_f_sched_{sid}"):
            opts = {"global": "Seguir el ciclo general del scheduler (como hasta ahora)",
                    "custom": "Programación propia (días y hora)",
                    "off": "Sin auditoría automática (solo manual)"}
            cur = "off" if not sc["auto_enabled"] else sc["mode"]
            mode = st.radio("Modo", list(opts), index=list(opts).index(cur), format_func=lambda k: opts[k])
            days = st.multiselect("Días", list(cfgmod.WEEKDAYS), default=sc["days"],
                                  format_func=lambda d: cfgmod.WEEKDAY_LABELS[d])
            tm = st.time_input("Hora (Colombia)", value=_dt.time(sc["hour"], sc["minute"]))
            if st.form_submit_button("Guardar programación"):
                if mode == "custom" and not days:
                    st.error("Elige al menos un día.")
                else:
                    h, m = _time_to_hm(tm)
                    cfgmod.set_site_config(sid, {"schedule": {
                        "mode": "global" if mode == "off" else mode, "auto_enabled": mode != "off",
                        "days": days or list(cfgmod.WEEKDAYS), "hour": h, "minute": m}})
                    _flash("success", "Programación guardada.")
                    st.rerun()
        st.info("Actual: " + sched.describe_schedule(cfgmod.get_site_config(sid)["schedule"]))

    # ---------------- Reportes
    with t_rep:
        rc = cfg["report"]
        st.caption("A dónde y cuándo se envía el reporte. Es independiente de la frecuencia de auditoría.")
        with st.form(f"enh_f_rep_{sid}"):
            teams_on = st.checkbox("Enviar a Microsoft Teams", value=rc["teams_enabled"])
            has_hook = cfgmod.has_teams_webhook(sid)
            hook = st.text_input("URL del webhook de Teams / flujo de Power Automate", type="password",
                                 placeholder="Guardado ✔ — deja vacío para conservarlo" if has_hook else "https://...")
            drop_hook = st.checkbox("Borrar el webhook guardado") if has_hook else False
            mail_on = st.checkbox("Enviar por correo", value=rc["email_enabled"])
            emails = st.text_area("Correos (uno o varios, separados por coma o salto de línea)",
                                  value="\n".join(rc["emails"]))
            rmode = st.radio("Cuándo enviar", ["after_each_audit", "scheduled"],
                             index=0 if rc["mode"] == "after_each_audit" else 1,
                             format_func=lambda k: "Después de cada auditoría" if k == "after_each_audit"
                             else "En días y hora específicos (independiente de la auditoría)")
            rdays = st.multiselect("Días de envío", list(cfgmod.WEEKDAYS), default=rc["days"],
                                   format_func=lambda d: cfgmod.WEEKDAY_LABELS[d])
            rtm = st.time_input("Hora de envío (Colombia)", value=_dt.time(rc["hour"], rc["minute"]))
            only_imp = st.checkbox("Enviar solo si hay alertas importantes o pendientes de autorización",
                                   value=rc["only_if_important"])
            if st.form_submit_button("Guardar reportes"):
                bad = cfgmod.invalid_emails(emails)
                if bad:
                    st.error("Correos con formato inválido: " + ", ".join(bad))
                elif hook.strip() and not distribution.valid_webhook(hook.strip()):
                    st.error("El webhook debe empezar con https://")
                elif rmode == "scheduled" and not rdays:
                    st.error("Elige al menos un día de envío.")
                else:
                    if hook.strip():
                        cfgmod.set_teams_webhook(sid, hook.strip())
                    elif drop_hook:
                        cfgmod.clear_teams_webhook(sid)
                    h, m = _time_to_hm(rtm)
                    cfgmod.set_site_config(sid, {"report": {
                        "teams_enabled": teams_on, "email_enabled": mail_on, "emails": cfgmod.parse_emails(emails),
                        "mode": rmode, "days": rdays or ["mon"], "hour": h, "minute": m, "only_if_important": only_imp}})
                    _flash("success", "Configuración de reportes guardada.")
                    st.rerun()
        c1, c2, c3 = st.columns(3)
        if c1.button("Probar Teams", key=f"enh_tt_{sid}"):
            ok, err = distribution.test_teams(sid)
            st.success("Mensaje de prueba enviado a Teams.") if ok else st.error(err)
        if c2.button("Probar correo", key=f"enh_tm_{sid}"):
            to = cfgmod.get_site_config(sid)["report"]["emails"]
            if not to:
                st.error("Guarda al menos un correo primero.")
            else:
                errs = []
                for addr in to:
                    ok, err = distribution.send_email(addr, "SAAF Pro — prueba de correo",
                                                      "Si recibes este mensaje, los reportes de esta campaña llegarán a este correo.")
                    if not ok:
                        errs.append(f"{addr}: {err}")
                st.error("; ".join(errs)) if errs else st.success("Correo de prueba enviado a " + ", ".join(to))
        if c3.button("Enviar último reporte", key=f"enh_tl_{sid}"):
            last = pipeline.get_report(site_id=sid)
            if not last:
                st.warning("Esta campaña aún no tiene reportes.")
            else:
                res = distribution.dispatch(sid, last["report"], force=True)
                if not res:
                    st.warning("No hay Teams ni correos configurados.")
                for d in res:
                    st.write(("✅ " if d["ok"] else "❌ ") + f"{d['channel']} {d['target'] if d['channel'] == 'email' else ''} "
                             + _esc(d.get("error") or ""))
        ok, why = distribution.email_ready()
        if not ok:
            st.caption("ℹ️ " + why)

    # ---------------- IA
    with t_ai:
        ac = cfg["ai"]
        with st.form(f"enh_f_ai_{sid}"):
            langs = st.text_input("Idiomas esperados en el sitio (códigos, p. ej. es, en)",
                                  value=", ".join(ac["expected_languages"]),
                                  help="Vacío = se infiere de la página de inicio. Las páginas en otro idioma se agrupan como alerta.")
            ctx = st.text_area("Contexto del negocio (ayuda a la IA a distinguir enlaces legítimos)",
                               value=ac["business_context"], max_chars=1000,
                               placeholder="Ej.: Empresa de cercas y cerramientos en Cali; enlaza a la Alcaldía y a entidades de permisos.")
            own = st.checkbox("Usar un umbral de confianza propio para esta campaña", value=ac["threshold"] is not None)
            thr = st.slider("Umbral propio (%)", 0, 100, ac["threshold"] if ac["threshold"] is not None else cfgmod.get_global()["threshold"])
            if st.form_submit_button("Guardar"):
                cfgmod.set_site_config(sid, {"ai": {"expected_languages": langs, "business_context": ctx,
                                                     "threshold": thr if own else None}})
                _flash("success", "Configuración de IA guardada.")
                st.rerun()
        st.caption(f"Umbral efectivo: {cfgmod.effective_threshold(cfgmod.get_site_config(sid))}%")

    # ---------------- WordPress
    with t_wp:
        wc = cfg["wp"]
        st.caption("Credenciales del bot de WordPress. Recomendado: un usuario con rol Editor, contraseña de "
                   "aplicación (Usuarios → Perfil) y sitio con HTTPS. La contraseña nunca se muestra ni se registra.")
        if not secrets_store.encryption_available():
            st.warning("Los secretos se guardan en un archivo con permisos restringidos, SIN cifrar. Para cifrarlos: "
                       "`pip install cryptography` y define SAAF_SECRET_KEY en saaf.env.")
        with st.form(f"enh_f_wp_{sid}"):
            en = st.checkbox("Habilitar conexión con WordPress", value=wc["enabled"])
            url = st.text_input("URL del sitio WordPress", value=wc["base_url"] or site["url"])
            user = st.text_input("Usuario del bot", value=wc["username"])
            has_pw = cfgmod.has_wp_password(sid)
            pw = st.text_input("Contraseña de aplicación", type="password",
                               placeholder="Guardada ✔ — deja vacío para conservarla" if has_pw else "xxxx xxxx xxxx xxxx xxxx xxxx")
            drop_pw = st.checkbox("Borrar la contraseña guardada") if has_pw else False
            st.markdown("**Qué puede hacer el bot**")
            allowed = st.multiselect("Acciones permitidas", list(cfgmod.ACTIONS), default=wc["allowed_actions"],
                                     format_func=lambda a: cfgmod.ACTIONS[a]["label"] + (" (siempre pide autorización)" if cfgmod.ACTIONS[a]["sensitive"] else ""))
            auto = st.checkbox("Corregir automáticamente cuando la confianza supere el umbral y no sea una acción sensible",
                               value=wc["auto_fix"])
            dry = st.checkbox("Modo simulación (registra lo que haría, sin modificar el sitio)", value=wc["dry_run"])
            if st.form_submit_button("Guardar WordPress"):
                if url.strip() and not url.strip().lower().startswith("https://"):
                    st.warning("La URL no usa HTTPS: las credenciales viajarían sin cifrar.")
                if pw.strip():
                    cfgmod.set_wp_password(sid, pw.strip())
                elif drop_pw:
                    cfgmod.clear_wp_password(sid)
                cfgmod.set_site_config(sid, {"wp": {"enabled": en, "base_url": url, "username": user,
                                                     "allowed_actions": allowed, "auto_fix": auto, "dry_run": dry}})
                _flash("success", "Configuración de WordPress guardada.")
                st.rerun()
        if cfg["wp"]["auto_fix"] and not cfg["wp"]["dry_run"]:
            st.warning("Esta campaña corrige automáticamente y SIN simulación.")
        if st.button("🔌 Probar conexión", key=f"enh_wptest_{sid}"):
            w = cfgmod.get_site_config(sid)["wp"]
            pwd = cfgmod.get_wp_password(sid)
            if not (w["base_url"] and w["username"] and pwd):
                st.error("Guarda primero la URL, el usuario y la contraseña de aplicación.")
            else:
                try:
                    res = WPClient(w["base_url"], w["username"], pwd).test()
                    for name, ok, detail in res["steps"]:
                        st.write(("✅ " if ok else "❌ ") + f"{name}: {_esc(detail)}")
                    (st.success if res["ok"] else st.error)(_esc(res.get("message", "")))
                except WPError as e:
                    st.error(_esc(str(e)))


# =============================================================
# General
# =============================================================
def _tab_general(sites):
    g = cfgmod.get_global()
    st.caption("La confianza de la IA nunca autoriza por sí sola una acción destructiva: el umbral solo decide "
               "qué se corrige automáticamente cuando la campaña lo permite y la acción no es sensible.")
    with st.form("enh_f_global"):
        enabled = st.checkbox("Mejoras activadas", value=g["enabled"])
        thr = st.slider("Umbral de confianza por defecto (%)", 0, 100, g["threshold"],
                        help="Predeterminado: 70. Cada campaña puede tener el suyo.")
        ai = st.checkbox("Usar IA (requiere ANTHROPIC_API_KEY)", value=g["ai_enabled"])
        mx = st.number_input("Máximo de correcciones automáticas por auditoría", 0, 500, g["max_auto_actions"])
        mn = st.slider("Confianza mínima para pedir autorización (%)", 0, 100, g["min_auth_confidence"],
                       help="Por debajo de este valor el hallazgo solo se informa, sin solicitud.")
        lg = st.checkbox("Reflejar en las alertas originales los enlaces que la IA juzgó legítimos (severidad baja)",
                         value=g["apply_legit_to_alerts"],
                         help="Apagado por defecto: las alertas del sistema original no se tocan.")
        if st.form_submit_button("Guardar configuración general"):
            cfgmod.set_global(enabled=enabled, threshold=thr, ai_enabled=ai, max_auto_actions=int(mx),
                              min_auth_confidence=mn, apply_legit_to_alerts=lg)
            _flash("success", "Configuración general guardada.")
            st.rerun()

    st.markdown("#### Estado del entorno")
    try:
        from claude_analyzer import _load_api_key
        has_key = bool(_load_api_key())
    except Exception:
        has_key = False
    ok_mail, why = distribution.email_ready()
    st.write(("✅" if has_key else "⚠️") + " Clave de IA (ANTHROPIC_API_KEY): " + ("configurada" if has_key else "no configurada; se usan solo reglas"))
    st.write(("✅" if ok_mail else "⚠️") + " Correo SMTP: " + ("listo" if ok_mail else why))
    st.write(("✅" if secrets_store.encryption_available() else "⚠️") + " Secretos cifrados: "
             + ("sí" if secrets_store.encryption_available() else "no (archivo con permisos restringidos)"))

    st.markdown("#### Resumen por campaña")
    rows = []
    for s in sites:
        c = cfgmod.get_site_config(s["id"])
        rows.append({"Campaña": s["name"], "Auditoría": sched.describe_schedule(c["schedule"]),
                     "Reportes": ("Teams " if c["report"]["teams_enabled"] else "") + ("Correo" if c["report"]["email_enabled"] and c["report"]["emails"] else "") or "—",
                     "Envío": "Tras cada auditoría" if c["report"]["mode"] == "after_each_audit"
                     else f"{sched.describe_days(c['report']['days'])} {c['report']['hour']:02d}:{c['report']['minute']:02d}",
                     "WordPress": "Sí" if c["wp"]["enabled"] else "No",
                     "Corrección": "Automática" + (" (simulación)" if c["wp"]["dry_run"] else "") if c["wp"]["auto_fix"] else "Solo con autorización",
                     "Umbral %": cfgmod.effective_threshold(c, g)})
    st.dataframe(rows, hide_index=True, use_container_width=True)
