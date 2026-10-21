#!/home/admin_ubuntu/Desktop/proyecto_saaf/opt/saaf/venv/bin/python
# =============================================================
# SAAF Pro — views/settings.py
# Configuracion: sitios, dominios spam, alertas, reportes, log ciclo
# =============================================================

import streamlit as st
import sys

sys.path.insert(0, "/home/admin_ubuntu/Desktop/proyecto_saaf/opt/saaf")
sys.path.insert(0, "/home/admin_ubuntu/Desktop/proyecto_saaf/opt/saaf/scripts/python")

from database import (
    get_all_sites,
    upsert_site,
    delete_site,
    get_site,
    get_spam_domains,
    add_spam_domain,
    delete_spam_domain,
    get_cycle_logs,
    get_reports,
    get_schedule_config,
    WEEKDAY_LABELS,
    to_local_str,
    init_db,
)

_CSV_PATH = "/home/admin_ubuntu/Desktop/proyecto_saaf/opt/saaf/config/sites.csv"


def render():
    init_db()
    st.markdown("## ⚙️ Configuración")

    tab1, tab2, tab3, tab4 = st.tabs(
        [
            "🌐 Sitios",
            "🚫 Dominios spam",
            "📧 Alertas",
            "📋 Reportes y logs",
        ]
    )

    with tab1:
        _render_sites()
    with tab2:
        _render_spam_domains()
    with tab3:
        _render_alerts_config()
    with tab4:
        _render_reports_logs()


# =============================================================
# Gestión de sitios
# =============================================================


def _render_sites():
    st.markdown("### Sitios monitoreados")

    sites = get_all_sites()

    if sites:
        for s in sites:
            with st.expander(
                f"{'🟢' if s['active'] else '⚫'} {s['name']} — {s['url']}"
            ):
                with st.form(key=f"edit_site_{s['id']}"):
                    c1, c2 = st.columns(2)
                    with c1:
                        name = st.text_input("Nombre", value=s["name"])
                        url = st.text_input("URL", value=s["url"])
                        sitemap = st.text_input(
                            "Sitemap URL", value=s["sitemap_url"] or ""
                        )
                    with c2:
                        niche = st.text_input("Nicho", value=s["niche"])
                        priority = st.selectbox(
                            "Prioridad",
                            ["high", "normal", "low"],
                            index=["high", "normal", "low"].index(s["priority"]),
                        )
                        active = st.checkbox("Activo", value=bool(s["active"]))
                        _sd = dict(s)
                        old_domains = st.text_input(
                            "Dominios antiguos (separados por coma)",
                            value=_sd.get("old_domains") or "",
                            help="Dominios previos del sitio. Detecta links rotos que aún apuntan al dominio viejo. Ej: alexas-enterprise.com",
                            key=f"old_dom_{s['id']}",
                        )

                    col_save, col_del = st.columns(2)
                    with col_save:
                        if st.form_submit_button(
                            "💾 Guardar", use_container_width=True
                        ):
                            try:
                                upsert_site(
                                    name,
                                    url,
                                    sitemap or None,
                                    niche,
                                    priority,
                                    active,
                                    old_domains=old_domains or None,
                                )
                                st.success("Sitio actualizado")
                                st.rerun()
                            except Exception as e:
                                st.error(f"Error actualizando sitio: {e}")
                    with col_del:
                        if st.form_submit_button(
                            "🗑️ Eliminar", use_container_width=True
                        ):
                            delete_site(s["id"])
                            st.warning(f"Sitio '{s['name']}' eliminado")
                            st.rerun()

    st.markdown("---")
    st.markdown("### Agregar nuevo sitio")
    with st.form("add_site_form"):
        c1, c2 = st.columns(2)
        with c1:
            new_name = st.text_input("Nombre *")
            new_url = st.text_input("URL * (https://...)")
            new_sitemap = st.text_input("Sitemap URL (opcional)")
        with c2:
            new_niche = st.text_input("Nicho", value="general")
            new_priority = st.selectbox("Prioridad", ["high", "normal", "low"], index=1)
            new_old_domains = st.text_input(
                "Dominios antiguos (separados por coma)",
                help="Opcional. Dominios previos del sitio para detectar links rotos. Ej: alexas-enterprise.com",
            )

        if st.form_submit_button(
            "➕ Agregar sitio", use_container_width=True, type="primary"
        ):
            if not new_name or not new_url:
                st.error("Nombre y URL son obligatorios")
            elif not new_url.startswith(("http://", "https://")):
                st.error("La URL debe comenzar con http:// o https://")
            else:
                try:
                    upsert_site(
                        new_name,
                        new_url,
                        new_sitemap or None,
                        new_niche,
                        new_priority,
                        True,
                        old_domains=new_old_domains or None,
                    )
                    # Sincronizar con sites.csv
                    # Sincronizar con sites.csv si existe
                    try:
                        from pathlib import Path
                        import csv

                        csv_path = Path(_CSV_PATH)
                        if csv_path.exists():
                            with open(csv_path, "a", newline="", encoding="utf-8") as f:
                                w = csv.writer(f)
                                w.writerow(
                                    [
                                        new_name,
                                        new_url,
                                        new_sitemap or "",
                                        new_niche,
                                        new_priority,
                                        "true",
                                    ]
                                )
                    except Exception:
                        pass  # CSV sync es opcional — la BD es la fuente de verdad
                    st.success(f"Sitio '{new_name}' agregado")
                    st.rerun()
                except Exception as e:
                    st.error(f"Error: {e}")


# =============================================================
# Gestión de dominios spam
# =============================================================


def _render_spam_domains():
    st.markdown("### Lista de dominios spam conocidos")
    st.caption(
        "Scripts externos de estos dominios generarán alertas con severidad escalada."
    )

    domains = get_spam_domains()

    # Agregar nuevo dominio
    col_input, col_btn = st.columns([3, 1])
    with col_input:
        new_domain = st.text_input(
            "Nuevo dominio spam",
            placeholder="evil-tracker.xyz",
            label_visibility="collapsed",
        )
    with col_btn:
        if st.button("➕ Agregar", use_container_width=True):
            if new_domain and "." in new_domain:
                add_spam_domain(new_domain.lower().strip())
                st.success(f"'{new_domain}' agregado")
                st.rerun()
            else:
                st.error("Dominio inválido")

    st.markdown(f"**{len(domains)} dominios en la lista:**")

    if not domains:
        st.info("La lista está vacía.")
        return

    # Mostrar en columnas con botón eliminar
    cols_per_row = 3
    for i in range(0, len(domains), cols_per_row):
        row_domains = domains[i : i + cols_per_row]
        cols = st.columns(cols_per_row)
        for j, domain in enumerate(row_domains):
            with cols[j]:
                col_d, col_x = st.columns([3, 1])
                with col_d:
                    st.caption(f"🚫 {domain}")
                with col_x:
                    if st.button(
                        "✕", key=f"del_spam_{domain}", help=f"Eliminar {domain}"
                    ):
                        delete_spam_domain(domain)
                        st.rerun()


# =============================================================
# Configuración de alertas
# =============================================================


def _render_alerts_config():
    import os

    st.markdown("### Configuración de emails de alerta")
    st.info(
        "Las credenciales SMTP se configuran via variables de entorno en el servidor. Aquí puedes verificar el estado actual."
    )

    cfg_vars = [
        ("SAAF_EMAIL_ENABLED", "Email habilitado"),
        ("SAAF_SMTP_SERVER", "Servidor SMTP"),
        ("SAAF_SMTP_PORT", "Puerto SMTP"),
        ("SAAF_SMTP_FROM", "Remitente"),
        ("SAAF_SMTP_USER", "Usuario SMTP"),
        ("SAAF_ALERT_RECIPIENTS", "Destinatarios"),
        ("SAAF_ALERT_CRITICAL", "Alertar CRÍTICO"),
        ("SAAF_ALERT_HIGH", "Alertar HIGH"),
        ("SAAF_ALERT_DOWN", "Alertar sitio caído"),
    ]

    for var, label in cfg_vars:
        val = os.environ.get(var, "")
        if "PASSWORD" in var:
            display = "***" if val else "⚠️ No configurado"
        else:
            display = val if val else "⚠️ No configurado"
        color = "normal" if val else "off"
        c1, c2 = st.columns([2, 3])
        c1.caption(f"**{label}**")
        c2.caption(display)

    st.markdown("---")
    st.markdown("**Frecuencia del ciclo automático:**")
    try:
        sched = get_schedule_config()
        if sched["frequency"] == "weekly":
            resumen = (
                f"🕐 Semanal — cada {WEEKDAY_LABELS.get(sched.get('weekday','mon'))} "
                f"a las {sched['hour']:02d}:{sched['minute']:02d} (hora de Colombia)"
            )
        else:
            resumen = f"🕐 Diaria — todos los días a las {sched['hour']:02d}:{sched['minute']:02d} (hora de Colombia)"
        st.caption(resumen)
        st.caption(
            "Se configura con el botón **🕐 Frecuencia** en el Dashboard. "
            "Las variables SAAF_SCHEDULE_HOUR / SAAF_SCHEDULE_MINUTE solo se usan "
            "como valor inicial si nunca se ha guardado una frecuencia desde ahí."
        )
    except Exception as e:
        st.error(f"Error leyendo frecuencia: {e}")

    st.markdown("---")
    st.markdown("**Probar configuración:**")
    if st.button("📧 Enviar email de prueba"):
        try:
            from alerts import send_to_all

            sent = send_to_all("SAAF Pro — Test", "Email de prueba desde el dashboard.")
            if sent > 0:
                st.success(f"Email enviado a {sent} destinatario(s)")
            else:
                st.warning("No se envió ningún email. Verificar configuración.")
        except Exception as e:
            st.error(f"Error: {e}")


# =============================================================
# Reportes y log del ciclo
# =============================================================


def _render_reports_logs():
    tab_reports, tab_logs = st.tabs(
        ["📄 Reportes diarios", "🔄 Log del ciclo automático"]
    )

    with tab_reports:
        st.markdown("### Reportes diarios")
        reports = get_reports(report_type="daily", limit=30)

        if not reports:
            st.info("No hay reportes generados aún.")
        else:
            for r in reports:
                col1, col2, col3 = st.columns([2, 3, 1])
                with col1:
                    st.caption(r["generated_at"][:16])
                with col2:
                    st.caption(r["file_path"])
                with col3:
                    try:
                        from pathlib import Path

                        path = Path(r["file_path"])
                        if path.exists():
                            content = path.read_text(encoding="utf-8")
                            st.download_button(
                                "⬇ Descargar",
                                content,
                                file_name=path.name,
                                mime="text/plain",
                                key=f"dl_report_{r['id']}",
                                use_container_width=True,
                            )
                        else:
                            st.caption("Archivo no encontrado")
                    except Exception:
                        st.caption("—")

    with tab_logs:
        st.markdown("### Log de ejecuciones del ciclo automático")
        st.caption(
            "Registro de cada vez que el scheduler ejecutó el ciclo de auditoría."
        )

        logs = get_cycle_logs(limit=30)

        if not logs:
            st.info("No hay ejecuciones registradas aún.")
            return

        for log in logs:
            icon = (
                "✅"
                if log["status"] == "ok"
                else ("🔴" if log["status"] == "error" else "🔄")
            )
            started = to_local_str(log["started_at"]) if log["started_at"] else "—"
            finished = to_local_str(log["finished_at"]) if log["finished_at"] else "En curso"

            with st.expander(
                f"{icon} {started} — {log['status'].upper()} — {log['sites_total']} sitios"
            ):
                c1, c2, c3, c4, c5 = st.columns(5)
                c1.metric("Total", log["sites_total"])
                c2.metric("✅ OK", log["sites_ok"])
                c3.metric("⚠️ Issues", log["sites_issues"])
                c4.metric("🔴 Caídos", log["sites_down"])
                c5.metric("❌ Errores", log["sites_error"])

                st.caption(f"Inicio: {started}  ·  Fin: {finished}")
                if log["error_msg"]:
                    st.error(f"Error: {log['error_msg']}")
