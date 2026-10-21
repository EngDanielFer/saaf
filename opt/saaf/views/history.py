#!/home/admin_ubuntu/Desktop/proyecto_saaf/opt/saaf/venv/bin/python
# =============================================================
# SAAF Pro — views/history.py
# Historial de hacks: todos los problemas con fecha y resolucion
# Exportar PDF por sitio o global
# =============================================================

import streamlit as st
import pandas as pd
import io
from datetime import datetime, timezone

import sys

sys.path.insert(0, "/home/admin_ubuntu/Desktop/proyecto_saaf/opt/saaf")
sys.path.insert(0, "/home/admin_ubuntu/Desktop/proyecto_saaf/opt/saaf/scripts/python")

from database import get_all_threats, get_all_sites, init_db, to_local_str, COLOMBIA_TZ

THREAT_LABELS = {
    "casino_pharma_adult": "URL spam",
    "hidden_spam_link": "Link spam oculto",
    "external_script": "Script externo",
    "hidden_iframe": "iFrame oculto",
    "obfuscated_js": "JS ofuscado",
    "claude_anomaly": "Anomalía Claude",
}


def render():
    init_db()
    st.markdown("## 📋 Historial de amenazas")
    st.caption("Todos los problemas detectados, incluyendo los ya resueltos.")

    # Filtros
    col_f1, col_f2, col_f3, col_export = st.columns([2, 2, 1.5, 1.5])
    with col_f1:
        sites = get_all_sites()
        site_opts = ["Todos"] + [s["name"] for s in sites]
        site_sel = st.selectbox("Sitio", site_opts)
    with col_f2:
        sev_opts = ["Todas", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
        sev_sel = st.selectbox("Severidad", sev_opts)
    with col_f3:
        status_sel = st.radio(
            "Estado", ["Todas", "Abiertas", "Resueltas"], horizontal=True
        )

    site_id = None
    if site_sel != "Todos":
        match = next((s for s in sites if s["name"] == site_sel), None)
        if match:
            site_id = match["id"]

    threats = get_all_threats(site_id=site_id, limit=500)

    # Aplicar filtros
    if sev_sel != "Todas":
        threats = [t for t in threats if t["severity"] == sev_sel]
    if status_sel == "Abiertas":
        threats = [t for t in threats if not t["resolved"]]
    elif status_sel == "Resueltas":
        threats = [t for t in threats if t["resolved"]]

    # Exportar
    with col_export:
        if st.button("📥 Exportar PDF", use_container_width=True):
            try:
                pdf_bytes = _generate_pdf(threats, site_sel)
                if pdf_bytes:
                    fname = (
                        f"saaf_historial_{site_sel.replace(' ','_')}"
                        f"{datetime.now().strftime('%Y%m%d')}.pdf"
                    )
                    st.download_button(
                        "⬇ Descargar PDF",
                        pdf_bytes,
                        fname,
                        "application/pdf",
                        use_container_width=True,
                    )
            except Exception as e:
                st.error(f"Error generando PDF: {e}")
                st.info("Alternativa: exportar como CSV usando la tabla de arriba.")

    st.markdown(f"**{len(threats)} registros**")
    st.markdown("---")

    if not threats:
        st.info("No hay registros con los filtros seleccionados.")
        return

    # Tabla resumen
    df = pd.DataFrame(
        [
            {
                "Fecha": to_local_str(t["detected_at"]),
                "Sitio": t["site_name"] if t["site_name"] else "—",
                "Tipo": THREAT_LABELS.get(t["threat_type"], t["threat_type"]),
                "Severidad": t["severity"],
                "URL": (t["url_found"] or "—")[:60],
                "Estado": "✅ Resuelto" if t["resolved"] else "⚠️ Abierto",
                "Resuelto el": to_local_str(t["resolved_at"], "%Y-%m-%d") if t["resolved_at"] else "—",
            }
            for t in threats
        ]
    )

    st.dataframe(df, use_container_width=True, hide_index=True)

    # Detalle expandible por entrada
    st.markdown("---")
    st.markdown("### Detalle")
    for t in threats[:50]:  # Mostrar max 50 con detalle
        icon = "✅" if t["resolved"] else "⚠️"
        label = THREAT_LABELS.get(t["threat_type"], t["threat_type"])
        site_name_display = t["site_name"] if t["site_name"] else "—"
        expander_label = f"{icon} {to_local_str(t['detected_at'])} — {site_name_display} — {label} [{t['severity']}]"
        with st.expander(expander_label):
            col1, col2 = st.columns([3, 1])
            with col1:
                st.caption(f"**Descripción:** {t['description']}")
                st.caption(f"**URL:** {t['url_found'] or '—'}")
                if t["resolved_at"]:
                    st.caption(f"**Resuelto:** {to_local_str(t['resolved_at'])}")
                if t["code_snippet"]:
                    st.markdown("**Código:**")
                    import html as _html

                    safe_snippet = _html.escape(t["code_snippet"][:400])
                    st.markdown(
                        f'<div class="code-snippet">{safe_snippet}</div>',
                        unsafe_allow_html=True,
                    )


def _generate_pdf(threats: list, site_name: str) -> bytes:
    """Genera un PDF simple del historial usando reportlab si está disponible."""
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.platypus import (
            SimpleDocTemplate,
            Table,
            TableStyle,
            Paragraph,
            Spacer,
        )
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.lib import colors

        buf = io.BytesIO()
        doc = SimpleDocTemplate(
            buf,
            pagesize=A4,
            rightMargin=40,
            leftMargin=40,
            topMargin=60,
            bottomMargin=40,
        )
        styles = getSampleStyleSheet()
        story = []

        story.append(Paragraph("SAAF Pro — Historial de amenazas", styles["Title"]))
        story.append(
            Paragraph(
                f"Sitio: {site_name} · Generado: {datetime.now(timezone.utc).astimezone(COLOMBIA_TZ).strftime('%Y-%m-%d %H:%M')} (hora de Colombia)",
                styles["Normal"],
            )
        )
        story.append(Spacer(1, 20))

        # Tabla
        headers = ["Fecha", "Sitio", "Tipo", "Severidad", "Estado"]
        data = [headers]
        for t in threats:
            data.append(
                [
                    to_local_str(t["detected_at"]),
                    t["site_name"] if "site_name" in t.keys() else "—"[:20],
                    THREAT_LABELS.get(t["threat_type"], t["threat_type"])[:25],
                    t["severity"],
                    "✓ Resuelto" if t["resolved"] else "Abierto",
                ]
            )

        tbl = Table(data, colWidths=[100, 100, 140, 70, 70])
        tbl.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2E74B5")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                    (
                        "ROWBACKGROUNDS",
                        (0, 1),
                        (-1, -1),
                        [colors.white, colors.HexColor("#F8FAFC")],
                    ),
                ]
            )
        )
        story.append(tbl)
        doc.build(story)
        return buf.getvalue()

    except ImportError:
        st.warning("reportlab no instalado. Instalar con: pip install reportlab")
        return None
    except Exception as e:
        st.error(f"Error generando PDF: {e}")
        return None
