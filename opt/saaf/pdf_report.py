#!/home/admin_ubuntu/Desktop/proyecto_saaf/opt/saaf/venv/bin/python
# =============================================================
# SAAF Pro — pdf_report.py
# Genera reportes PDF del estado actual de todos los sitios
# y del historial de un sitio especifico.
# Ruta: /home/admin_ubuntu/Desktop/proyecto_saaf/opt/saaf/pdf_report.py
# Dependencia: pip install reportlab
# =============================================================

import io
import sys
import logging
from datetime import datetime, timezone
from pathlib import Path

logger = logging.getLogger(__name__)

sys.path.insert(0, "/home/admin_ubuntu/Desktop/proyecto_saaf/opt/saaf")
sys.path.insert(0, "/home/admin_ubuntu/Desktop/proyecto_saaf/opt/saaf/scripts/python")

try:
    from database import to_local_str, COLOMBIA_TZ
except ImportError:
    COLOMBIA_TZ = None

    def to_local_str(raw_ts, fmt="%Y-%m-%d %H:%M"):
        return (str(raw_ts)[:16] if raw_ts else "—")
    
try:
    from reportlab.lib.pagesizes import A4, landscape
    from reportlab.platypus import (
        SimpleDocTemplate,
        Table,
        TableStyle,
        Paragraph,
        Spacer,
        HRFlowable,
    )
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib import colors
    from reportlab.lib.units import cm

    REPORTLAB_AVAILABLE = True
except ImportError:
    REPORTLAB_AVAILABLE = False
    logger.warning("reportlab no instalado. Instalar: pip install reportlab")

# =============================================================
# Estilos
# =============================================================

SEV_COLORS = {
    "CRITICAL": colors.HexColor("#DC2626"),
    "HIGH": colors.HexColor("#EA580C"),
    "MEDIUM": colors.HexColor("#CA8A04"),
    "LOW": colors.HexColor("#16A34A"),
    "INFO": colors.HexColor("#64748B"),
}

# Etiquetas cortas de estado de auditoria (la columna del PDF es estrecha)
STATUS_SHORT = {"COMPLETED_WITH_WARNINGS": "WARNINGS"}

THREAT_LABELS = {
    "casino_pharma_adult": "URL spam",
    "hidden_spam_link": "Link spam oculto",
    "external_script": "Script externo",
    "hidden_iframe": "iFrame oculto",
    "obfuscated_js": "JS ofuscado",
    "claude_anomaly": "Anomalía Claude",
}


def _get_styles():
    styles = getSampleStyleSheet()
    styles.add(
        ParagraphStyle(
            name="SectionHeader",
            fontSize=12,
            fontName="Helvetica-Bold",
            textColor=colors.HexColor("#1F3864"),
            spaceBefore=12,
            spaceAfter=6,
        )
    )
    styles.add(
        ParagraphStyle(
            name="SmallText",
            fontSize=8,
            fontName="Helvetica",
            textColor=colors.HexColor("#666666"),
        )
    )
    return styles


# =============================================================
# Reporte global — todos los sitios
# =============================================================


def generate_all_sites_report(output_path: str = None) -> bytes:
    """
    Genera un PDF con el estado actual de todos los sitios.
    Si output_path es None, retorna los bytes del PDF.
    Si se especifica output_path, guarda el archivo y retorna bytes tambien.
    """
    if not REPORTLAB_AVAILABLE:
        raise ImportError(
            "reportlab no instalado. Correr:\n"
            "  /home/admin_ubuntu/Desktop/proyecto_saaf/opt/saaf/venv/bin/pip install reportlab\n"
            "Luego reiniciar el dashboard."
        )

    from database import (
        init_db,
        get_all_sites,
        is_site_currently_up,
        get_uptime_stats,
        get_last_audit,
        get_open_threats,
        get_dashboard_summary,
    )

    init_db()

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=landscape(A4),
        rightMargin=2 * cm,
        leftMargin=2 * cm,
        topMargin=2 * cm,
        bottomMargin=2 * cm,
    )
    styles = _get_styles()
    story = []
    now = datetime.now(timezone.utc).astimezone(COLOMBIA_TZ).strftime("%Y-%m-%d %H:%M") + " (hora de Colombia)" if COLOMBIA_TZ else datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    # Titulo
    story.append(Paragraph("SAAF Pro — Estado de todos los sitios", styles["Title"]))
    story.append(Paragraph(f"Generado: {now}", styles["SmallText"]))
    story.append(Spacer(1, 0.4 * cm))

    # Resumen global
    try:
        summary = get_dashboard_summary()
        summary_data = [
            [
                "Sitios activos",
                str(summary["total_sites"]),
                "Sitios caídos",
                str(summary["sites_down"]),
                "Alertas críticas",
                str(summary["open_critical"]),
                "Total alertas",
                str(summary["open_total"]),
            ],
        ]
        tbl = Table(summary_data, colWidths=[3 * cm] * 8)
        tbl.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#EFF6FF")),
                    ("FONTSIZE", (0, 0), (-1, -1), 9),
                    ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                    ("ALIGN", (0, 0), (-1, -1), "CENTER"),
                ]
            )
        )
        story.append(tbl)
    except Exception:
        pass

    story.append(Spacer(1, 0.5 * cm))
    story.append(
        HRFlowable(width="100%", thickness=1, color=colors.HexColor("#CBD5E1"))
    )
    story.append(Spacer(1, 0.3 * cm))

    # Tabla de sitios
    story.append(Paragraph("Estado por sitio", styles["SectionHeader"]))

    headers = [
        "Sitio",
        "URL",
        "Nicho",
        "Estado",
        "Uptime 7d",
        "Uptime 30d",
        "Alertas abiertas",
        "Última auditoría",
        "Sev. máx.",
    ]
    data = [headers]

    sites = get_all_sites(active_only=False)
    for s in sites:
        is_up = is_site_currently_up(s["id"])
        uptime7 = get_uptime_stats(s["id"], days=7)
        uptime30 = get_uptime_stats(s["id"], days=30)
        last = get_last_audit(s["id"])
        open_t = get_open_threats(s["id"])
        sev_max = last["severity_max"] if last and last["severity_max"] else "—"

        status_str = "CAÍDO" if is_up is False else ("ACTIVO" if is_up else "—")

        data.append(
            [
                s["name"][:25],
                s["url"][:35],
                s["niche"],
                status_str,
                f"{uptime7}%" if uptime7 else "—",
                f"{uptime30}%" if uptime30 else "—",
                str(len(open_t)),
                to_local_str(last["started_at"]) if last else "—",
                sev_max,
            ]
        )

    col_widths = [
        3.5 * cm,
        5 * cm,
        2 * cm,
        2 * cm,
        2 * cm,
        2 * cm,
        2.2 * cm,
        3.5 * cm,
        2 * cm,
    ]
    tbl = Table(data, colWidths=col_widths, repeatRows=1)

    tbl_style = [
        ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2E74B5")),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
        (
            "ROWBACKGROUNDS",
            (0, 1),
            (-1, -1),
            [colors.white, colors.HexColor("#F8FAFC")],
        ),
        ("ALIGN", (4, 1), (7, -1), "CENTER"),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
    ]

    # Colorear columna de severidad
    for i, row in enumerate(data[1:], start=1):
        sev = row[-1]
        if sev in SEV_COLORS:
            tbl_style.append(("TEXTCOLOR", (-1, i), (-1, i), SEV_COLORS[sev]))
            tbl_style.append(("FONTNAME", (-1, i), (-1, i), "Helvetica-Bold"))
        if row[3] == "CAÍDO":
            tbl_style.append(("TEXTCOLOR", (3, i), (3, i), colors.HexColor("#DC2626")))
            tbl_style.append(("FONTNAME", (3, i), (3, i), "Helvetica-Bold"))

    tbl.setStyle(TableStyle(tbl_style))
    story.append(tbl)

    story.append(Spacer(1, 0.5 * cm))
    story.append(
        Paragraph("SAAF Pro — Security Audit & Alert Framework", styles["SmallText"])
    )

    doc.build(story)
    pdf_bytes = buf.getvalue()

    if output_path:
        Path(output_path).write_bytes(pdf_bytes)
        logger.info("Reporte global guardado: %s", output_path)

    return pdf_bytes


# =============================================================
# Reporte por sitio
# =============================================================


def generate_site_report(site_id: int, output_path: str = None) -> bytes:
    """
    Genera un PDF con el historial completo de un sitio especifico.
    """
    if not REPORTLAB_AVAILABLE:
        raise ImportError(
            "reportlab no instalado. Correr:\n"
            "  /home/admin_ubuntu/Desktop/proyecto_saaf/opt/saaf/venv/bin/pip install reportlab\n"
            "Luego reiniciar el dashboard."
        )

    from database import (
        init_db,
        get_site,
        get_site_audits,
        get_all_threats,
        get_uptime_stats,
        get_uptime_history,
        is_site_currently_up,
    )

    init_db()

    site = get_site(site_id)
    if not site:
        raise ValueError(f"Sitio no encontrado: {site_id}")

    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        rightMargin=2 * cm,
        leftMargin=2 * cm,
        topMargin=2 * cm,
        bottomMargin=2 * cm,
    )
    styles = _get_styles()
    story = []
    now = datetime.now(timezone.utc).astimezone(COLOMBIA_TZ).strftime("%Y-%m-%d %H:%M") + " (hora de Colombia)" if COLOMBIA_TZ else datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    # Encabezado
    story.append(Paragraph(f"SAAF Pro — Reporte: {site['name']}", styles["Title"]))
    story.append(
        Paragraph(
            f"{site['url']}  ·  Nicho: {site['niche']}  ·  {now}", styles["SmallText"]
        )
    )
    story.append(Spacer(1, 0.3 * cm))

    # Métricas
    is_up = is_site_currently_up(site_id)
    uptime7 = get_uptime_stats(site_id, days=7)
    uptime30 = get_uptime_stats(site_id, days=30)
    threats = get_all_threats(site_id, limit=200)
    open_t = [t for t in threats if not t["resolved"]]

    metrics_data = [
        [
            "Estado actual",
            "CAÍDO" if is_up is False else "ACTIVO",
            "Uptime 7d",
            f"{uptime7}%" if uptime7 else "—",
            "Uptime 30d",
            f"{uptime30}%" if uptime30 else "—",
            "Alertas abiertas",
            str(len(open_t)),
        ]
    ]
    m_tbl = Table(metrics_data, colWidths=[3 * cm] * 8)
    m_tbl.setStyle(
        TableStyle(
            [
                ("FONTSIZE", (0, 0), (-1, -1), 9),
                ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                ("BACKGROUND", (0, 0), (-1, -1), colors.HexColor("#EFF6FF")),
                ("FONTNAME", (1, 0), (1, 0), "Helvetica-Bold"),
                (
                    "TEXTCOLOR",
                    (1, 0),
                    (1, 0),
                    (
                        colors.HexColor("#DC2626")
                        if is_up is False
                        else colors.HexColor("#16A34A")
                    ),
                ),
            ]
        )
    )
    story.append(m_tbl)
    story.append(Spacer(1, 0.4 * cm))

    # Historial de amenazas
    story.append(Paragraph("Historial de amenazas", styles["SectionHeader"]))

    if threats:
        t_headers = ["Fecha", "Tipo", "Severidad", "URL", "Estado", "Descripcion"]
        t_data = [t_headers]
        for t in threats:
            t_data.append(
                [
                    to_local_str(t["detected_at"]),
                    THREAT_LABELS.get(t["threat_type"], t["threat_type"]),
                    t["severity"],
                    (t["url_found"] or "—")[:40],
                    "✓" if t["resolved"] else "⚠",
                    t["description"][:50],
                ]
            )
        t_tbl = Table(
            t_data,
            colWidths=[2.8 * cm, 3 * cm, 2 * cm, 4.5 * cm, 1.2 * cm, 4.5 * cm],
            repeatRows=1,
        )
        t_style = [
            ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2E74B5")),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 7.5),
            ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
            (
                "ROWBACKGROUNDS",
                (0, 1),
                (-1, -1),
                [colors.white, colors.HexColor("#F8FAFC")],
            ),
        ]
        for i, row in enumerate(t_data[1:], start=1):
            sev = row[2]
            if sev in SEV_COLORS:
                t_style.append(("TEXTCOLOR", (2, i), (2, i), SEV_COLORS[sev]))
                t_style.append(("FONTNAME", (2, i), (2, i), "Helvetica-Bold"))
        t_tbl.setStyle(TableStyle(t_style))
        story.append(t_tbl)
    else:
        story.append(Paragraph("No se han detectado amenazas.", styles["Normal"]))

    story.append(Spacer(1, 0.4 * cm))

    # Historial de auditorías
    story.append(Paragraph("Historial de auditorías", styles["SectionHeader"]))
    audits = get_site_audits(site_id, limit=30)
    if audits:
        a_data = [["Fecha", "Estado", "Metodo", "URLs", "Sev. max", "Error"]]
        for a in audits:
            a_data.append(
                [
                    to_local_str(a["started_at"]),
                    a["status"],
                    a["crawl_method"] or "—",
                    str(a["urls_analyzed"]),
                    a["severity_max"] or "—",
                    (a["error_msg"] or "")[:40],
                ]
            )
        a_tbl = Table(
            a_data,
            colWidths=[3 * cm, 2 * cm, 2.2 * cm, 1.5 * cm, 2 * cm, 5.5 * cm],
            repeatRows=1,
        )
        a_tbl.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#2E74B5")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#CBD5E1")),
                    (
                        "ROWBACKGROUNDS",
                        (0, 1),
                        (-1, -1),
                        [colors.white, colors.HexColor("#F8FAFC")],
                    ),
                ]
            )
        )
        story.append(a_tbl)

    story.append(Spacer(1, 0.5 * cm))
    story.append(
        Paragraph("SAAF Pro — Security Audit & Alert Framework", styles["SmallText"])
    )

    doc.build(story)
    pdf_bytes = buf.getvalue()

    if output_path:
        Path(output_path).write_bytes(pdf_bytes)
        logger.info("Reporte de sitio guardado: %s", output_path)

    return pdf_bytes


# =============================================================
# Entrypoint
# =============================================================

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s"
    )
    if not REPORTLAB_AVAILABLE:
        print("[!] reportlab no instalado. Correr:")
        print(
            "    /home/admin_ubuntu/Desktop/proyecto_saaf/opt/saaf/venv/bin/pip install reportlab"
        )
        sys.exit(1)

    print("Generando reporte global...")
    pdf = generate_all_sites_report(
        "/home/admin_ubuntu/Desktop/proyecto_saaf/opt/saaf/logs/report_test.pdf"
    )
    print(
        f"[OK] Reporte guardado: /home/admin_ubuntu/Desktop/proyecto_saaf/opt/saaf/logs/report_test.pdf ({len(pdf)} bytes)"
    )
