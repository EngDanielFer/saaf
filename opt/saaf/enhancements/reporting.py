# =============================================================
# SAAF Pro — enhancements/reporting.py
# Construye el reporte final (punto 8): resumen cuantitativo + grupos +
# enlaces externos + historial + pendientes + analisis global de IA, y lo
# renderiza como texto, HTML (correo) y tarjeta adaptable (Teams).
#
# Las URLs de RECURSOS externos se muestran "desarmadas" (hxxps://dominio[.]com)
# en correo y Teams para que nadie haga clic por accidente en spam/malware.
# Todo texto que viene del sitio auditado se escapa antes de ir a HTML.
# =============================================================

import html as _html
import os
import re
from collections import Counter, defaultdict

from database import to_local_str

from . import history as hist
from . import links as lk
from . import taxonomy as tx
from .items import page_path, res_key

STATE_LABEL = {"limpio": "Sin hallazgos relevantes", "atencion": "Requiere atención",
               "comprometido": "Posible compromiso"}
STATE_ICON = {"limpio": "🟢", "atencion": "🟠", "comprometido": "🔴"}
SEV_ORDER = ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
MAX_EXAMPLES = 5


def defang(url) -> str:
    """https://evil.com/x -> hxxps://evil[.]com/x  (texto, no enlace)."""
    if not url:
        return ""
    u = str(url).strip()
    m = re.match(r"^(https?)://([^/\s]+)(.*)$", u, re.I)
    if m:
        scheme = m.group(1).lower().replace("http", "hxxp")
        return f"{scheme}://{m.group(2).replace('.', '[.]')}{m.group(3)}"
    if re.match(r"^[\w\-]+(\.[\w\-]+)+(/.*)?$", u):
        host, _, rest = u.partition("/")
        return host.replace(".", "[.]") + (("/" + rest) if rest else "")
    return u


def _sev_max(items):
    return max((i.get("severity") or "LOW" for i in items), key=lambda s: SEV_ORDER.index(s) if s in SEV_ORDER else 0)


# ------------------------------------------------------------------
# Hechos del reporte
# ------------------------------------------------------------------
def build_facts(site: dict, audit: dict, items: list, link_rows: list, link_summary: dict,
                hist_result: dict, rem_counters: dict, expected_langs: list, ai_info: dict,
                legit_items: list = None, important_threshold: str = "HIGH") -> dict:
    legit_items = legit_items or []
    by_cat = defaultdict(list)
    for it in items:
        by_cat[it["category"]].append(it)

    groups = []
    for cat in tx.CATEGORY_ORDER:
        members = by_cat.get(cat)
        if not members:
            continue
        members = sorted(members, key=lambda i: -int(i.get("confidence") or 0))
        pages = {page_path(m.get("page_url")) for m in members if m.get("page_url")}
        statuses = Counter(m.get("lifecycle") or m.get("status") for m in members)
        # Que se encontro realmente (para que el analisis no sea generico):
        # terminos citables, dominios de los recursos y huellas de codigo.
        term_count = Counter(t for m in members for t in (m.get("terms") or []))
        # "casino" y "casino online" dicen lo mismo: se conserva el mas corto
        for t in sorted(term_count, key=len):
            for other in [x for x in term_count if x != t and len(x) > len(t)]:
                if t in other:
                    term_count.pop(other, None)
        host_count = Counter(res_key(m["resource_url"]).split("/")[0]
                             for m in members if m.get("resource_url"))
        code_notes = list(dict.fromkeys(d for m in members for d in (m.get("code_notes") or [])))
        fixed_pages = [page_path(m.get("page_url")) for m in members if m.get("rem_status") == "APPLIED"]
        pending_pages = [page_path(m.get("page_url")) for m in members
                         if m.get("rem_status") == "PENDING_AUTHORIZATION"]
        # "Mismo patron": varios elementos repartidos en varias paginas que comparten
        # un termino o un mismo recurso de origen -> probablemente una sola inyeccion.
        shared_term = [t for t, c in term_count.items() if c >= 2]
        shared_host = [h for h, c in host_count.items() if c >= 2]
        same_pattern = bool(len(members) >= 3 and len(pages) >= 2 and (shared_term or shared_host))
        groups.append({
            "key": cat,
            "label": tx.label(cat),
            "items": len(members),
            "pages": len(pages),
            "confidence": round(sum(int(m.get("confidence") or 0) for m in members) / len(members)),
            "severity": _sev_max(members),
            "statuses": dict(statuses),
            "auto_fixed": sum(1 for m in members if m.get("rem_status") == "APPLIED"),
            "pending": sum(1 for m in members if m.get("rem_status") == "PENDING_AUTHORIZATION"),
            "dry_run": sum(1 for m in members if m.get("rem_status") == "DRY_RUN"),
            "failed": sum(1 for m in members if m.get("rem_status") == "FAILED"),
            "terms": [t for t, _ in term_count.most_common(6)],
            "hosts": [h for h, _ in host_count.most_common(4)],
            "code_notes": code_notes[:3],
            "fixed_pages": fixed_pages[:5],
            "pending_pages": pending_pages[:5],
            "same_pattern": same_pattern,
            "examples": [
                {
                    "page": page_path(m.get("page_url")),
                    "resource": res_key(m.get("resource_url")) if m.get("resource_url") else "",
                    "type": m.get("threat_type"),
                    "status": m.get("status"),
                    "lifecycle": m.get("lifecycle"),
                    "confidence": int(m.get("confidence") or 0),
                    "action": m.get("rem_status"),
                }
                for m in members[:MAX_EXAMPLES]
            ],
        })
    groups.sort(key=lambda g: (-SEV_ORDER.index(g["severity"]) if g["severity"] in SEV_ORDER else 0, -g["items"]))

    n = lambda pred: sum(1 for i in items if pred(i))
    summary = {
        "alerts": len(items),
        "groups": len(groups),
        "auto_fixed": n(lambda i: i.get("rem_status") == "APPLIED"),
        "pending": n(lambda i: i.get("rem_status") == "PENDING_AUTHORIZATION"),
        "persistent": n(lambda i: i.get("lifecycle") == hist.PERSISTENT),
        "resolved": len(hist_result.get("resolved", [])),
        "new": n(lambda i: i.get("lifecycle") == hist.NEW),
        "reopened": n(lambda i: i.get("lifecycle") == hist.REOPENED),
        "dry_run": n(lambda i: i.get("rem_status") == "DRY_RUN"),
        "failed": n(lambda i: i.get("rem_status") == "FAILED"),
        "legit_resources": link_summary.get("legit", 0) + len(legit_items),
        "unverified": hist_result.get("unverified", 0),
    }

    unresolved = [i for i in items if i.get("rem_status") != "APPLIED"]
    if not unresolved:
        state = "limpio"
    elif any(i.get("severity") == "CRITICAL" for i in unresolved) or \
            sum(1 for i in unresolved if i["category"] in tx.SPAM_CATEGORIES and int(i.get("confidence") or 0) >= 70) >= 5 or \
            any(i.get("severity") in ("CRITICAL", "HIGH") and i.get("corroborated") and int(i.get("confidence") or 0) >= 80
                for i in unresolved):
        # Un hallazgo grave, respaldado por indicadores deterministas y con alta confianza (p. ej. un cargador
        # de malware o una página de spam inyectada) ya es un posible compromiso.
        state = "comprometido"
    else:
        state = "atencion"

    review_rows = [r for r in link_rows if r["verdict"] == "review"]
    unverified_rows = [r for r in link_rows if r["verdict"] == "legit" and not lk.is_confirmed(r)]
    facts = {
        "site": {"id": site["id"], "name": site["name"], "url": site["url"], "niche": site.get("niche"),
                 "host": res_key(site["url"]).split("/")[0]},
        "audit": audit,
        "summary": summary,
        "site_state": state,
        "groups": groups,
        "external_links": {
            "total": link_summary.get("domains", 0),
            "links": link_summary.get("links", 0),
            "legit": link_summary.get("legit", 0),
            "review": link_summary.get("review", 0),
            "confirmed": link_summary.get("confirmed", 0),
            "unverified": link_summary.get("unverified", 0),
            "review_hosts": link_summary.get("review_hosts", []),
            "review_list": [
                {"host": r["host"], "reason": r["reason"], "confidence": r["confidence"],
                 "pages": [page_path(p) for p in r["sample_pages"][:3]]}
                for r in review_rows[:10]
            ],
            "legit_hosts": link_summary.get("legit_hosts", [])[:30],
            "confirmed_hosts": link_summary.get("confirmed_hosts", [])[:30],
            "unverified_hosts": link_summary.get("unverified_hosts", [])[:30],
            "unverified_list": [
                {"host": r["host"], "reason": r["reason"], "links": r["links_count"],
                 "pages": [page_path(p) for p in r["sample_pages"][:3]]}
                for r in unverified_rows[:10]
            ],
        },
        "history": {
            "previous_audit_id": hist_result.get("previous_audit_id"),
            "persistent_examples": [
                f"{page_path(i.get('page_url'))}" + (f" ({res_key(i['resource_url'])})" if i.get("resource_url") else "")
                for i in items if i.get("lifecycle") == hist.PERSISTENT
            ][:5],
            "new_examples": [page_path(i.get("page_url")) for i in items if i.get("lifecycle") == hist.NEW][:5],
            "resolved_examples": [
                page_path(r.get("page_url")) or r.get("fingerprint") for r in hist_result.get("resolved", [])
            ][:5],
            "reopened_examples": [page_path(i.get("page_url")) for i in items if i.get("lifecycle") == hist.REOPENED][:5],
        },
        "pending": [
            {"page": page_path(i.get("page_url")), "resource": res_key(i.get("resource_url")) if i.get("resource_url") else "",
             "category": tx.label(i["category"]), "confidence": int(i.get("confidence") or 0),
             "action": i.get("rem_action"), "reason": i.get("rem_message", "")}
            for i in items if i.get("rem_status") == "PENDING_AUTHORIZATION"
        ][:15],
        "remediation": {k: rem_counters.get(k, 0) for k in ("auto_applied", "dry_run", "failed", "pending")},
        "expected_languages": expected_langs,
        "ai": ai_info,
    }
    facts["important"] = is_important(facts)
    return facts


def is_important(facts: dict) -> bool:
    """Importante = algo que pide atencion: pendiente de autorizacion, reabierto, correccion fallida,
    o un hallazgo CRITICAL/HIGH que sigue sin corregir."""
    s = facts["summary"]
    if s["pending"] or s["reopened"] or s["failed"]:
        return True
    return any(g["severity"] in ("CRITICAL", "HIGH") and (g["items"] - g["auto_fixed"]) > 0 for g in facts["groups"])


# ------------------------------------------------------------------
# Texto plano
# ------------------------------------------------------------------
SUMMARY_LINES = (
    ("alerts", "Alertas detectadas"),
    ("groups", "Problemas agrupados"),
    ("auto_fixed", "Corregidos automáticamente"),
    ("pending", "Pendientes de autorización"),
    ("persistent", "Persistentes desde auditorías anteriores"),
    ("resolved", "Resueltos desde la última auditoría"),
)
EXTRA_LINES = (
    ("new", "Nuevos"), ("reopened", "Reabiertos"), ("dry_run", "Correcciones simuladas (sin cambios)"),
    ("failed", "Correcciones fallidas"), ("legit_resources", "Recursos analizados y válidos"),
    ("muted_alerts", "Alertas originales omitidas (reversible)"),
)


def _when(facts):
    a = facts["audit"]
    return to_local_str(a.get("finished_at") or a.get("started_at")) if a else ""


def _ext_sentence(facts):
    e = facts["external_links"]
    if not e["total"]:
        return ""
    n = e["total"]
    s = (f"Se analizaron {n} {'enlace externo (dominio)' if n == 1 else 'enlaces externos (dominios)'}. "
         f"{e['legit']} no {'representa' if e['legit'] == 1 else 'representan'} riesgo")
    # Punto 2: no es lo mismo "coherente con el negocio" (institucional, declarado
    # por la campania o juzgado por la IA) que "sin indicios, pero sin verificar".
    conf, unv = e.get("confirmed", 0), e.get("unverified", 0)
    if conf and unv:
        s += (f" ({conf} {'es fuente institucional, plataforma conocida o servicio declarado' if conf == 1 else 'son fuentes institucionales, plataformas conocidas o servicios declarados'}; "
              f"{unv} sin indicios de riesgo pero sin verificar su coherencia)")
    elif unv and not conf:
        s += f" ({'ninguno está verificado' if unv > 1 else 'sin verificar su coherencia'})"
    s += "."
    if e["review"]:
        s += f" Se {'identificó' if e['review'] == 1 else 'identificaron'} {e['review']} que {'requiere' if e['review'] == 1 else 'requieren'} revisión."
    return s


def render_text(report: dict) -> str:
    f, an = report["facts"], report["analysis"]
    s = f["summary"]
    L = [
        f"SAAF Pro — Reporte de auditoría",
        f"Campaña: {f['site']['name']} ({f['site']['url']})",
        f"Auditoría #{f['audit']['id']} — {_when(f)}   Estado: {STATE_ICON[f['site_state']]} {STATE_LABEL[f['site_state']]}",
        "", "RESUMEN", "-" * 40,
    ]
    for k, lab in SUMMARY_LINES:
        L.append(f"  {lab}: {s[k]}")
    for k, lab in EXTRA_LINES:
        if s.get(k):
            L.append(f"  {lab}: {s[k]}")
    L += ["", "ANÁLISIS GENERAL" + (" (IA)" if an.get("ai_used") else " (automático)"), "-" * 40, an["text"]]
    if an.get("relationships"):
        L.append("")
        L += [f"  • {r}" for r in an["relationships"]]
    if f["groups"]:
        L += ["", "PROBLEMAS AGRUPADOS", "-" * 40]
        for i, g in enumerate(f["groups"], 1):
            st = ", ".join(f"{hist.STATE_LABEL.get(k, k)} {v}" for k, v in g["statuses"].items() if k)
            L.append(f"{i}. {g['label']} — {g['items']} elemento(s) · {g['pages']} página(s) · confianza {g['confidence']}% · {g['severity']}")
            if st:
                L.append(f"   Estado: {st}")
            for e in g["examples"]:
                res = f" → {defang(e['resource'])}" if e["resource"] else ""
                act = {"APPLIED": " [corregido]", "PENDING_AUTHORIZATION": " [pendiente de autorización]",
                       "DRY_RUN": " [simulado]", "FAILED": " [corrección fallida]"}.get(e["action"], "")
                L.append(f"   • {e['page']}{res} ({e['confidence']}%){act}")
    if _ext_sentence(f):
        L += ["", "ENLACES EXTERNOS", "-" * 40, _ext_sentence(f)]
        for r in f["external_links"]["review_list"]:
            L.append(f"   • {defang(r['host'])} — {r['reason']}")
        unv = f["external_links"].get("unverified_list") or []
        if unv:
            L.append("   Sin indicios de riesgo, pero sin verificar (declara los que use la campaña):")
            for r in unv[:5]:
                L.append(f"   • {defang(r['host'])} — {r['links']} enlace(s)")
            if f["external_links"].get("unverified", 0) > 5:
                L.append(f"   • … y {f['external_links']['unverified'] - 5} más (ver el dashboard)")
    if f["pending"]:
        L += ["", "PENDIENTES DE AUTORIZACIÓN", "-" * 40]
        for p in f["pending"]:
            L.append(f"   • {p['page']} — {p['category']} ({p['confidence']}%) — {p['reason']}")
        dash = os.environ.get("SAAF_DASHBOARD_URL", "")
        L.append("   Autoriza o rechaza desde el dashboard (🧠 Auditoría IA)" + (f": {dash}" if dash else "."))
    if an.get("error_human"):
        L += ["", f"Nota: {an['error_human']}"]
    return "\n".join(L)


# ------------------------------------------------------------------
# HTML (correo)
# ------------------------------------------------------------------
def _e(x):
    return _html.escape(str(x if x is not None else ""), quote=True)


def render_html(report: dict) -> str:
    f, an = report["facts"], report["analysis"]
    s = f["summary"]
    color = {"limpio": "#16A34A", "atencion": "#EA580C", "comprometido": "#DC2626"}[f["site_state"]]
    tiles = "".join(
        f'<td style="padding:10px 14px;border:1px solid #E2E8F0;text-align:center;border-radius:6px">'
        f'<div style="font-size:22px;font-weight:700;color:#0F172A">{_e(s[k])}</div>'
        f'<div style="font-size:11px;color:#64748B">{_e(lab)}</div></td>'
        for k, lab in SUMMARY_LINES
    )
    rows = ""
    for g in f["groups"]:
        ex = "".join(
            f'<li style="margin:2px 0"><code>{_e(e["page"])}</code>'
            + (f' → <code>{_e(defang(e["resource"]))}</code>' if e["resource"] else "")
            + f' <span style="color:#64748B">({_e(e["confidence"])}%)</span></li>'
            for e in g["examples"]
        )
        st = ", ".join(f"{_e(hist.STATE_LABEL.get(k, k))} {_e(v)}" for k, v in g["statuses"].items() if k)
        rows += (
            f'<tr><td style="padding:8px;border-bottom:1px solid #E2E8F0;vertical-align:top">'
            f'<b>{_e(g["label"])}</b><br><span style="color:#64748B;font-size:12px">{st}</span></td>'
            f'<td style="padding:8px;border-bottom:1px solid #E2E8F0;text-align:center">{_e(g["items"])}<br>'
            f'<span style="font-size:11px;color:#64748B">{_e(g["pages"])} pág.</span></td>'
            f'<td style="padding:8px;border-bottom:1px solid #E2E8F0;text-align:center">{_e(g["confidence"])}%</td>'
            f'<td style="padding:8px;border-bottom:1px solid #E2E8F0;font-size:12px"><ul style="margin:0;padding-left:16px">{ex}</ul></td></tr>'
        )
    groups_html = (
        '<h3 style="margin:22px 0 6px">Problemas agrupados</h3>'
        '<table style="border-collapse:collapse;width:100%;font-size:13px"><tr style="background:#F1F5F9;text-align:left">'
        '<th style="padding:8px">Problema</th><th style="padding:8px">Elementos</th><th style="padding:8px">Confianza</th>'
        f'<th style="padding:8px">Ejemplos</th></tr>{rows}</table>'
    ) if rows else ""
    ext = _ext_sentence(f)
    ext_html = ""
    if ext:
        li = "".join(f"<li><code>{_e(defang(r['host']))}</code> — {_e(r['reason'])}</li>" for r in f["external_links"]["review_list"])
        unv = f["external_links"].get("unverified_list") or []
        unv_html = ""
        if unv:
            ul = "".join(f"<li><code>{_e(defang(r['host']))}</code> — {_e(r['links'])} enlace(s)</li>" for r in unv[:5])
            if f["external_links"].get("unverified", 0) > 5:
                ul += f"<li>… y {_e(f['external_links']['unverified'] - 5)} más</li>"
            unv_html = ('<p style="color:#64748B;font-size:13px;margin:8px 0 2px">Sin indicios de riesgo, pero sin '
                        f'verificar su coherencia con el negocio:</p><ul>{ul}</ul>')
        ext_html = (f'<h3 style="margin:22px 0 6px">Enlaces externos</h3><p>{_e(ext)}</p>'
                    + (f"<ul>{li}</ul>" if li else "") + unv_html)
    pend_html = ""
    if f["pending"]:
        li = "".join(f"<li><code>{_e(p['page'])}</code> — {_e(p['category'])} ({_e(p['confidence'])}%)<br>"
                     f"<span style='color:#64748B;font-size:12px'>{_e(p['reason'])}</span></li>" for p in f["pending"])
        dash = os.environ.get("SAAF_DASHBOARD_URL", "")
        pend_html = (f'<h3 style="margin:22px 0 6px">⏳ Pendientes de autorización</h3><ul>{li}</ul>'
                     f'<p style="font-size:12px;color:#64748B">Autoriza o rechaza desde el dashboard (🧠 Auditoría IA)'
                     + (f': {_e(dash)}' if dash else '.') + '</p>')
    rel = "".join(f"<li>{_e(r)}</li>" for r in an.get("relationships", []))
    note = f'<p style="font-size:12px;color:#94A3B8">Nota: {_e(an["error_human"])}</p>' if an.get("error_human") else ""
    return f"""<!doctype html><html><body style="font-family:Segoe UI,Arial,sans-serif;color:#0F172A;max-width:760px;margin:auto">
<div style="border-left:6px solid {color};padding:6px 14px;margin-bottom:14px">
<div style="font-size:12px;color:#64748B">SAAF Pro — Reporte de auditoría</div>
<div style="font-size:20px;font-weight:700">{_e(f['site']['name'])}</div>
<div style="font-size:13px;color:#475569">{_e(f['site']['url'])} · Auditoría #{_e(f['audit']['id'])} · {_e(_when(f))}</div>
<div style="margin-top:4px;color:{color};font-weight:600">{STATE_ICON[f['site_state']]} {_e(STATE_LABEL[f['site_state']])}</div></div>
<table style="border-collapse:separate;border-spacing:6px"><tr>{tiles}</tr></table>
<h3 style="margin:22px 0 6px">Análisis general {'(IA)' if an.get('ai_used') else '(automático)'}</h3>
<p style="line-height:1.5">{_e(an['text'])}</p>{('<ul>' + rel + '</ul>') if rel else ''}
{groups_html}{ext_html}{pend_html}{note}
<hr style="border:none;border-top:1px solid #E2E8F0;margin-top:24px"><p style="font-size:11px;color:#94A3B8">Las direcciones de recursos externos se muestran desarmadas (hxxp / [.]) para evitar clics accidentales.</p>
</body></html>"""


# ------------------------------------------------------------------
# Mensaje de Teams (texto plano, sin tarjeta ni webhook)
# ------------------------------------------------------------------
def teams_lines(report: dict) -> list:
    """Lineas del mensaje que se escribe en el chat de Teams (se envia con teams_browser)."""
    f, an = report["facts"], report["analysis"]
    s = f["summary"]
    L = [f"{STATE_ICON[f['site_state']]} SAAF Pro — {f['site']['name']}",
         f"{STATE_LABEL[f['site_state']]} · Auditoría #{f['audit']['id']} · {_when(f)}", ""]
    for k, lab in SUMMARY_LINES:
        L.append(f"• {lab}: {s[k]}")
    L += ["", "Análisis general" + (" (IA)" if an.get("ai_used") else ""), an["text"][:1400]]
    if f["groups"]:
        L += ["", "Problemas agrupados"]
        for g in f["groups"][:8]:
            ex = ", ".join(e["page"] for e in g["examples"][:2] if e["page"])
            L.append(f"• {g['label']}: {g['items']} elemento(s), confianza {g['confidence']}%" + (f" — ej. {ex}" if ex else ""))
    ext = _ext_sentence(f)
    if ext:
        L += ["", ext]
    if f["pending"]:
        L += ["", f"⏳ {len(f['pending'])} elemento(s) pendientes de autorización. Revísalos en el dashboard (Auditoría IA)."]
    dash = os.environ.get("SAAF_DASHBOARD_URL", "")
    if dash.startswith(("http://", "https://")):
        L += ["", "Dashboard: " + defang(dash)]
    return L


def subject(report: dict) -> str:
    f = report["facts"]
    s = f["summary"]
    return (f"{STATE_ICON[f['site_state']]} SAAF Pro — {f['site']['name']}: {s['alerts']} alerta(s) en "
            f"{s['groups']} problema(s)" + (f", {s['pending']} pendiente(s)" if s["pending"] else ""))
