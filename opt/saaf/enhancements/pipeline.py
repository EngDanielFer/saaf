# =============================================================
# SAAF Pro — enhancements/pipeline.py
# Flujo posterior a cada auditoria (se llama desde orchestrator.audit_site
# DESPUES de cerrar la auditoria, con todo aislado en try/except):
#
#   amenazas -> elementos -> idioma -> enlaces externos -> clasificacion
#   heuristica -> IA contextual -> legitimos -> historial -> correcciones
#   -> guardado -> analisis global -> reporte -> envio Teams/correo
#
# Nada de esto modifica las tablas originales (threats, audits...), salvo la
# opcion explicita "apply_legit_to_alerts" (desactivada por defecto).
# =============================================================

import traceback

from bs4 import BeautifulSoup

from database import get_conn, get_site, get_spam_domains
from url_utils import get_host

from . import ai_context, config as cfgmod, distribution, history, items as itm, language, links as lk
from . import remediation, reporting, store
from . import taxonomy as tx
from .log import get_logger
from .wordpress import extract_post_id

log = get_logger()

MAX_LANGUAGE_ITEMS = 200


def report_exists(audit_id: int) -> bool:
    store.ensure_schema()
    with get_conn() as conn:
        return conn.execute("SELECT 1 FROM enh_reports WHERE audit_id=?", (audit_id,)).fetchone() is not None


# ------------------------------------------------------------------
def _language_items(site: dict, html_results: list, explicit: list, niche: str):
    pages = []
    for r in html_results:
        if r.get("error") or not r.get("html"):
            continue
        try:
            soup = BeautifulSoup(r["html"], "html.parser")
            title = (soup.title.string or "").strip() if soup.title and soup.title.string else ""
            lang, conf, method, text = language.detect_page(soup)
        except Exception:
            continue
        pages.append({"url": r.get("url") or site["url"], "lang": lang, "conf": conf, "text": text, "title": title})
    expected = language.infer_expected(pages, site["url"], explicit)
    out = []
    if expected:
        for p in pages:
            if p["lang"] == "unknown" or p["lang"] in expected or p["conf"] < 0.5:
                continue
            it = itm.language_item(p["url"], language.LANG_NAMES.get(p["lang"], p["lang"]),
                                   [language.LANG_NAMES.get(e, e) for e in expected],
                                   p["title"] or p["text"][:200], p["conf"])
            it["page_terms"] = tx.find_terms({"text": f"{p['title']} {p['text'][:2500]}"}, niche)
            out.append(it)
            if len(out) >= MAX_LANGUAGE_ITEMS:
                break
    return out, expected


# Tipos que un servicio declarado por la campania puede absolver. Nunca spam, enlaces ocultos ni JS ofuscado.
TRUSTED_SERVICE_TYPES = {"external_script", "hidden_iframe"}


def _host_matches(host: str, domains) -> bool:
    host = (host or "").lower()
    return any(host == d or host.endswith("." + d) for d in domains)


def _apply_trusted_services(items: list, link_rows: list, trusted: list, spam_domains) -> int:
    """Marca como validos los scripts/iframes cuyo dominio la campania declaro usar. Devuelve cuantos."""
    n = 0
    for it in items:
        if it.get("legit") or it.get("threat_type") not in TRUSTED_SERVICE_TYPES or not it.get("resource_url"):
            continue
        host = get_host(it["resource_url"])
        if not _host_matches(host, trusted) or _host_matches(host, spam_domains or []):
            continue
        # Con terminos de spam, huellas de codigo malicioso o señales fuertes NO se absuelve, aunque el dominio sea "declarado".
        if it.get("indicators") or any(s.get("strong") for s in it.get("signals", [])):
            continue
        it.update(legit=True, legit_by="campaña", status="VALID",
                  legit_reason="Servicio de terceros declarado por la campaña (" + host + ")")
        n += 1
    for r in link_rows:
        if r["verdict"] == "review" and not r.get("hard_bad") and _host_matches(r["host"], trusted):
            r.update(verdict="legit", reason="Servicio de terceros declarado por la campaña", source="campaña",
                     confidence=95)
    return n


def _previous_summary(site_id: int, audit_id: int):
    """Total de alertas y categorias del reporte anterior de la campaña (para comparar), o None."""
    try:
        with get_conn() as conn:
            row = conn.execute("SELECT report FROM enh_reports WHERE site_id=? AND audit_id<? ORDER BY audit_id DESC LIMIT 1",
                               (site_id, audit_id)).fetchone()
        if not row:
            return None
        f = store.jload(row["report"], {}).get("facts", {})
        return {"alerts": int(f.get("summary", {}).get("alerts", 0)), "groups": [g.get("key") for g in f.get("groups", [])]}
    except Exception:
        return None


def _map_threat_ids(audit_id: int, items: list):
    try:
        with get_conn() as conn:
            rows = conn.execute(
                "SELECT id, threat_type, url_found, resource_url FROM threats WHERE audit_id=?", (audit_id,)
            ).fetchall()
        idx = {}
        for r in rows:
            idx.setdefault((r["threat_type"], itm.norm_page(r["url_found"]), itm.res_key(r["resource_url"])), r["id"])
        for it in items:
            if it["source"] == "threat":
                it["threat_id"] = idx.get((it["threat_type"], itm.norm_page(it["page_url"]), itm.res_key(it["resource_url"])))
    except Exception:
        log.warning("No se pudo relacionar amenazas con ids", exc_info=True)


def _save_findings(site_id: int, audit_id: int, items: list):
    now = store.now_iso()
    rows = []
    for it in items:
        rows.append((
            site_id, audit_id, it["fingerprint"], it["source"], it.get("threat_id"), it["threat_type"],
            it.get("severity"), it.get("category"), int(it.get("confidence") or 0), it.get("page_url"),
            it.get("resource_url"), (it.get("description") or "")[:600], (it.get("snippet") or "")[:500],
            it.get("lifecycle"), it.get("status"), 1 if it.get("legit") else 0,
            (it.get("legit_reason") or it.get("ai_reason") or it.get("reason") or "")[:400],
            store.jdump({k: it.get(k) for k in ("h_confidence", "h_category", "ai_category", "ai_confidence",
                                                 "indicators", "rem_action", "rem_mode", "rem_status",
                                                 "rem_message", "rem_reason", "history_note", "times_seen",
                                                 "first_seen_at", "signals") if it.get(k) is not None}),
            now,
        ))
    with get_conn() as conn:
        conn.executemany(
            """INSERT INTO enh_findings (site_id, audit_id, fingerprint, source, threat_id, threat_type, severity,
                   category, confidence, page_url, resource_url, description, snippet, lifecycle, status, legit,
                   reason, extra, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""", rows)


def _save_resources(site_id: int, audit_id: int, link_rows: list):
    now = store.now_iso()
    with get_conn() as conn:
        conn.executemany(
            """INSERT INTO enh_resources (site_id, audit_id, host, sample_url, links_count, pages_count, sample_pages,
                   anchors, verdict, confidence, reason, source, created_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            [(site_id, audit_id, r["host"], r["sample_url"], r["links_count"], r["pages_count"],
              store.jdump(r["sample_pages"]), store.jdump(r["anchors"]), r["verdict"], r["confidence"],
              r["reason"][:300], r["source"], now) for r in link_rows])


# ------------------------------------------------------------------
def run_after_audit(site: dict, site_id: int, audit_id: int, threats: list, html_results: list,
                    audit_status: str = None, send: bool = True):
    """Ejecuta todo el flujo. Devuelve el reporte (dict) o None si esta apagado. Puede lanzar: el llamador aisla."""
    if cfgmod.killed():
        return None
    glob = cfgmod.get_global()
    if not glob["enabled"]:
        return None
    store.ensure_schema()
    if report_exists(audit_id):
        return None

    db_site = dict(get_site(site_id) or site)
    db_site["id"] = site_id
    niche = db_site.get("niche") or "general"
    site_cfg = cfgmod.get_site_config(site_id)
    threshold = cfgmod.effective_threshold(site_cfg, glob)
    spam_domains = get_spam_domains()
    old_domains = [d.strip() for d in (db_site.get("old_domains") or "").split(",") if d.strip()]
    ai_on = bool(glob["ai_enabled"])
    log.info("[%s] Mejoras: auditoría %s (umbral %s%%, IA %s)", db_site["name"], audit_id, threshold, "sí" if ai_on else "no")

    # 1) Elementos
    items = itm.from_threats(threats)
    _map_threat_ids(audit_id, items)
    lang_items, expected_langs = _language_items(db_site, html_results, site_cfg["ai"]["expected_languages"], niche)
    items += lang_items

    # 2) Clasificacion heuristica
    for it in items:
        itm.classify_item(it, niche, spam_domains, it.pop("page_terms", None))

    # 3) Enlaces externos
    domains = lk.extract_external_links(html_results, db_site["url"], old_domains)
    link_rows = lk.heuristic_verdicts(domains, niche, spam_domains, db_site["url"])

    # 4) IA contextual (conjunto)
    ai_info = {"classify_used": False, "classify_error": None, "classify_error_human": None}
    if ai_on and (items or link_rows):
        try:
            res = ai_context.classify_with_ai(db_site, site_cfg, expected_langs, items, link_rows)
            ai_info.update(classify_used=res["ai_used"], classify_error=res["error"],
                           classify_error_human=res["error_human"])
        except Exception as e:  # la IA nunca debe romper el flujo
            log.warning("Clasificación con IA falló: %s", e.__class__.__name__, exc_info=True)
            ai_info.update(classify_error="internal", classify_error_human="Error interno al usar la IA; se usó solo la heurística.")

    # 4b) Servicios de terceros que la campania declara usar (decision humana, no depende de la IA)
    trusted = site_cfg["ai"].get("trusted_services") or []
    if trusted:
        _apply_trusted_services(items, link_rows, trusted, spam_domains)

    # 5) Legitimos y enlaces por revisar
    legit_items = [i for i in items if i.get("legit")]
    items = [i for i in items if not i.get("legit")]
    alerted_hosts = {itm.res_key(i["resource_url"]).split("/")[0] for i in items if i.get("resource_url")}
    alerted_regs = set()
    try:
        from url_utils import registrable_domain, get_host
        alerted_regs = {registrable_domain(get_host(i["resource_url"])) for i in items if i.get("resource_url")}
    except Exception:
        pass
    for r in link_rows:
        if r["verdict"] != "review" or r["host"] in alerted_regs or r["host"] in alerted_hosts:
            continue
        it = itm.link_review_item(r["host"], r["sample_url"], r["all_pages"], r["anchors"], r["reason"], r["confidence"])
        itm.classify_item(it, niche, spam_domains)
        items.append(it)

    for it in items + legit_items:
        it["fingerprint"] = itm.fingerprint(it)
    # Deduplicar por huella (un elemento por auditoria)
    seen, uniq = set(), []
    for it in items:
        if it["fingerprint"] in seen:
            continue
        seen.add(it["fingerprint"])
        uniq.append(it)
    items = uniq

    # 6) Historial
    fetched_ok = {itm.norm_page(r.get("url")) for r in html_results if r.get("html") and not r.get("error")}
    gone = {itm.norm_page(r.get("url")) for r in html_results if r.get("status_code") in (404, 410)}
    complete = bool(fetched_ok) and len(fetched_ok) / max(len(html_results), 1) >= 0.5
    hist_result = history.apply_history(site_id, audit_id, items, fetched_ok, gone, complete)

    # 7) Correcciones (solo si WordPress esta configurado)
    hint_ids = {}
    for r in html_results:
        if r.get("html") and r.get("url"):
            pid = extract_post_id(r["html"][:60000])
            if pid:
                hint_ids[itm.norm_page(r["url"])] = pid
    resolved_fps = {r["fingerprint"] for r in hist_result["resolved"]}
    try:
        rem_counters = remediation.process_items(db_site, site_id, audit_id, items, site_cfg, glob, hint_ids, resolved_fps)
    except Exception:
        log.error("Fallo en el motor de correcciones:\n%s", traceback.format_exc())
        rem_counters = {"auto_applied": 0, "dry_run": 0, "failed": 0, "pending": 0, "skipped": 0}

    # 8) Opcion: reflejar "legitimo" en las alertas originales
    if glob["apply_legit_to_alerts"]:
        try:
            from database import ignore_threat
            for it in legit_items:
                if it.get("threat_id") and it.get("severity") in ("LOW", "MEDIUM", "INFO") and it.get("legit_by") == "ia":
                    ignore_threat(it["threat_id"])
        except Exception:
            log.warning("No se pudo marcar alertas legítimas como omitidas", exc_info=True)

    # 9) Guardado
    _save_findings(site_id, audit_id, items + legit_items)
    _save_resources(site_id, audit_id, link_rows)

    # 10) Hechos + analisis global
    link_summary = lk.summarize(link_rows)
    from database import get_audit
    a = get_audit(audit_id)
    audit_meta = {"id": audit_id, "status": (a["status"] if a else audit_status),
                  "started_at": a["started_at"] if a else None, "finished_at": a["finished_at"] if a else None,
                  "urls_analyzed": a["urls_analyzed"] if a else None}
    facts = reporting.build_facts(db_site, audit_meta, items, link_rows, link_summary, hist_result,
                                  rem_counters, expected_langs, ai_info, legit_items)
    _prev = _previous_summary(site_id, audit_id)
    if _prev:
        facts["history"]["previous_alerts"] = _prev["alerts"]
        facts["history"]["previous_groups"] = _prev["groups"]
    if ai_on and (facts["summary"]["alerts"] or facts["external_links"]["total"]):
        try:
            analysis = ai_context.write_analysis(facts)
        except Exception:
            log.warning("Análisis global falló", exc_info=True)
            analysis = {**ai_context.fallback_analysis(facts), "ai_used": False, "error": "internal",
                        "error_human": "Error interno al redactar el análisis con IA; se usó el análisis automático."}
    else:
        fb = ai_context.fallback_analysis(facts)
        analysis = {**fb, "ai_used": False, "error": None, "error_human": None}
    if not analysis.get("error_human") and ai_info.get("classify_error_human") and not ai_info["classify_used"]:
        analysis["error_human"] = ai_info["classify_error_human"]
    # El estado final es el MAS grave entre el calculado con reglas y el que sugiere la IA:
    # la IA puede subir la alerta, nunca rebajar lo que las reglas ya detectaron.
    _rank = {"limpio": 0, "atencion": 1, "comprometido": 2}
    _ai_state = analysis.get("site_state")
    if _ai_state in _rank and _rank[_ai_state] > _rank.get(facts["site_state"], 1):
        facts["site_state"] = _ai_state
    report = {"version": 1, "generated_at": store.now_iso(), "facts": facts, "analysis": analysis}

    # 11) Guardar reporte y enviar
    dispatch_res = []
    with get_conn() as conn:
        conn.execute(
            """INSERT OR IGNORE INTO enh_reports (site_id, audit_id, created_at, ai_used, ai_error, report, dispatch)
               VALUES (?,?,?,?,?,?,?)""",
            (site_id, audit_id, report["generated_at"], 1 if (ai_info["classify_used"] or analysis.get("ai_used")) else 0,
             analysis.get("error_human"), store.jdump(report), None))
    if send and site_cfg["report"]["mode"] == "after_each_audit":
        try:
            dispatch_res = distribution.dispatch(site_id, report)
        except Exception:
            log.warning("Envío del reporte falló", exc_info=True)
            dispatch_res = [{"channel": "-", "target": "-", "ok": False, "error": "error interno al enviar"}]
        if dispatch_res:
            with get_conn() as conn:
                conn.execute("UPDATE enh_reports SET dispatch=? WHERE audit_id=?", (store.jdump(dispatch_res), audit_id))
    s = facts["summary"]
    log.info("[%s] Reporte listo: %d alertas, %d grupos, %d corregidas, %d pendientes, %d persistentes, %d resueltas",
             db_site["name"], s["alerts"], s["groups"], s["auto_fixed"], s["pending"], s["persistent"], s["resolved"])
    return report


# ------------------------------------------------------------------
# Lectura (interfaz)
# ------------------------------------------------------------------
def get_report(report_id: int = None, site_id: int = None, audit_id: int = None):
    store.ensure_schema()
    q, params = "SELECT * FROM enh_reports WHERE 1=1", []
    if report_id:
        q += " AND id=?"; params.append(report_id)
    if site_id:
        q += " AND site_id=?"; params.append(site_id)
    if audit_id:
        q += " AND audit_id=?"; params.append(audit_id)
    q += " ORDER BY id DESC LIMIT 1"
    with get_conn() as conn:
        row = conn.execute(q, params).fetchone()
    if not row:
        return None
    d = dict(row)
    d["report"] = store.jload(row["report"], {})
    d["dispatch"] = store.jload(row["dispatch"], [])
    return d


def list_reports(site_id: int = None, limit: int = 30) -> list:
    store.ensure_schema()
    q = ("SELECT r.id, r.site_id, r.audit_id, r.created_at, r.ai_used, r.dispatch, s.name AS site_name "
         "FROM enh_reports r JOIN sites s ON s.id=r.site_id")
    params = []
    if site_id:
        q += " WHERE r.site_id=?"; params.append(site_id)
    q += " ORDER BY r.id DESC LIMIT ?"; params.append(limit)
    with get_conn() as conn:
        return [dict(r) for r in conn.execute(q, params).fetchall()]
