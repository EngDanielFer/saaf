#!/home/admin_ubuntu/Desktop/proyecto_saaf/opt/saaf/venv/bin/python
# =============================================================
# SAAF Pro — test_fase5.py
# Pruebas de las mejoras: lista de exclusiones, severidad por señales
# y estado real de las auditorias (ver Mejoras_auditoria_y_alertas.docx).
# Ejecutar:  venv/bin/python tests/test_fase5.py
# =============================================================

import os
import re
import sys
import json
import sqlite3
import tempfile
import traceback
from pathlib import Path
from datetime import datetime, timedelta, timezone

TMP = Path(tempfile.mkdtemp(prefix="saaf_t5_"))
os.environ["SAAF_DB_PATH"] = str(TMP / "test.db")
BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))
sys.path.insert(0, str(BASE / "scripts" / "python"))

_ok = _fail = 0


def ok(msg):
    global _ok
    _ok += 1
    print(f"  [OK] {msg}")


def fail(msg, err=""):
    global _fail
    _fail += 1
    print(f"  [FAIL] {msg}")
    if err:
        print(f"         {err}")


def section(title):
    print("\n" + "=" * 55 + f"\n  {title}\n" + "=" * 55)
    

def check(cond, msg):
    """assert con reporte: no aborta el resto de las pruebas."""
    if cond:
        ok(msg)
    else:
        fail(msg)
    return cond


def run(name, fn):
    try:
        fn()
    except Exception as e:  # noqa
        fail(name, f"{type(e).__name__}: {e}")
        traceback.print_exc(limit=3)


import database as db
from audit_state import *  # noqa
import severity as sev

db.init_db()
SITE = db.upsert_site("Lopez Morales Abogados", "https://lopezmorales.com", niche="legal")
SITE2 = db.upsert_site("Otra Campaña", "https://otra.com", niche="blog")


# ----------------------------------------------------------------
def t_lifecycle():
    section("Auditorias — ciclo de vida")
    a = db.start_audit(SITE)
    r = db.get_audit(a)
    check(r["status"] == RUNNING and r["worker_pid"] == os.getpid(), "start_audit crea RUNNING con PID del proceso")
    alive, cancel = db.touch_audit(a, stage="Descargando páginas", progress=40, pages_done=4, pages_total=10, warning="Página X falló")
    r = db.get_audit(a)
    check(alive and not cancel and r["current_stage"] == "Descargando páginas" and r["progress"] == 40, "touch_audit registra etapa, progreso y latido")
    db.touch_audit(a, warning="Página X falló")
    check(db.get_audit(a)["warnings"].count("Página X falló") == 1, "advertencias repetidas no se duplican")
    check(db.finish_audit(a, "sitemap", 10, "COMPLETED_WITH_WARNINGS", severity_max="ALTO"), "finish_audit cierra la auditoria")
    r = db.get_audit(a)
    check(r["status"] == COMPLETED_WITH_WARNINGS and r["severity_max"] == "HIGH" and r["progress"] == 100, "estado final + severidad legada normalizada (ALTO->HIGH)")
    check(not db.finish_audit(a, "sitemap", 10, "FAILED", error_msg="x"), "un estado final NO se sobrescribe")
    check(db.get_audit(a)["status"] == COMPLETED_WITH_WARNINGS, "...y conserva el estado original")
    check(db.touch_audit(a) == (False, False), "touch_audit sobre auditoria cerrada devuelve (False, False)")

    b = db.start_audit(SITE)
    db.finish_audit(b, "none", 0, "issues")
    check(db.get_audit(b)["status"] == COMPLETED, "valores antiguos ('issues') se aceptan y migran a COMPLETED")
    c = db.start_audit(SITE)
    db.finish_audit(c, "none", 0, "error", error_msg="boom")
    check(db.get_audit(c)["status"] == FAILED, "valor antiguo 'error' -> FAILED")
    tmp = db.start_audit(SITE)
    try:
        db.finish_audit(tmp, "none", 0, "RUNNING"); fail("finish_audit debe rechazar estados no finales")
    except ValueError:
        ok("finish_audit rechaza estados no finales")
    db.finish_audit(tmp, "none", 0, COMPLETED)
    act = db.start_audit(SITE)
    check(any(x["id"] == act for x in db.get_active_audits(SITE)), "get_active_audits ve la auditoria abierta")
    db.finish_audit(act, "none", 0, COMPLETED)
    check(not any(x["id"] == act for x in db.get_active_audits(SITE)), "...y deja de verla al cerrarse")
    

def t_pending_cancel():
    section("Auditorias — PENDING y cancelación")
    p = db.start_audit(SITE2, status="PENDING")
    check(db.get_audit(p)["status"] == PENDING, "auditoria en cola = PENDING")
    check(db.mark_audit_running(p), "PENDING -> RUNNING")
    check(db.get_audit(p)["status"] == RUNNING, "queda RUNNING")
    check(not db.mark_audit_running(p), "no se puede iniciar dos veces")
    n = db.request_cancel_audits(audit_id=p)
    check(n == 1, "solicitud de cancelación registrada")
    alive, cancel = db.touch_audit(p, stage="X")
    check(alive and cancel, "el worker vivo ve la cancelación en su siguiente latido")
    db.finish_audit(p, "none", 0, CANCELLED, error_msg="Cancelada por el usuario")
    check(db.get_audit(p)["status"] == CANCELLED, "cierra como CANCELLED")
    q = db.start_audit(SITE2, status="PENDING")
    db.request_cancel_audits(audit_id=q)
    check(not db.mark_audit_running(q), "una PENDING cancelada ya no arranca")
    db.finish_audit(q, "none", 0, CANCELLED)


def t_reaper():
    section("Vigilante — auditorias que dejaron de ejecutarse")
    now = datetime.now(timezone.utc)

    # a) proceso muerto (PID inexistente) + sin actividad
    a = db.start_audit(SITE)
    old = (now - timedelta(minutes=5)).isoformat()
    with db.get_conn() as c:
        c.execute("UPDATE audits SET worker_pid=?, last_activity_at=?, current_stage='Analizando scripts externos' WHERE id=?", (2**22 - 3, old, a))
    closed = db.reap_stale_audits()
    r = db.get_audit(a)
    check(r["status"] == FAILED and "Analizando scripts externos" in r["error_msg"], "PID inexistente + sin actividad -> FAILED con la etapa")
    check(any(x["id"] == a for x in closed), "el vigilante reporta lo cerrado")

    # b) PID inexistente pero actividad MUY reciente: NO se toca (evita falsos positivos)
    b = db.start_audit(SITE)
    with db.get_conn() as c:
        c.execute("UPDATE audits SET worker_pid=? WHERE id=?", (2**22 - 3, b))
    db.reap_stale_audits()
    check(db.get_audit(b)["status"] == RUNNING, "actividad reciente dentro de la gracia: sigue RUNNING")

    # c) proceso vivo (este) pero sin latido > umbral -> colgado
    c_ = db.start_audit(SITE)
    with db.get_conn() as c:
        c.execute("UPDATE audits SET last_activity_at=? WHERE id=?", ((now - timedelta(minutes=30)).isoformat(), c_))
    db.reap_stale_audits()
    r = db.get_audit(c_)
    check(r["status"] == FAILED and "dejó de responder" in r["error_msg"], "proceso vivo sin latido > 10 min -> FAILED (colgado)")

    # d) proceso vivo y con latido: se respeta
    d = db.start_audit(SITE)
    db.touch_audit(d, stage="Descargando páginas")
    db.reap_stale_audits()
    check(db.get_audit(d)["status"] == RUNNING, "auditoria sana (vivo + latido) no se toca")
    
    # e) un worker zombi no puede resucitar una auditoria ya cerrada
    check(not db.finish_audit(c_, "sitemap", 5, COMPLETED), "worker colgado que despierta NO sobrescribe el FAILED")
    check(db.touch_audit(c_) == (False, False), "...y su siguiente latido le indica que debe abortar")
    db.finish_audit(d, "none", 0, COMPLETED); db.finish_audit(b, "none", 0, COMPLETED)

    # f) cancelacion pedida y nadie la atiende (PID muerto)
    f = db.start_audit(SITE2)
    with db.get_conn() as c:
        c.execute("UPDATE audits SET worker_pid=?, last_activity_at=? WHERE id=?", (2**22 - 3, old, f))
    db.request_cancel_audits(audit_id=f)
    check(db.get_audit(f)["status"] == CANCELLED, "cancelación con worker muerto se cierra de inmediato como CANCELLED")

    # g) PENDING huérfana
    g = db.start_audit(SITE2, status="PENDING")
    with db.get_conn() as c:
        c.execute("UPDATE audits SET worker_pid=?, last_activity_at=? WHERE id=?", (2**22 - 3, old, g))
    db.reap_stale_audits()
    r = db.get_audit(g)
    check(r["status"] == FAILED and "nunca llegó a iniciar" in r["error_msg"], "PENDING huérfana -> FAILED 'nunca llegó a iniciar'")

    # h) cycle_log colgado en 'running'
    cid = db.start_cycle_log()
    with db.get_conn() as c:
        c.execute("UPDATE cycle_logs SET started_at=? WHERE id=?", ((now - timedelta(hours=1)).isoformat(), cid))
    db.reap_stale_audits()
    with db.get_conn() as c:
        row = c.execute("SELECT status, error_msg FROM cycle_logs WHERE id=?", (cid,)).fetchone()
    check(row["status"] == "error" and "inesperada" in row["error_msg"], "cycle_log 'running' sin auditorias activas -> error")
    

def t_heartbeat_pending():
    section("Latido del ciclo cubre a las auditorias en cola")
    cid = db.start_cycle_log()
    run_a = db.start_audit(SITE, cycle_log_id=cid)
    pend = db.start_audit(SITE2, cycle_log_id=cid, status="PENDING")
    with db.get_conn() as c:
        c.execute("UPDATE audits SET last_activity_at=? WHERE id=?", ((datetime.now(timezone.utc) - timedelta(minutes=9)).isoformat(), pend))
    before = db.get_audit(pend)["last_activity_at"]
    db.touch_audit(run_a, stage="x")
    check(db.get_audit(pend)["last_activity_at"] > before, "touch_audit refresca la actividad de las PENDING del mismo ciclo")
    db.finish_audit(run_a, "none", 0, COMPLETED); db.finish_audit(pend, "none", 0, CANCELLED)
    db.finish_cycle_log(cid, "ok")


# ----------------------------------------------------------------
def t_threats_allowlist():
    section("Amenazas y lista permitida (BD)")
    aud = db.start_audit(SITE)
    ids = {}
    ids["rc"] = db.add_threat(aud, SITE, "hidden_iframe", "ALTO", "Iframe oculto detectado: src='https://www.google.com/recaptcha/api2/aframe'",
                              url_found="https://lopezmorales.com/", resource_url="https://www.google.com/recaptcha/api2/aframe")
    ids["mm"] = db.add_threat(aud, SITE, "hidden_spam_link", "CRITICAL", "Link oculto", url_found="https://lopezmorales.com/", resource_url="https://m.me/lopezylopezabogado")
    ids["mm2"] = db.add_threat(aud, SITE2, "hidden_spam_link", "CRITICAL", "Link oculto", url_found="https://otra.com/", resource_url="https://m.me/lopezylopezabogado")
    ids["dk"] = db.add_threat(aud, SITE, "external_script", "CRITICAL", "Script", url_found="https://lopezmorales.com/", resource_url="https://draft-kings.bet/projects/moscwagang/mini.js.php",
                              signals=[sev.Signal("high_risk_tld", 3, "TLD .bet", True)])
    ids["inf"] = db.add_threat(aud, SITE, "hidden_iframe", "INFO", "info", resource_url="https://www.youtube.com/embed/x")
    try:
        db.add_threat(aud, SITE, "x", "GRAVISIMO", "d"); fail("severidad invalida debe rechazarse")
    except ValueError:
        ok("add_threat rechaza severidades inválidas")
    
    check(len(db.get_open_threats(SITE)) == 4, "get_open_threats lista las abiertas del sitio")
    check(len(db.get_open_threats(SITE, include_info=False)) == 3, "include_info=False excluye INFO")
    check(db.get_open_threats(SITE)[0]["severity"] == "CRITICAL", "orden: CRITICAL primero")
    sm = db.get_dashboard_summary()
    check(sm["open_critical"] == 3 and sm["open_high"] == 1, "resumen del dashboard con severidades nuevas")
    check(sm["open_total"] == 4, "open_total no cuenta INFO")
    
    # --- Regla GLOBAL de reCAPTCHA ---
    r1 = db.add_allowlist_rule("global", "google.com/recaptcha/", reason="reCAPTCHA legítimo")
    try:
        db.add_allowlist_rule("global", "google.com/recaptcha/"); fail("duplicado debe rechazarse")
    except ValueError as e:
        ok("regla duplicada rechazada")
    # --- Regla por CAMPAÑA ---
    r2 = db.add_allowlist_rule("site", "https://m.me/lopezylopezabogado", site_id=SITE, reason="Messenger del cliente")
    n1 = db.apply_rule_to_open_threats(r1); n2 = db.apply_rule_to_open_threats(r2)
    check(n1 == 1 and n2 == 1, "las reglas se aplican a las alertas abiertas que ya coinciden")
    open_ids = {t["id"] for t in db.get_open_threats()}
    check(ids["rc"] not in open_ids and ids["mm"] not in open_ids, "las alertas permitidas dejan de mostrarse")
    check(ids["mm2"] in open_ids, "la regla de una campaña NO afecta a otra campaña (requisito del doc)")
    check(ids["dk"] in open_ids, "el script malicioso sigue siendo alerta")
    eff = {r["id"] for r in db.get_effective_allowlist(SITE)}; eff2 = {r["id"] for r in db.get_effective_allowlist(SITE2)}
    check(eff == {r1, r2} and eff2 == {r1}, "get_effective_allowlist = globales + las de esa campaña")
    
    # desactivar / reactivar / eliminar
    db.set_allowlist_rule_active(r2, False)
    check(ids["mm"] in {t["id"] for t in db.get_open_threats()}, "desactivar la regla devuelve la alerta")
    db.set_allowlist_rule_active(r2, True)
    check(ids["mm"] not in {t["id"] for t in db.get_open_threats()}, "reactivar la regla la oculta de nuevo")
    db.delete_allowlist_rule(r2)
    check(ids["mm"] in {t["id"] for t in db.get_open_threats()}, "eliminar la regla devuelve la alerta")
    check(db.get_allowlist_rule(r2) is None, "regla eliminada")
    # editar
    db.update_allowlist_rule(r1, pattern="gstatic.com/recaptcha/", reason="cambio")
    check(ids["rc"] in {t["id"] for t in db.get_open_threats()}, "editar el patrón libera lo que ya no coincide")
    db.record_allowlist_hits({r1: 3}); db.record_allowlist_hits({r1: 2})
    check(db.get_allowlist_rule(r1)["hit_count"] == 5 and db.get_allowlist_rule(r1)["last_hit_at"], "hit_count y last_hit_at se acumulan")
    try:
        db.add_allowlist_rule("global", "google"); fail("patrón peligroso debe rechazarse")
    except ValueError:
        ok("add_allowlist_rule valida el patrón (rechaza 'google')")
    db.finish_audit(aud, "none", 1, COMPLETED)
    # borrar el sitio elimina sus reglas
    db.delete_site(SITE2)
    check(True, "delete_site con FK no revienta")
    
    
# ----------------------------------------------------------------
# ORQUESTADOR (integracion con scraper / crawler / Claude / alertas simulados)
# ----------------------------------------------------------------
from unittest.mock import patch, MagicMock

MAL_SCRIPT = ('<script id="asahi-jquery-min-bundle-js" '
              'src="https://draft-kings.bet/projects/moscwagang/mini.js.php"></script>')
RECAPTCHA = ('<iframe src="https://www.google.com/recaptcha/api2/aframe" width="0" height="0" '
             'style="display:none"></iframe>')
OTHER_BAD = '<script src="https://evil-loader.xyz/wp-content/uploads/a.php"></script>'


def page(url, body):
    return {"html": f"<html><head>{body}</head><body>ok</body></html>", "url": url,
            "status_code": 200, "response_time_ms": 12, "error": None}
    

def bad_page(url, err="Timeout en scraper"):
    return {"html": None, "url": url, "status_code": None, "response_time_ms": None, "error": err}


class Env:
    """Contexto con orchestrator parcheado. pages: {url: dict|callable}."""

    def __init__(self, pages, claude=None, urls=None, alert=None):
        self.pages, self.claude = pages, claude
        self.urls = urls
        self.alert = alert or MagicMock(return_value={"emails_sent": 1, "sms_sent": 0})
        self.down = MagicMock()
        self.scrape_calls = []
    
    def __enter__(self):
        import orchestrator as o
        from crawler import CrawlResult
        self.o = o

        def scraper(url):
            self.scrape_calls.append(url)
            v = self.pages.get(url) or self.pages.get(url.rstrip("/"))
            return v() if callable(v) else (v or bad_page(url, "404"))

        def get_urls(site, max_pages=None, on_progress=None):
            if on_progress:
                on_progress("crawl")
            mine = self.urls if self.urls is not None else [
                k for k in self.pages if k.startswith(site["url"])
            ]
            return CrawlResult(urls=list(mine), method="sitemap")

        from claude_analyzer import ClaudeResult
        self.ps = [
            patch.object(o, "_run_scraper", scraper),
            patch.object(o, "get_urls", get_urls),
            patch.object(o, "claude_analyze", self.claude or (lambda *a, **k: ClaudeResult(triggered=False))),
            patch.object(o, "send_threat_alert", self.alert),
            patch.object(o, "send_site_down_alert", self.down),
        ]
        for p in self.ps:
            p.start()
        return self
    
    def __exit__(self, *a):
        for p in self.ps:
            p.stop()
    
    
SITE_D = {"name": "Lopez Morales Abogados", "url": "https://lopezmorales.com", "niche": "legal", "priority": "high"}


def fresh_site(name="S"):
    """Sitio nuevo y aislado para cada escenario."""
    n = len(db.get_all_sites()) + 1
    d = {"name": f"{name}{n}", "url": f"https://site{n}.example.com", "niche": "general", "priority": "normal", "sitemap_url": None}
    db.upsert_site(d["name"], d["url"], niche="general")
    return d, db.get_site_by_url(d["url"])["id"]


def t_orch_doc_case():
    section("Orquestador — caso del documento (draft-kings + reCAPTCHA)")
    site, sid = fresh_site()
    u = site["url"]
    pages = {u: page(u, MAL_SCRIPT + RECAPTCHA)}
    with Env(pages) as e:
        r = e.o.audit_site(site)
    a = db.get_audit(r["audit_id"])
    check(r["status"] == COMPLETED and a["status"] == COMPLETED, "auditoria COMPLETED")
    th = {t["resource_url"]: t for t in db.get_all_threats(sid)}
    dk = th.get("https://draft-kings.bet/projects/moscwagang/mini.js.php")
    check(dk is not None and dk["severity"] == "CRITICAL", "draft-kings.bet/.../mini.js.php => CRITICAL (antes MEDIUM)")
    sigs = json.loads(dk["signals"])
    check(sum(1 for s in sigs if s["strong"]) >= 3, f"guarda las señales que lo justifican ({len(sigs)} señales, >=3 fuertes)")
    rc = th.get("https://www.google.com/recaptcha/api2/aframe")
    check(rc is not None and rc["severity"] == "INFO", "reCAPTCHA aframe NO es crítico: queda INFO")
    check(a["severity_max"] == "CRITICAL" and r["has_issues"], "severity_max = CRITICAL")
    args = e.alert.call_args[0]
    check(any(t.severity == "CRITICAL" for t in args[1]), "se envía alerta por el CRITICAL")
    
    # --- ahora con exclusiones global + sitio ---
    db.add_allowlist_rule("global", "google.com/recaptcha/")
    db.add_allowlist_rule("site", "https://draft-kings.bet/projects/moscwagang/mini.js.php", site_id=sid, reason="prueba")
    with Env(pages) as e:
        r = e.o.audit_site(site)
    a = db.get_audit(r["audit_id"])
    check(a["allowlisted_count"] == 2 and not r["threats"], "recursos permitidos: detectados y reconocidos (allowlisted_count=2), sin amenazas")
    check(a["severity_max"] is None and not r["has_issues"], "ya no aparecen como riesgo")
    check(sum(x["hit_count"] for x in db.get_allowlist_rules()) >= 2, "las reglas registran sus aciertos (hit_count)")
    check(not e.alert.called, "no hay alerta para recursos permitidos")
    
    
def t_orch_claude_failures():
    section("Orquestador — falla del proveedor de IA")
    from claude_analyzer import ClaudeResult
    site, sid = fresh_site()
    u = site["url"]
    pages = {u: page(u, MAL_SCRIPT)}
    cred = lambda *a, **k: ClaudeResult(triggered=True, error="400 credit balance is too low", error_code="credits",
                                        error_human="Créditos insuficientes en el proveedor de IA.")
    with Env(pages, claude=cred) as e:
        r = e.o.audit_site(site)
    a = db.get_audit(r["audit_id"])
    check(a["status"] == FAILED and a["error_msg"] == "Créditos insuficientes en el proveedor de IA.", "créditos agotados => FAILED con el motivo (ya no se queda 'ok'/RUNNING)")
    check(len(db.get_all_threats(sid)) == 1, "las amenazas por patrones SE GUARDAN igual")
    check(e.alert.called, "...y la alerta CRITICAL se envía igual")
    check(a["finished_at"] and a["status"] != RUNNING, "tiene fecha de fin")

    with patch.object(__import__("orchestrator"), "AI_ERROR_FAILS_AUDIT", False):
        site2, _ = fresh_site()
        with Env({site2["url"]: page(site2["url"], MAL_SCRIPT)}, claude=cred) as e:
            r = e.o.audit_site(site2)
    a = db.get_audit(r["audit_id"])
    check(a["status"] == COMPLETED_WITH_WARNINGS and "Créditos" in (a["warnings"] or ""), "con SAAF_AI_ERROR_FAILS_AUDIT=0 => COMPLETED_WITH_WARNINGS")

    # sin API key NO es una falla
    site3, _ = fresh_site()
    nokey = lambda *a, **k: ClaudeResult(triggered=False, error="ANTHROPIC_API_KEY no configurada", error_code="not_configured")
    with Env({site3["url"]: page(site3["url"], MAL_SCRIPT)}, claude=nokey) as e:
        r = e.o.audit_site(site3)
    check(db.get_audit(r["audit_id"])["status"] == COMPLETED, "sin ANTHROPIC_API_KEY: COMPLETED (no es una falla)")
    
    
def t_orch_claude_real_wiring():
    section("claude_analyzer.analyze — clasificación real del error")
    import claude_analyzer as ca
    from analyzer import Threat

    class BadRequestError(Exception):
        status_code = 400

    class FakeClient:
        def __init__(self, **kw):
            FakeClient.kw = kw
            self.messages = self
        def create(self, **kw):
            raise BadRequestError("Error code: 400 - Your credit balance is too low to access the Anthropic API.")

    import anthropic
    html = [{"html": "<html></html>", "url": "https://x.com", "error": None}]
    with patch.object(anthropic, "Anthropic", FakeClient), patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-ant-test"}):
        res = ca.analyze(html, {"name": "x", "url": "https://x.com"}, pattern_threats=[Threat("hidden_iframe", "d")])
    check(res.failed and res.error_code == "credits" and "Créditos insuficientes" in res.error_human, "analyze() devuelve error_code=credits + mensaje claro")
    check(FakeClient.kw.get("timeout") == ca.CLAUDE_TIMEOUT_S and FakeClient.kw.get("max_retries") == ca.CLAUDE_MAX_RETRIES, "el cliente se crea con timeout y max_retries explícitos")
    
    
def t_orch_warnings_and_total_failure():
    section("Orquestador — páginas fallidas")
    site, sid = fresh_site(); u = site["url"]
    pages = {u: page(u, ""), u + "/a": bad_page(u + "/a", "Timeout en scraper"), u + "/b": page(u + "/b", "")}
    with Env(pages) as e:
        r = e.o.audit_site(site)
    a = db.get_audit(r["audit_id"])
    check(a["status"] == COMPLETED_WITH_WARNINGS and "1 de 3 páginas" in a["warnings"], "algunas páginas fallan => COMPLETED_WITH_WARNINGS con el detalle")
    check(a["pages_total"] == 3 and a["pages_done"] == 2, "registra páginas totales/descargadas")

    site, sid = fresh_site(); u = site["url"]
    with Env({u: bad_page(u, "ECONNREFUSED")}) as e:
        r = e.o.audit_site(site)
    a = db.get_audit(r["audit_id"])
    check(a["status"] == FAILED and "No se pudo descargar ninguna página" in a["error_msg"], "ninguna página descargable => FAILED (antes quedaba 'ok')")
    check(e.down.called and r["is_up"] is False, "sitio caído: se envía la alerta de caída")


def t_orch_cancel_interrupt_timeout():
    section("Orquestador — cancelación, interrupción, vigilante y tiempo máximo")
    # a) cancelación manual a mitad de la descarga
    site, sid = fresh_site(); u = site["url"]
    holder = {}

    def second_page():
        db.request_cancel_audits(site_id=sid)      # el usuario pulsa "Cancelar"
        return page(u + "/2", "")
    pages = {u: page(u, ""), u + "/1": page(u + "/1", ""), u + "/2": second_page, u + "/3": page(u + "/3", ""), u + "/4": page(u + "/4", "")}
    with Env(pages) as e:
        r = e.o.audit_site(site)
    a = db.get_audit(r["audit_id"])
    check(a["status"] == CANCELLED and "cancelada manualmente" in a["error_msg"], "cancelación manual => CANCELLED")
    check(u + "/4" not in e.scrape_calls, "tras cancelar no se siguen descargando páginas")
    
    # b) SIGTERM / reinicio del servicio durante la descarga
    site, sid = fresh_site(); u = site["url"]
    def boom():
        raise SystemExit(143)
    with Env({u: page(u, ""), u + "/1": boom}) as e:
        try:
            e.o.audit_site(site); fail("SystemExit debe re-lanzarse")
        except SystemExit:
            ok("SystemExit se re-lanza (el proceso termina)")
    a = db.get_audit(db.get_site_audits(sid)[0]["id"])
    check(a["status"] == FAILED and "interrumpido" in a["error_msg"] and "Descargando páginas" in a["error_msg"], "proceso interrumpido => FAILED con la etapa (no queda RUNNING)")

    # c) excepcion no controlada en el analisis
    site, sid = fresh_site(); u = site["url"]
    with Env({u: page(u, "")}) as e, patch.object(e.o, "analyze_html", side_effect=RuntimeError("kaboom")):
        r = e.o.audit_site(site)
    a = db.get_audit(r["audit_id"])
    check(a["status"] == FAILED and "kaboom" in a["error_msg"] and "Analizando HTML" in a["error_msg"], "excepción no controlada => FAILED con motivo y etapa")
    
    # d) el vigilante cerro la auditoria mientras el worker seguia (colgado que despierta)
    site, sid = fresh_site(); u = site["url"]
    def reaped_midway():
        with db.get_conn() as c:
            c.execute("UPDATE audits SET status='FAILED', error_msg='cerrada por el vigilante' WHERE site_id=? AND status='RUNNING'", (sid,))
        return page(u + "/1", "")
    with Env({u: page(u, ""), u + "/1": reaped_midway, u + "/2": page(u + "/2", "")}) as e:
        r = e.o.audit_site(site)
    a = db.get_audit(r["audit_id"])
    check(a["status"] == FAILED and a["error_msg"] == "cerrada por el vigilante", "worker que despierta tras el vigilante NO sobrescribe el FAILED")
    check(u + "/2" not in e.scrape_calls, "...y se detiene (AuditAborted)")
    
    # e) tiempo maximo
    site, sid = fresh_site(); u = site["url"]
    import orchestrator as o
    with Env({u: page(u, ""), u + "/1": page(u + "/1", "")}) as e, patch.object(o, "MAX_AUDIT_MINUTES", 0.0):
        r = e.o.audit_site(site)
    a = db.get_audit(r["audit_id"])
    check(a["status"] == FAILED and "tiempo máximo" in a["error_msg"], "supera el tiempo máximo => FAILED")
    
    
def t_orch_dedup_hole():
    section("Orquestador — deduplicación por recurso (falso negativo)")
    site, sid = fresh_site(); u = site["url"]
    benign = '<script src="https://widget.tidio.co/abc.js"></script>'
    with Env({u: page(u, benign)}) as e:
        e.o.audit_site(site)
    check(not e.alert.called or all(t.severity not in ("CRITICAL", "HIGH") for t in e.alert.call_args[0][1]), "script externo común: sin alerta CRITICAL/HIGH")
    # 2da auditoria: misma pagina + un script MALICIOSO nuevo
    with Env({u: page(u, benign + MAL_SCRIPT)}) as e:
        r = e.o.audit_site(site)
    new = [t for t in r["threats"] if t.is_new]
    check(any("draft-kings.bet" in (t.resource_url or "") for t in new), "el script malicioso NUEVO en una página que ya tenía otro script se marca como nuevo")
    check(e.alert.called and any(t.severity == "CRITICAL" for t in e.alert.call_args[0][1]), "...y dispara la alerta (antes se perdía)")
    old = [t for t in r["threats"] if "tidio" in (t.resource_url or "")]
    check(old and not old[0].is_new, "el script ya conocido sigue sin ser nuevo")
    # 3ra: nada cambia -> sin alertas
    with Env({u: page(u, benign + MAL_SCRIPT)}) as e:
        e.o.audit_site(site)
    check(not e.alert.called, "sin cambios: no se repite la alerta")
    
    # amenaza antigua (sin resource_url, URL truncada a 100 chars) no vuelve a ser 'nueva'
    site, sid = fresh_site(); u = site["url"]
    long_src = "https://cdn.long-vendor.example.net/" + "a" * 90 + "/script.js"
    aud = db.start_audit(sid); db.finish_audit(aud, "none", 1, COMPLETED)
    db.add_threat(aud, sid, "external_script", "MEDIO", f"Script externo de dominio unknown: x (src='{long_src[:100]}')", url_found=u, is_new=True)
    with Env({u: page(u, f'<script src="{long_src}"></script>')}) as e:
        r = e.o.audit_site(site)
    check(r["threats"] and not r["threats"][0].is_new, "amenaza heredada (URL truncada a 100 chars) se reconoce como ya conocida: sin re-alerta masiva")
    
    
def t_orch_cycle():
    section("run_cycle — cola PENDING, cancelación y cierre")
    import orchestrator as o
    sA, idA = fresh_site("A"); sB, idB = fresh_site("B"); sC, idC = fresh_site("C")
    states_seen = {}

    def scraper_for(site, cancel_next=None):
        def f():
            with db.get_conn() as c:
                cid = c.execute("SELECT MAX(id) FROM cycle_logs").fetchone()[0]
            states_seen[site["name"]] = {x["site_id"]: x["status"] for x in db.get_cycle_audits(cid)}
            if cancel_next:
                db.request_cancel_audits(site_id=cancel_next)
            return page(site["url"], "")
        return f
    pages = {sA["url"]: scraper_for(sA, cancel_next=idC), sB["url"]: scraper_for(sB), sC["url"]: scraper_for(sC)}
    with Env(pages) as e, patch.object(o, "load_and_sync_sites", return_value=[sA, sB, sC]):
        res = o.run_cycle()
    snap = states_seen[sA["name"]]
    check(snap.get(idA) == RUNNING and snap.get(idB) == PENDING and snap.get(idC) == PENDING, "durante la 1ª auditoría: A=RUNNING, B y C=PENDING (cola visible)")
    st = {r["site"]["name"]: r["status"] for r in res}
    check(st[sA["name"]] == COMPLETED and st[sB["name"]] == COMPLETED and st[sC["name"]] == CANCELLED, "C cancelada mientras esperaba: CANCELLED sin ejecutarse")
    check(sC["url"] not in e.scrape_calls, "la cancelada nunca llegó a descargar")
    with db.get_conn() as c:
        cl = c.execute("SELECT * FROM cycle_logs ORDER BY id DESC LIMIT 1").fetchone()
        left = c.execute("SELECT COUNT(*) FROM audits WHERE cycle_log_id=? AND status IN ('PENDING','RUNNING')", (cl["id"],)).fetchone()[0]
    check(cl["status"] == "error" and "cancelada" in cl["error_msg"] and cl["sites_total"] == 3, "cycle_log refleja la cancelación")
    check(left == 0, "no queda ninguna auditoría del ciclo en PENDING/RUNNING")
    
    # SIGTERM en medio del ciclo: nada queda PENDING/RUNNING
    sD, idD = fresh_site("D"); sE, idE = fresh_site("E")
    def term():
        raise SystemExit(143)
    with Env({sD["url"]: term, sE["url"]: page(sE["url"], "")}) as e, patch.object(o, "load_and_sync_sites", return_value=[sD, sE]):
        try:
            o.run_cycle(); fail("debe propagar SystemExit")
        except SystemExit:
            ok("SIGTERM durante el ciclo se propaga")
    with db.get_conn() as c:
        rows = {r["site_id"]: r for r in c.execute("SELECT * FROM audits WHERE site_id IN (?,?) ORDER BY id DESC", (idD, idE))}
    check(rows[idD]["status"] == FAILED and rows[idE]["status"] == FAILED and "terminó antes" in rows[idE]["error_msg"], "ninguna auditoría queda PENDING/RUNNING tras la interrupción")



# ----------------------------------------------------------------
# MODULOS PUROS: url_utils, allowlist, risk_signals, severity, audit_state
# ----------------------------------------------------------------
def t_url_utils():
    section("url_utils — coincidencia segura de URLs")
    from url_utils import url_matches, strip_www, registrable_domain, is_public_suffix, is_third_party
    cases = [
        ("https://www.google.com/recaptcha/api2/aframe", "google.com/recaptcha/", True),
        ("https://google.com.evil.tk/recaptcha/api2", "google.com/recaptcha/", False),
        ("https://notgoogle.com/recaptcha/", "google.com/recaptcha/", False),
        ("https://www.google.com/recaptchaX/", "google.com/recaptcha/", False),
        ("https://www.google.com/maps/embed", "google.com/recaptcha/", False),
        ("https://m.me/lopezylopezabogado", "https://m.me/lopezylopezabogado", True),
        ("https://m.me/lopezylopezabogado-evil", "https://m.me/lopezylopezabogado", False),
        ("https://M.ME/LopezyLopezAbogado", "m.me/lopezylopezabogado", True),
        ("//cdn.jsdelivr.net/npm/x.js", "jsdelivr.net", True),
        ("https://sub.cdn.example.com:8443/a.js", "example.com", True),
        ("https://example.com.co/x", "example.com", False),
        ("", "google.com", False),
        ("https://x.com/a", "", False),
    ]
    bad = [(u, p) for u, p, exp in cases if url_matches(u, p) != exp]
    check(not bad, f"{len(cases)} casos de coincidencia (incluye confusión de dominios) {bad or ''}")
    check(strip_www("wordpress.com") == "wordpress.com" and strip_www("www.wix.com") == "wix.com", "strip_www no borra letras (bug de lstrip('www.'))")
    check(registrable_domain("cdn.sub.ejemplo.com.co") == "ejemplo.com.co" and registrable_domain("a.draft-kings.bet") == "draft-kings.bet", "registrable_domain")
    check(is_public_suffix("com") and is_public_suffix("co.uk") and is_public_suffix("com.co") and not is_public_suffix("google.com"), "is_public_suffix")
    check(is_third_party("draft-kings.bet", "lopezmorales.com") and not is_third_party("cdn.lopezmorales.com", "www.lopezmorales.com"), "is_third_party")
    
    
def t_allowlist_module():
    section("allowlist — validación y matcher")
    from allowlist import validate_rule, AllowlistMatcher, extract_resource_url
    for sc, pat, mt, sid in [("global", "google.com/recaptcha/", "url", None), ("site", "https://m.me/lopezylopezabogado", "url", 7),
                             ("global", "recaptcha/api2", "contains", None), ("global", r"^https://([a-z0-9-]+\.)?youtube\.com/embed/", "regex", None)]:
        try:
            validate_rule(sc, pat, mt, sid); ok(f"acepta {mt}: {pat[:40]}")
        except ValueError as e:
            fail(f"rechazó algo válido: {pat}", e)
    for sc, pat, mt, sid in [("global", "google", "url", None), ("global", "com", "url", None), ("global", "co.uk", "url", None), ("global", "com.co", "url", None),
                             ("global", "", "url", None), ("site", "google.com", "url", None), ("global", "http", "contains", None), ("global", ".com", "contains", None),
                             ("global", "script", "contains", None), ("global", ".*", "regex", None), ("global", "(a+)+$", "regex", None), ("global", "[", "regex", None),
                             ("global", "http", "regex", None), ("global", "a b.com", "url", None), ("planeta", "google.com", "url", None)]:
        try:
            validate_rule(sc, pat, mt, sid); fail(f"aceptó algo peligroso: {(sc, pat, mt)}")
        except ValueError:
            ok(f"rechaza {mt}: {pat or '(vacío)'}")
    rules = [
        {"id": 1, "scope": "global", "site_id": None, "match_type": "url", "pattern": "google.com/recaptcha/", "threat_type": None, "active": 1},
        {"id": 2, "scope": "site", "site_id": 7, "match_type": "url", "pattern": "https://m.me/lopezylopezabogado", "threat_type": None, "active": 1},
        {"id": 3, "scope": "global", "site_id": None, "match_type": "url", "pattern": "inactiva.com", "threat_type": None, "active": 0},
        {"id": 4, "scope": "global", "site_id": None, "match_type": "url", "pattern": "solo-iframes.com", "threat_type": "hidden_iframe", "active": 1},
    ]
    m = AllowlistMatcher(rules)
    got = lambda u, s, t: (lambda r: r["id"] if r else None)(m.match(u, s, t))
    check(got("https://www.google.com/recaptcha/api2/aframe", 99, "hidden_iframe") == 1, "regla global aplica a cualquier campaña")
    check(got("https://m.me/lopezylopezabogado", 7, "hidden_spam_link") == 2, "regla de campaña aplica a su campaña")
    check(got("https://m.me/lopezylopezabogado", 8, "hidden_spam_link") is None, "regla de campaña NO aplica a otra campaña")
    check(got("https://inactiva.com/x.js", 7, "external_script") is None, "regla desactivada no aplica")
    check(got("https://solo-iframes.com/x", 7, "hidden_iframe") == 4 and got("https://solo-iframes.com/x", 7, "external_script") is None, "regla restringida a un tipo")
    check(got("https://draft-kings.bet/projects/moscwagang/mini.js.php", 7, "external_script") is None and got("", 7, "x") is None, "recurso malicioso / vacío no coincide")
    check(m.hits == {1: 1, 2: 1, 4: 1}, f"contador de aciertos por regla {m.hits}")
    check(extract_resource_url("external_script", "Script externo (src='https://x.bet/a.js')") == "https://x.bet/a.js", "extract_resource_url: src")
    check(extract_resource_url("hidden_spam_link", "Link href='https://m.me/x' texto='c'") == "https://m.me/x", "extract_resource_url: href")
    check(extract_resource_url("broken_internal_link", "dominio='viejo.com' en lugar de 'n.com'", "x") == "https://viejo.com/", "extract_resource_url: dominio antiguo")
    check(extract_resource_url("obfuscated_js", "JS ofuscado", "eval(atob('x'))") is None, "obfuscated_js: sin recurso")
    

def t_risk_and_severity():
    section("risk_signals y severity")
    import re as _re
    from risk_signals import evaluate_resource, brand_impersonated, trusted_prefix, SCRIPT, IFRAME
    from severity import classify_threat, normalize_severity, max_severity, summarize_severities, classify_threats
    SPAM = _re.compile(r"\b(casino|poker|bet(ting)?|viagra|porn|xxx)\b", _re.I)
    dk = "https://draft-kings.bet/projects/moscwagang/mini.js.php"
    codes = {s.code for s in evaluate_resource(dk, SCRIPT, tag_id="asahi-jquery-min-bundle-js", spam_pattern=SPAM)}
    check({"high_risk_tld", "brand_impersonation", "double_extension", "server_side_ext", "anomalous_path", "library_masquerade"} <= codes, f"draft-kings: todas las señales del documento {sorted(codes)}")
    for u in ["https://www.google.com/recaptcha/api2/aframe", "https://www.youtube.com/embed/dQw4w9WgXcQ", "https://googleads.g.doubleclick.net/pagead/x",
              "https://fundingchoicesmessages.google.com/f/AGSKW", "https://ep2.adtrafficquality.google/sodar/x.html"]:
        check(trusted_prefix(u) is not None, f"servicio de confianza: {u[:55]}")
    check(trusted_prefix("https://sites.google.com/view/spam") is None and trusted_prefix("https://google.com.evil.tk/recaptcha/") is None, "google.com en general / dominio falso NO son de confianza")
    ev = [s.code for s in evaluate_resource("https://www.youtube.com/embed/dQw4w9WgXcQ", IFRAME)]
    check("anomalous_path" not in ev, "ID de video de YouTube no se marca como ruta anómala")
    for h, exp in [("google.com", False), ("www.google.com.co", False), ("amazon.de", False), ("pineapple.com", False), ("google-analytics.com", False),
                   ("applesauce.com", False), ("draftkings.com", False), ("pay-pal.com", True), ("paypa1.com", True), ("paypal.com.secure-login.xyz", True),
                   ("paypal.xyz", True), ("draftkings.bet", True), ("draft-kings.bet", True)]:
        check(bool(brand_impersonated(h)) == exp, f"marca imitada: {h} -> {exp}")
        
    C = lambda t, n="general", ctx=None: classify_threat(t, n, ctx).severity
    check(C("external_script", "general", {"resource_url": dk, "tag_id": "asahi-jquery-min-bundle-js"}) == "CRITICAL", "draft-kings => CRITICAL (antes MEDIUM)")
    check(C("hidden_iframe", "general", {"resource_url": "https://www.google.com/recaptcha/api2/aframe"}) == "INFO", "reCAPTCHA aframe => INFO (no crítico)")
    check(C("hidden_iframe", "general", {"resource_url": "https://googleads.g.doubleclick.net/pagead/x"}) == "INFO", "iframe de Google Ads => INFO")
    check(C("external_script", "general", {"resource_url": "https://widget.tidio.co/a.js"}) == "MEDIUM", "script de tercero común => MEDIUM (como antes)")
    check(C("hidden_spam_link", "general", {"resource_url": "https://gist.github.com/x/abc"}) == "CRITICAL", "enlace oculto a gist.github.com sigue CRITICAL (no se rebaja)")
    check(C("hidden_spam_link", "general", {"resource_url": "https://m.me/lopezylopezabogado"}) == "CRITICAL", "m.me oculto es CRITICAL hasta que el usuario lo permita")
    check(C("external_script", "general", {"resource_url": "https://evil-tracker.com/a.js", "is_spam_domain": True}) == "HIGH", "dominio spam conocido => HIGH (como antes)")
    check(C("external_script", "general", {"resource_url": "https://evil.xyz/a.js", "is_spam_domain": True}) == "CRITICAL", "dominio spam + TLD abusado => CRITICAL")
    check(C("external_script", "ecommerce") == "HIGH" and C("external_script", "portfolio") == "LOW", "nicho: ecommerce HIGH (ya no CRITICAL), portfolio LOW")
    check(C("obfuscated_js", "ecommerce") == "CRITICAL" and C("obfuscated_js", "blog") == "HIGH" and C("hidden_iframe", "ecommerce") == "CRITICAL", "skimmers en ecommerce siguen CRITICAL")
    check(C("claude_anomaly") == "MEDIUM" and C("casino_pharma_adult") == "HIGH" and C("hidden_spam_link", "portfolio") == "CRITICAL", "tipos sin recurso conservan su severidad base")
    check(C("external_script", "general", {"resource_url": "https://x.bet/a.js", "tag_id": "x"}) in ("HIGH", "CRITICAL"), "script desde TLD .bet nunca queda en MEDIUM")
    check([normalize_severity(x) for x in ("CRITICO", "alto", "Medio", "BAJO", "CRÍTICO", "info", "x", None)] == ["CRITICAL", "HIGH", "MEDIUM", "LOW", "CRITICAL", "INFO", None, None], "normalize_severity acepta nombres antiguos / acentos")
    check(max_severity(["LOW", "ALTO", "INFO"]) == "HIGH" and max_severity([]) is None, "max_severity")

    class T:
        def __init__(s, tt, ctx=None): s.threat_type, s.extra_context, s.resource_url = tt, ctx or {}, (ctx or {}).get("resource_url")
    ts = classify_threats([T("external_script", {"resource_url": "https://w.tidio.co/a.js"}), T("external_script", {"resource_url": dk})], "general")
    check(ts[0].severity == "CRITICAL" and ts[0].signals and summarize_severities(ts)["CRITICAL"] == 1 and len(summarize_severities(ts)) == 5, "classify_threats ordena por severidad, adjunta señales y resume los 5 niveles")


def t_audit_state_module():
    section("audit_state — estados y errores")
    import json
    from audit_state import classify_exception, classify_result, normalize_status, fmt_duration, AuditError

    class E(Exception):
        def __init__(s, m, status=None): super().__init__(m); s.status_code = status
    class BadRequestError(E): pass
    class AuthenticationError(E): pass
    class RateLimitError(E): pass
    class InternalServerError(E): pass
    class APITimeoutError(Exception): pass
    class APIConnectionError(Exception): pass
    cases = [(BadRequestError("Error code: 400 - Your credit balance is too low to access the Anthropic API.", 400), "credits"),
             (AuthenticationError("invalid x-api-key", 401), "auth"), (RateLimitError("rate_limit_error", 429), "rate_limit"),
             (APITimeoutError("Request timed out."), "timeout"), (APIConnectionError("Connection error."), "connection"),
             (InternalServerError("oops", 500), "provider"), (E("overloaded_error", 529), "provider"),
             (json.JSONDecodeError("x", "y", 0), "invalid_response"), (TimeoutError("t"), "timeout"), (ConnectionRefusedError("r"), "connection"),
             (KeyboardInterrupt(), "interrupted"), (SystemExit(15), "interrupted"), (ZeroDivisionError("z"), "internal"),
             (AuditError("Tiempo máximo", "timeout"), "timeout")]
    bad = [type(e).__name__ for e, exp in cases if classify_exception(e)[0] != exp]
    check(not bad, f"{len(cases)} tipos de error clasificados {bad or ''}")
    check(classify_exception(BadRequestError("credit balance is too low", 400))[1] == "Créditos insuficientes en el proveedor de IA.", "mensaje de créditos exacto del documento")
    check(classify_exception(APITimeoutError("x"))[1] == "La API externa no respondió después del tiempo máximo permitido.", "mensaje de timeout exacto del documento")
    check([normalize_status(x) for x in ("running", "OK", "issues", "error", "completed_with_warnings", "basura", None)] == ["RUNNING", "COMPLETED", "COMPLETED", "FAILED", "COMPLETED_WITH_WARNINGS", None, None], "normalize_status (acepta valores antiguos)")
    check([classify_result(r) for r in ({"status": "FAILED"}, {"status": "COMPLETED", "has_issues": True}, {"status": "COMPLETED_WITH_WARNINGS"}, {"status": "COMPLETED", "is_up": False}, {"status": "CANCELLED"})] == ["error", "issues", "ok", "down", "cancelled"], "classify_result")
    check((fmt_duration(5), fmt_duration(90), fmt_duration(3725), fmt_duration(None)) == ("5s", "1m 30s", "1h 02m 05s", "—"), "fmt_duration")
    
    
def t_migration():
    section("Migración v2 — BD de la versión anterior")
    import shutil, subprocess, textwrap
    legacy = Path(__file__).resolve().parent / "fixtures" / "legacy_v1.sql"
    d = TMP / "mig"; d.mkdir(exist_ok=True)
    con = sqlite3.connect(d / "old.db"); con.executescript(legacy.read_text(encoding="utf-8")); con.close()
    code = textwrap.dedent(f'''
        import os, sys, sqlite3, json
        os.environ["SAAF_DB_PATH"] = r"{d / 'old.db'}"
        sys.path[:0] = [r"{BASE}", r"{BASE / 'scripts' / 'python'}"]
        import database as db
        db.init_db(); db.init_db()
        c = sqlite3.connect(os.environ["SAAF_DB_PATH"]); c.row_factory = sqlite3.Row
        out = {{
          "ver": c.execute("pragma user_version").fetchone()[0],
          "sev": dict(c.execute("select severity,count(*) from threats group by 1").fetchall()),
          "st": dict(c.execute("select status,count(*) from audits group by 1").fetchall()),
          "n": [c.execute(f"select count(*) from {{t}}").fetchone()[0] for t in ("sites","audits","threats")],
          "res": dict(c.execute("select threat_type,count(resource_url) from threats group by 1").fetchall()),
          "run_msg": c.execute("select error_msg from audits where id=3").fetchone()[0],
          "fk": c.execute("pragma foreign_key_check").fetchall(), "integ": c.execute("pragma integrity_check").fetchone()[0],
          "seq": c.execute("select seq from sqlite_sequence where name='audits'").fetchone()[0],
        }}
        print("JSON:" + json.dumps(out))
    ''')
    p = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True)
    line = [l for l in p.stdout.splitlines() if l.startswith("JSON:")]
    check(bool(line), f"la migración corre sin errores {p.stderr[-200:] if not line else ''}")
    if not line:
        return
    o = json.loads(line[0][5:])
    check(o["ver"] == 2 and o["n"] == [1, 4, 5], f"versión 2 y sin pérdida de filas {o['n']}")
    check(o["sev"] == {"CRITICAL": 1, "HIGH": 1, "LOW": 1, "MEDIUM": 2}, f"severidades convertidas {o['sev']}")
    check(o["st"] == {"COMPLETED": 2, "FAILED": 2}, f"estados: ok/issues->COMPLETED, error/running->FAILED {o['st']}")
    check("heredado" in (o["run_msg"] or ""), "una auditoría 'running' heredada pasa a FAILED con motivo explícito")
    check(o["res"].get("external_script") == 2 and o["res"].get("hidden_iframe") == 1 and o["res"].get("obfuscated_js") == 0, f"resource_url reconstruido {o['res']}")
    check(o["fk"] == [] and o["integ"] == "ok" and o["seq"] >= 4, "FK íntegras, integrity_check ok, secuencia preservada")
    shutil.rmtree(d, ignore_errors=True)
    
    
    
    if __name__ == "__main__":
        for name, fn in [
            ("url_utils", t_url_utils), ("allowlist_module", t_allowlist_module),
            ("risk_and_severity", t_risk_and_severity), ("audit_state_module", t_audit_state_module),
            ("migration", t_migration),
            ("lifecycle", t_lifecycle), ("pending_cancel", t_pending_cancel), ("reaper", t_reaper),
            ("heartbeat_pending", t_heartbeat_pending), ("threats_allowlist", t_threats_allowlist),
            ("orch_doc_case", t_orch_doc_case), ("orch_claude_failures", t_orch_claude_failures),
            ("orch_claude_real_wiring", t_orch_claude_real_wiring),
            ("orch_warnings", t_orch_warnings_and_total_failure),
            ("orch_cancel_interrupt", t_orch_cancel_interrupt_timeout),
            ("orch_dedup", t_orch_dedup_hole), ("orch_cycle", t_orch_cycle),
        ]:
            run(name, fn)
        print("\n" + "=" * 55 + f"\n  Resultado: {_ok} OK  |  {_fail} FAIL\n" + "=" * 55)
        sys.exit(1 if _fail else 0)