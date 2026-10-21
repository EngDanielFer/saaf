#!/home/admin_ubuntu/Desktop/proyecto_saaf/opt/saaf/venv/bin/python
# =============================================================
# SAAF Pro — test_fase5_ui.py
# Pruebas de la INTERFAZ (Streamlit AppTest, disponible desde 1.28):
# renderiza las vistas con una BD real e interactua con ellas.
# Ejecutar:  venv/bin/python tests/test_fase5_ui.py
# =============================================================

import os
import sys
import tempfile
import threading
import time
from pathlib import Path
from unittest.mock import patch

TMP = Path(tempfile.mkdtemp(prefix="saaf_ui_"))
os.environ["SAAF_DB_PATH"] = str(TMP / "ui.db")
BASE = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE))
sys.path.insert(0, str(BASE / "scripts" / "python"))

import streamlit as st
from streamlit.testing.v1 import AppTest

# AppTest (Streamlit 1.28) no reinicia el estado de un boton tras un st.rerun()
# INTERNO: el patron "if st.button(): ...; st.rerun()" (que usa toda la app y
# funciona en produccion) entra en bucle solo en el harness. Se neutraliza aqui
# y cada prueba comprueba el efecto en la BD y con una ejecucion fresca.
st.rerun = lambda *a, **k: None

import database as db

_ok = _fail = 0


def check(cond, msg):
    global _ok, _fail
    if cond:
        _ok += 1
        print(f"  [OK] {msg}")
    else:
        _fail += 1
        print(f"  [FAIL] {msg}")
    return cond


def section(t):
    print("\n" + "=" * 55 + f"\n  {t}\n" + "=" * 55)


PRE = f'''
import sys
sys.path.insert(0, "{BASE}")
sys.path.insert(0, "{BASE / 'scripts' / 'python'}")
'''


def app(code, **state):
    at = AppTest.from_string(PRE + code, default_timeout=30)
    for k, v in state.items():
        at.session_state[k] = v
    return at


def btn(at, label=None, key=None):
    for b in at.button:
        if (label is not None and b.label == label) or (key is not None and b.key == key):
            return b
    raise KeyError(label or key)


def press(at, button):
    """Pulsa un boton y emula el st.rerun() que la app hace despues (2a ejecucion)."""
    button.click()
    at.run()
    at.run()


def texts(at):
    """Todo el texto visible (markdown + captions + alertas)."""
    out = []
    for coll in (at.markdown, at.caption, at.error, at.warning, at.info, at.success):
        out += [e.value for e in coll]
    return "\n".join(out)


db.init_db()
SITE = db.upsert_site("Lopez Morales Abogados", "https://lopezmorales.com", niche="legal")
SITE2 = db.upsert_site("Otra Campaña", "https://otra.com", niche="blog")


def seed_threats():
    aud = db.start_audit(SITE)
    ids = {
        "mm": db.add_threat(aud, SITE, "hidden_spam_link", "CRITICAL", "Link oculto: href='https://m.me/lopezylopezabogado'",
                            url_found="https://lopezmorales.com/", resource_url="https://m.me/lopezylopezabogado"),
        "dk": db.add_threat(aud, SITE, "external_script", "CRITICAL", "Script externo", url_found="https://lopezmorales.com/",
                            resource_url="https://draft-kings.bet/projects/moscwagang/mini.js.php",
                            signals=[{"code": "high_risk_tld", "points": 3, "label": "TLD de alto riesgo (.bet)", "strong": True}]),
        "rc": db.add_threat(aud, SITE, "hidden_iframe", "INFO", "Iframe oculto", url_found="https://lopezmorales.com/",
                            resource_url="https://www.google.com/recaptcha/api2/aframe"),
        "js": db.add_threat(aud, SITE, "obfuscated_js", "HIGH", "JS ofuscado", url_found="https://lopezmorales.com/"),
    }
    aud2 = db.start_audit(SITE2)
    ids["mm2"] = db.add_threat(aud2, SITE2, "hidden_spam_link", "CRITICAL", "Link oculto", url_found="https://otra.com/",
                               resource_url="https://m.me/lopezylopezabogado")
    db.finish_audit(aud, "sitemap", 5, "COMPLETED", severity_max="CRITICAL")
    db.finish_audit(aud2, "sitemap", 5, "COMPLETED", severity_max="CRITICAL")
    return ids


ALERTS = "from views.alerts import render\nrender()\n"


def t_alerts():
    section("Alertas — renderizado y 'Agregar a lista permitida'")
    ids = seed_threats()
    at = app(ALERTS).run()
    check(not at.exception, "la página de Alertas renderiza sin excepciones")
    check([t.label for t in at.tabs] == ["🚨 Alertas activas", "✅ Lista permitida"], "tiene la pestaña 'Lista permitida'")
    check(sorted(at.multiselect[0].options) == ["CRITICAL", "HIGH", "INFO", "LOW", "MEDIUM"], "filtro con los 5 niveles")
    mets = {m.label: m.value for m in at.metric}
    check(mets["Total abiertas"] == "4" and mets["🔵 Info"] == "1", "métricas: INFO no cuenta como alerta abierta")
    check("TLD de alto riesgo" in texts(at), "se muestran las señales que justifican la severidad")
    check(f"allowbtn_{ids['mm']}" in [b.key for b in at.button], "botón 'Agregar a lista permitida' en alertas con recurso")
    check(f"allowbtn_{ids['js']}" not in [b.key for b in at.button], "...pero no en JS ofuscado (sin recurso comparable)")

    # --- solo esta campaña ---
    press(at, btn(at, key=f"allowbtn_{ids['mm']}"))
    check(not at.exception and any(b.label == "💾 Guardar exclusión" for b in at.button), "se abre el formulario de exclusión")
    radio = [r for r in at.radio if r.key == f"allow_{ids['mm']}_scope"][0]
    check(radio.options[0].startswith("Solo esta campaña (Lopez Morales") and radio.options[1] == "Todas las campañas", "opciones: solo esta campaña / todas las campañas")
    pat = [t for t in at.text_input if t.key == f"allow_{ids['mm']}_pattern"][0]
    check(pat.value == "m.me/lopezylopezabogado", "propone el patrón a partir del recurso")
    [t for t in at.text_input if t.key == f"allow_{ids['mm']}_reason"][0].set_value("Messenger del cliente")
    btn(at, "💾 Guardar exclusión").click(); at.run()  # una sola pasada: el camino de error no hace rerun
    check(not at.exception, "guardar no genera excepciones")
    rules = db.get_allowlist_rules()
    check(len(rules) == 1 and rules[0]["scope"] == "site" and rules[0]["site_id"] == SITE and rules[0]["reason"] == "Messenger del cliente", "regla creada: alcance campaña, con motivo")
    open_ids = {t["id"] for t in db.get_open_threats()}
    check(ids["mm"] not in open_ids and ids["mm2"] in open_ids, "la alerta desaparece; la de OTRA campaña sigue (requisito del doc)")
    check("Exclusión guardada" in texts(at), "mensaje de confirmación")
    
    # --- todas las campañas ---
    at = app(ALERTS).run()
    press(at, btn(at, key=f"allowbtn_{ids['mm2']}"))
    [r for r in at.radio if r.key == f"allow_{ids['mm2']}_scope"][0].set_value("Todas las campañas")
    btn(at, "💾 Guardar exclusión").click(); at.run()  # una sola pasada: el camino de error no hace rerun
    rules = {r["scope"]: r for r in db.get_allowlist_rules()}
    check("global" in rules and rules["global"]["site_id"] is None, "regla global creada (sin campaña)")

    # --- validación visible ---
    at = app(ALERTS).run()
    press(at, btn(at, key=f"allowbtn_{ids['dk']}"))
    [t for t in at.text_input if t.key == f"allow_{ids['dk']}_pattern"][0].set_value("google")
    btn(at, "💾 Guardar exclusión").click(); at.run()  # una sola pasada: el camino de error no hace rerun
    check(any("dominio completo" in e.value for e in at.error), "un patrón peligroso ('google') se rechaza con mensaje claro")
    check(ids["dk"] in {t["id"] for t in db.get_open_threats()}, "el script malicioso sigue siendo alerta")


def t_manager():
    section("Lista permitida — gestor")
    at = app(ALERTS).run()
    check(any(t.key == "allow_new_pattern" for t in at.text_input), "formulario de alta disponible")
    [t for t in at.text_input if t.key == "allow_new_pattern"][0].set_value("youtube.com/embed/")
    [t for t in at.text_input if t.key == "allow_new_reason"][0].set_value("videos del cliente")
    press(at, btn(at, "➕ Agregar exclusión"))
    check(any(r["pattern"] == "youtube.com/embed/" for r in db.get_allowlist_rules()), "alta manual de una exclusión global")
    check("youtube.com/embed/" in texts(at), "aparece en el listado")

    rid = [r["id"] for r in db.get_allowlist_rules() if r["pattern"] == "youtube.com/embed/"][0]
    at = app(ALERTS).run()
    press(at, btn(at, key=f"allow_tg_{rid}"))
    check(not db.get_allowlist_rule(rid)["active"], "desactivar una exclusión")
    at = app(ALERTS).run()
    press(at, btn(at, key=f"allow_ed_{rid}"))
    check(any(t.key == "allow_edit_pattern" for t in at.text_input), "editar abre el formulario con los datos actuales")
    [t for t in at.text_input if t.key == "allow_edit_pattern"][0].set_value("youtube-nocookie.com/embed/")
    press(at, btn(at, "💾 Guardar cambios"))
    check(db.get_allowlist_rule(rid)["pattern"] == "youtube-nocookie.com/embed/", "editar guarda el nuevo patrón")
    at = app(ALERTS).run()
    press(at, btn(at, key=f"allow_dl_{rid}"))
    check(db.get_allowlist_rule(rid) is not None and "¿Eliminar esta exclusión?" in texts(at), "eliminar pide confirmación (no borra al primer clic)")
    press(at, btn(at, key=f"allow_yes_{rid}"))
    check(db.get_allowlist_rule(rid) is None, "tras confirmar, se elimina")
    

def t_panel_and_dashboard():
    section("Dashboard — estado real de la auditoría")
    NO_AUTO = {"saaf_auto_refresh_audits": False}
    # sin auditorías activas -> historial; FAILED muestra el motivo
    a = db.start_audit(SITE2)
    db.finish_audit(a, "none", 0, "FAILED", error_msg="Créditos insuficientes en el proveedor de IA.")
    at = app("from views.dashboard import render\nrender()\n", **NO_AUTO).run()
    check(not at.exception, "el Dashboard renderiza sin excepciones")
    check("FAILED" in texts(at) and any("Créditos insuficientes" in e.value for e in at.error) or "Créditos insuficientes" in "".join(e.label for e in at.expander) + texts(at), "una auditoría FAILED muestra el motivo")

    # auditoría en curso
    run = db.start_audit(SITE)
    db.touch_audit(run, stage="Analizando scripts externos", progress=64, pages_done=7, pages_total=11, warning="1 de 11 páginas no se pudieron descargar")
    pend = db.start_audit(SITE2, status="PENDING")
    at = app("from views.dashboard import render\nrender()\n", **NO_AUTO).run()
    t = texts(at)
    check("Analizando scripts externos" in t, "muestra la etapa actual")
    check("RUNNING" in t and "PENDING" in t or "En cola" in t, "muestra estado RUNNING y la cola")
    check("Transcurrido" in t and "Última actividad" in t and "Inicio:" in t, "inicio, tiempo transcurrido y última actividad")
    check("páginas 7/11" in t, "progreso de páginas")
    check(len(at.get("progress")) >= 1, "barra de progreso")
    check("1 de 11 páginas" in t, "advertencias visibles")
    cancel = [b for b in at.button if b.key == f"dash_audits_cancel_{run}"]
    check(len(cancel) == 1, "botón Cancelar en la auditoría en curso")
    press(at, cancel[0])
    check(db.get_audit(run)["cancel_requested"] == 1, "Cancelar registra la solicitud (cooperativa)")
    check("Cancelación solicitada" in texts(at), "...y la UI lo indica")
    db.finish_audit(run, "none", 0, "CANCELLED", error_msg="Auditoría cancelada manualmente."); db.finish_audit(pend, "none", 0, "CANCELLED")
    
    # una auditoría colgada se cierra sola al abrir el panel (estado real)
    from datetime import datetime, timedelta, timezone
    zombie = db.start_audit(SITE)
    with db.get_conn() as c:
        c.execute("UPDATE audits SET worker_pid=?, last_activity_at=?, current_stage='Descargando páginas (3/9)' WHERE id=?",
                  (2**22 - 5, (datetime.now(timezone.utc) - timedelta(minutes=8)).isoformat(), zombie))
    at = app("from views.dashboard import render\nrender()\n", **NO_AUTO).run()
    z = db.get_audit(zombie)
    check(z["status"] == "FAILED" and "Descargando páginas (3/9)" in z["error_msg"], "al abrir el Dashboard, una auditoría muerta pasa a FAILED (ya no queda RUNNING)")
    check(not at.exception, "...y la página sigue renderizando")
    
def t_site_detail_launcher():
    section("Detalle del sitio — lanzar auditoría")
    gate = threading.Event()
    done = threading.Event()

    def fake_audit(site, cycle_log_id=None, cycle_started_at=None, audit_id=None):
        db.mark_audit_running(audit_id, "Descargando páginas")
        db.touch_audit(audit_id, stage="Descargando páginas (1/3)", progress=30)
        gate.wait(10)
        db.finish_audit(audit_id, "sitemap", 3, "COMPLETED")
        done.set()
    
        import orchestrator
        code = f"from views.site_detail import render\nrender({SITE})\n"
        NO_AUTO = {"saaf_auto_refresh_audits": False}
        with patch.object(orchestrator, "audit_site", fake_audit):
            at = app(code, **NO_AUTO).run()
            check(not at.exception, "el detalle del sitio renderiza")
            btn(at, "▶ Auditar ahora").click(); at.run()
            check(not at.exception, "lanzar la auditoría no genera excepciones")
            for _ in range(50):
                act = db.get_active_audits(SITE)
                if act and act[0]["status"] == "RUNNING":
                    break
                time.sleep(0.1)
            act = db.get_active_audits(SITE)
            check(len(act) == 1 and act[0]["status"] == "RUNNING", "la auditoría pasa de PENDING a RUNNING")
            at = app(code, **NO_AUTO).run()
            check("Descargando páginas (1/3)" in texts(at) and "RUNNING" in texts(at), "el panel del sitio muestra etapa y estado")
            # doble clic: el guardia es la BD
            btn(at, "▶ Auditar ahora").click(); at.run()
            check(any("Ya hay una auditoría en curso" in w.value for w in at.warning), "segundo clic: aviso 'Ya hay una auditoría en curso'")
            check(len(db.get_active_audits(SITE)) == 1, "...y NO se lanza una segunda auditoría (antes sí ocurría)")
            gate.set(); done.wait(10)
            time.sleep(0.2)
            check(db.get_last_audit(SITE)["status"] == "COMPLETED", "termina COMPLETED")
    
    # si el hilo falla, la auditoría queda FAILED con motivo
    def exploding(site, cycle_log_id=None, cycle_started_at=None, audit_id=None):
        raise RuntimeError("kaboom en el hilo")
    with patch.object(orchestrator, "audit_site", exploding):
        at = app(code, **NO_AUTO).run()
        btn(at, "▶ Auditar ahora").click(); at.run()
        time.sleep(0.8)
        last = db.get_last_audit(SITE)
        check(last["status"] == "FAILED" and "kaboom" in last["error_msg"], "un error dentro del hilo deja la auditoría FAILED con el motivo (antes se tragaba en silencio)")

    # historial del sitio con los estados nuevos
    at = app(code, **NO_AUTO).run()
    check(not at.exception, "el detalle sigue renderizando con auditorías FAILED/COMPLETED")
    

if __name__ == "__main__":
    for fn in (t_alerts, t_manager, t_panel_and_dashboard, t_site_detail_launcher):
        try:
            fn()
        except Exception as e:
            import traceback
            _fail += 1
            print(f"  [FAIL] {fn.__name__}: {type(e).__name__}: {e}")
            traceback.print_exc(limit=4)
    print("\n" + "=" * 55 + f"\n  Resultado UI: {_ok} OK  |  {_fail} FAIL\n" + "=" * 55)
    sys.exit(1 if _fail else 0)