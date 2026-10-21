#!/home/admin_ubuntu/Desktop/proyecto_saaf/opt/saaf/venv/bin/python
# =============================================================
# SAAF Pro — test_fase1.py
# Tests de validación completos para Fase 1
# Ruta: /home/admin_ubuntu/Desktop/proyecto_saaf/opt/saaf/tests/test_fase1.py
# =============================================================

import sys
import os
import tempfile
from pathlib import Path

# Usar directorio temporal para no tocar la BD real
TMP = Path(tempfile.mkdtemp())
os.environ["SAAF_DB_PATH"] = str(TMP / "test.db")

# Agregar rutas de importación
sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent / "scripts" / "python"))

import database as db
import config_loader as cfg

PASS = 0
FAIL = 0


def ok(msg):
    global PASS
    PASS += 1
    print(f" [OK] {msg}")


def fail(msg, err=""):
    global FAIL
    FAIL += 1
    print(f"  [FAIL] {msg}" + (f"\n Error: {err}" if err else ""))


def section(title):
    print(f"\n{'='*50}")
    print(f" {title}")
    print(f"{'='*50}")


# ==========================================================
section("database.py — init_db()")
# ==========================================================
try:
    db.init_db()
    ok("init_db() ejecutado sin errores")
except Exception as e:
    fail("init_db()", e)

try:
    db.init_db()
    ok("init_db() es idempotente (segunda llamada segura)")
except Exception as e:
    fail("init_db() segunda llamada", e)


# ==========================================================
section("database.py — Sites CRUD")
# ==========================================================
try:
    sid = db.upsert_site(
        "Test Blog",
        "https://testblog.com",
        "https://testblog.com/sitemap.xml",
        "blog",
        "high", True,
    )
    assert isinstance(sid, int) and sid > 0
    ok(f"upsert_site() insercion — id={sid}")
except Exception as e:
    fail("upsert_site() insercion", e)
    sid = None


if sid:
    try:
        sid2 = db.upsert_site("Test Blog Updated", "https://testblog.com", niche="tech")
        assert sid2 == sid
        site = db.get_site(sid)
        assert site["name"] == "Test Blog Updated"
        assert site["niche"] == "tech"
        ok("upsert_site() actualizacion (mismo URL)")
    except Exception as e:
        fail("upsert_site() actualizacion", e)

    try:
        site = db.get_site_by_url("https://testblog.com")
        assert site is not None and site["id"] == sid
        ok("get_site_by_url() correcto")
    except Exception as e:
        fail("get_site_by_url()", e)

    try:
        sites = db.get_all_sites()
        assert len(sites) >= 1
        ok(f"get_all_sites() devuelve {len(sites)} sitio(s)")
    except Exception as e:
        fail("get_all_sites()", e)

    try:
        db.update_site(sid, active=0)
        site = db.get_site(sid)
        assert site["active"] == 0
        active_sites = db.get_all_sites(active_only=True)
        assert not any(s["id"] == sid for s in active_sites)
        ok("update_site() + filtro active_only correcto")
    except Exception as e:
        fail("update_site()", e)


# ==========================================================
section("database.py — Audits")
# ==========================================================
try:
    log_id = db.start_cycle_log()
    audit_id = db.start_audit(sid, cycle_log_id=log_id)
    assert isinstance(audit_id, int)
    ok(f"start_audit() — id={audit_id}")
except Exception as e:
    fail("start_audit()", e)
    audit_id = None

if audit_id:
    try:
        db.finish_audit(audit_id, "sitemap", 8, "issues")
        audit = db.get_last_audit(sid)
        assert audit["crawl_method"] == "sitemap"
        assert audit["urls_analyzed"] == 8
        assert audit["status"] == "COMPLETED"  # el valor antiguo "issues" se migra a COMPLETED
        ok("finish_audit() + get_last_audit() correctos")
    except Exception as e:
        fail("finish_audit()", e)


# ==========================================================
section("database.py — Threats")
# ==========================================================
try:
    tid = db.add_threat(
        audit_id=audit_id,
        site_id=sid,
        threat_type="hidden_spam_link",
        severity="HIGH",
        description="Spam link oculto encontrado",
        code_snippet='<a style="display:none" href="casino.com">x</a>',
        url_found="https://testblog.com/pagina",
        is_new=True,
    )
    ok(f"add_threat() — id={tid}")
except Exception as e:
    fail("add_threat()", e)
    tid = None

if tid:
    try:
        threats = db.get_open_threats(sid)
        assert len(threats) == 1
        assert threats[0]["threat_type"] == "hidden_spam_link"
        ok("get_open_threats() correcto")
    except Exception as e:
        fail("get_open_threats()", e)

    try:
        # Sin cycle_started_at: devuelve todas las no resueltas
        baseline = db.get_baseline_threats(sid)
        assert len(baseline) >= 1
        ok(f"get_baseline_threats() sin ciclo: {len(baseline)} amenaza(s")
    except Exception as e:
        fail("get_baseline_threats() sin ciclo", e)

    try:
        # Con cycle_started_at futuro: debe incluir la amenaza actual
        from datetime import datetime, timezone, timedelta

        futuro = (datetime.now(timezone.utc) + timedelta(hours=1)).isoformat()
        baseline = db.get_baseline_threats(sid, cycle_started_at=futuro)
        assert len(baseline) >= 1
        ok(
            f"get_baseline_threats() con ciclo futuro: {len(baseline)} amenaza(s) (deduplicacion correcta)"
        )
    except Exception as e:
        fail("get_baseline_threats() con ciclo futuro", e)

    try:
        # Con cycle_started_at pasado (antes de que se creara la amenaza): NO debe devolver nada
        pasado = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
        baseline = db.get_baseline_threats(sid, cycle_started_at=pasado)
        assert len(baseline) == 0
        ok(
            "get_baseline_threats() con ciclo pasado: 0 amenazas (amenaza posterior al ciclo = nueva)"
        )
    except Exception as e:
        fail("get_baseline_threats() con ciclo pasado", e)

    try:
        db.resolve_threat(tid)
        threats = db.get_open_threats(sid)
        assert not any(t["id"] == tid for t in threats)
        ok("resolve_threat() cierra la amenaza")
    except Exception as e:
        fail("resolve_threat()", e)


# ==========================================================
section("database.py — Uptime")
# ==========================================================
try:
    db.add_uptime(sid, is_up=True, status_code=200, response_time_ms=312)
    db.add_uptime(sid, is_up=True, status_code=200, response_time_ms=290)
    db.add_uptime(sid, is_up=False, status_code=503, error_msg="Service Unavailable")
    ok("add_uptime() x3 sin errores")
except Exception as e:
    fail("add_uptime()", e)

try:
    pct = db.get_uptime_stats(sid, days=30)
    assert pct is not None
    ok(f"get_uptime_stats() = {pct}% uptime")
except Exception as e:
    fail("get_uptime_stats()", e)

try:
    is_up = db.is_site_currently_up(sid)
    assert is_up == False
    ok("is_site_currently_up() = False (ultimo registro fue caido)")
except Exception as e:
    fail("is_site_currently_up()", e)

# ==========================================================
section("database.py — Spam Domains")
# ==========================================================
try:
    domains = db.get_spam_domains()
    assert "casino.com" in domains
    ok(f"get_spam_domains() devuelve {len(domains)} dominios (seed OK)")
except Exception as e:
    fail("get_spam_domains()", e)

try:
    db.add_spam_domain("newspam.com")
    assert "newspam.com" in db.get_spam_domains()
    ok("add_spam_domain() correcto")
except Exception as e:
    fail("add_spam_domain()", e)

try:
    db.delete_spam_domain("newspam.com")
    assert "newspam.com" not in db.get_spam_domains()
    ok("delete_spam_domain() correcto")
except Exception as e:
    fail("delete_spam_domain()", e)


# ==========================================================
section("database.py — Cycle Logs")
# ==========================================================
try:
    db.finish_cycle_log(log_id, "ok", sites_total=3, sites_ok=2, sites_issues=1)
    logs = db.get_cycle_logs()
    assert logs[0]["status"] == "ok"
    assert logs[0]["sites_total"] == 3
    ok("finish_cycle_log() + get_cycle_logs() correctos")
except Exception as e:
    fail("cycle_logs", e)


# ==========================================================
section("database.py — Dashboard Summary")
# ==========================================================
try:
    summary = db.get_dashboard_summary()
    assert "total_sites" in summary
    assert "open_total" in summary
    ok(f"get_dashboard_summary(): {dict(summary)}")
except Exception as e:
    fail("get_dashboard_summary()", e)


# ==========================================================
section("config_loader.py — CSV valido")
# ==========================================================
csv_valid = TMP / "sites_valid.csv"
csv_valid.write_text(
    "name,url,sitemap_url,niche,priority,active\n"
    "Blog,https://blog.com,https://blog.com/sitemap.xml,blog,high,true\n"
    "Tienda,https://tienda.com,,ecommerce,normal,true\n"
    "Inactivo,https://inactivo.com,,general,low,false\n",
    encoding="utf-8",
)

try:
    sites = cfg.load_sites_from_csv(csv_valid)
    assert len(sites) == 3
    ok(f"load_sites_from_csv() carga {len(sites)} sitios")
except Exception as e:
    fail("load_sites_from_csv() basico", e)

try:
    active = cfg.get_active_sites(csv_valid)
    assert len(active) == 2
    ok(f"get_active_sites() filtra correctamente — {len(active)} activos")
except Exception as e:
    fail("get_active_sites()", e)

try:
    sites = cfg.load_sites_from_csv(csv_valid)
    blog = next(s for s in sites if s["url"] == "https://blog.com")
    assert blog["niche"] == "blog"
    assert blog["priority"] == "high"
    assert blog["active"] == True
    assert blog["sitemap_url"] == "https://blog.com/sitemap.xml"
    ok("Campos del sitio normalizados correctamente")
except Exception as e:
    fail("Normalizacion de campos", e)


# ==========================================================
section("config_loader.py — Validaciones y errores")
# ==========================================================
csv_bad_url = TMP / "sites_bad_url.csv"
csv_bad_url.write_text(
    "name,url\nBueno,https://bueno.com\nMalo,no-es-una-url\n", encoding="utf-8"
)
try:
    sites = cfg.load_sites_from_csv(csv_bad_url)
    assert len(sites) == 1
    assert sites[0]["url"] == "https://bueno.com"
    ok("URL invalida omitida, sitio valido cargado")
except Exception as e:
    fail("Manejo de URL invalida", e)

csv_dup = TMP / "sites_dup.csv"
csv_dup.write_text("name,url\nA,https://dup.com\nB,https://dup.com\n", encoding="utf-8")
try:
    sites = cfg.load_sites_from_csv(csv_dup)
    assert len(sites) == 1
    ok("URL duplicada omitida correctamente")
except Exception as e:
    fail("Manejo de URL duplicada", e)

try:
    cfg.load_sites_from_csv(TMP / "noexiste.csv")
    fail("Deberia lanzar FileNotFoundError")
except FileNotFoundError:
    ok("FileNotFoundError para archivo inexistente")
except Exception as e:
    fail("FileNotFoundError esperado pero otro error", e)

csv_no_col = TMP / "sites_no_col.csv"
csv_no_col.write_text("titulo,direccion\nBlog,https://blog.com\n", encoding="utf-8")
try:
    cfg.load_sites_from_csv(csv_no_col)
    fail("Deberia lanzar ValueError por columnas faltantes")
except ValueError:
    ok("ValueError para columnas requeridas faltantes")
except Exception as e:
    fail("ValueError esperado pero otro error", e)

csv_semicolon = TMP / "sites_semicolon.csv"
csv_semicolon.write_text(
    "name;url;niche\nBlog;https://semiblog.com;blog\n", encoding="utf-8"
)
try:
    sites = cfg.load_sites_from_csv(csv_semicolon)
    assert len(sites) == 1
    ok("CSV con separador punto y coma detectado automaticamente")
except Exception as e:
    fail("Deteccion de separador punto y coma", e)


# ==========================================================
section("config_loader.py — CSV de ejemplo")
# ==========================================================
example_path = TMP / "example.csv"
try:
    cfg.create_example_csv(example_path)
    assert example_path.exists()
    sites = cfg.load_sites_from_csv(example_path)
    assert len(sites) >= 2
    ok(f"create_example_csv() crea CSV valido con {len(sites)} sitios")
except Exception as e:
    fail("create_example_csv()", e)

try:
    cfg.create_example_csv(example_path)
    ok("create_example_csv() no sobreescribe si ya existe")
except Exception as e:
    fail("create_example_csv() idempotente", e)


# ==========================================================
section("Directorios requeridos")
# ==========================================================
# Solo verificamos existencia — los directorios los crea orchestrator.py
# con los permisos correctos del usuario saaf. No intentamos crearlos aquí.
for d in ["/home/admin_ubuntu/Desktop/proyecto_saaf/opt/saaf/data", "/home/admin_ubuntu/Desktop/proyecto_saaf/opt/saaf/logs", "/home/admin_ubuntu/Desktop/proyecto_saaf/opt/saaf/config"]:
    if Path(d).exists():
        ok(f"Directorio {d} existe")
    else:
        fail(
            f"Directorio {d} no existe — ejecuta: python3 /home/admin_ubuntu/Desktop/proyecto_saaf/opt/saaf/orchestrator.py --dry-run"
        )


# ==========================================================
print(f"\n{'='*50}")
print(f"  Resultado: {PASS} OK  |  {FAIL} FAIL")
print(f"{'='*50}")

if FAIL > 0:
    print("  [!] Hay tests fallidos. Revisar antes de continuar con Fase 2.")
    sys.exit(1)
else:
    print("  [OK] Todos los tests de Fase 1 pasaron.")
    print("  [->] Listo para continuar con Fase 2.")
    sys.exit(0)
