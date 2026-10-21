#!/home/admin_ubuntu/Desktop/proyecto_saaf/opt/saaf/venv/bin/python
# =============================================================
# SAAF Pro — test_fase4.py
# Tests de validacion para alerts.py, scheduler.py (mock)
# y orchestrator.py Fase 4
# Ruta: /home/admin_ubuntu/Desktop/proyecto_saaf/opt/saaf/tests/test_fase4.py
# =============================================================

import sys
import os
import tempfile
from pathlib import Path
from unittest.mock import patch, MagicMock
from datetime import datetime, timezone

TMP = Path(tempfile.mkdtemp())
os.environ["SAAF_DB_PATH"] = str(TMP / "test.db")

sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent / "scripts" / "python"))

PASS = 0
FAIL = 0


def ok(msg):
    global PASS
    PASS += 1
    print(f" [OK] {msg}")


def fail(msg, err=""):
    global FAIL
    FAIL += 1
    print(f"  [FAIL] {msg}" + (f"\n         {err}" if err else ""))


def section(title):
    print(f"\n{'='*55}")
    print(f"  {title}")
    print(f"{'='*55}")


# ==========================================================
section("Imports")
# ==========================================================
try:
    from alerts import (
        send_email,
        send_threat_alert,
        send_site_down_alert,
        send_daily_report,
        should_send_alert,
        get_config,
        get_email_recipients as get_recipients,
        _build_threat_body,
        _build_down_body,
        _build_daily_report_body,
    )

    ok("alerts.py importado")
except ImportError as e:
    fail("alerts.py", e)
    sys.exit(1)

try:
    from analyzer import Threat

    ok("Threat importado de analyzer.py")
except ImportError as e:
    fail("Threat from analyzer", e)
    sys.exit(1)

# ==========================================================
section("alerts.py — configuracion")
# ==========================================================
try:
    cfg = get_config()
    assert "email_enabled" in cfg
    assert "smtp_server" in cfg
    assert "alert_on_critical" in cfg
    assert "alert_on_high" in cfg
    assert "alert_on_down" in cfg
    ok("get_config() devuelve todas las claves esperadas")
except Exception as e:
    fail("get_config()", e)

try:
    os.environ["SAAF_EMAIL_ENABLED"] = "0"
    os.environ["SAAF_ALERT_CRITICAL"] = "1"
    os.environ["SAAF_ALERT_HIGH"] = "1"
    assert should_send_alert("CRITICAL") == False  # email disabled
    os.environ["SAAF_EMAIL_ENABLED"] = "1"
    assert should_send_alert("CRITICAL") == True
    assert should_send_alert("HIGH") == True
    assert should_send_alert("MEDIUM") == False
    assert should_send_alert("LOW") == False
    ok("should_send_alert() correcto segun config")
except Exception as e:
    fail("should_send_alert()", e)
finally:
    os.environ["SAAF_EMAIL_ENABLED"] = "0"  # reset para evitar envios reales

try:
    os.environ["SAAF_ALERT_RECIPIENTS"] = "admin@empresa.com,dev@empresa.com"
    recipients = get_recipients()
    assert "admin@empresa.com" in recipients
    assert "dev@empresa.com" in recipients
    ok(f"get_recipients() desde env var: {recipients}")
except Exception as e:
    fail("get_recipients()", e)
finally:
    del os.environ["SAAF_ALERT_RECIPIENTS"]

# ==========================================================
section("alerts.py — cuerpos de email")
# ==========================================================
site = {"name": "Mi Blog", "url": "https://myblog.com", "niche": "blog"}


def make_threat(t_type, severity, desc="Test"):
    t = Threat(t_type, desc, url_found="https://myblog.com/page")
    t.severity = severity
    t.is_new = True
    return t


try:
    threats = [
        make_threat("hidden_spam_link", "HIGH", "Link casino oculto"),
        make_threat("obfuscated_js", "CRITICAL", "eval(atob(...))"),
    ]
    body = _build_threat_body(site, threats)
    assert "Mi Blog" in body
    assert "CRITICAL" in body
    assert "HIGH" in body
    assert "Link casino oculto" in body
    assert "eval(atob" in body
    assert "SAAF Pro" in body
    ok("_build_threat_body() contiene todos los campos esperados")
except Exception as e:
    fail("_build_threat_body()", e)

try:
    body = _build_down_body(site, error_msg="Connection refused")
    assert "Mi Blog" in body
    assert "CAIDO" in body
    assert "Connection refused" in body
    ok("_build_down_body() correcto")
except Exception as e:
    fail("_build_down_body()", e)

try:
    summary = {
        "sites_total": 3,
        "sites_ok": 2,
        "sites_issues": 1,
        "sites_down": 0,
        "sites_error": 0,
        "duration_sec": 120,
    }
    results = [
        {
            "site": site,
            "status": "COMPLETED", "has_issues": True,
            "severity_max": "HIGH",
            "threats": threats,
            "is_up": True,
        },
        {
            "site": {
                "name": "Tienda",
                "url": "https://tienda.com",
                "niche": "ecommerce",
            },
            "status": "COMPLETED",
            "severity_max": None,
            "threats": [],
            "is_up": True,
        },
    ]
    body = _build_daily_report_body(summary, results)
    assert "Reporte Diario" in body
    assert "Mi Blog" in body
    assert "Tienda" in body
    assert "3" in body  # sites_total
    ok("_build_daily_report_body() correcto")
except Exception as e:
    fail("_build_daily_report_body()", e)


# ==========================================================
section("alerts.py — send_email con mock SMTP")
# ==========================================================
try:
    os.environ["SAAF_EMAIL_ENABLED"] = "1"
    os.environ["SAAF_SMTP_SERVER"] = "smtp.test.com"
    os.environ["SAAF_SMTP_USER"] = "user@test.com"
    os.environ["SAAF_SMTP_PASSWORD"] = "testpass"
    os.environ["SAAF_SMTP_FROM"] = "saaf@test.com"

    with patch("smtplib.SMTP") as mock_smtp:
        mock_instance = MagicMock()
        mock_smtp.return_value.__enter__ = lambda s: mock_instance
        mock_smtp.return_value.__exit__ = MagicMock(return_value=False)
        result = send_email("admin@empresa.com", "Test", "Body test")

    assert result == True
    ok("send_email() con SMTP mock — retorna True")
except Exception as e:
    fail("send_email() mock SMTP", e)

try:
    result = send_email("no-es-un-email", "Test", "Body")
    assert result == False
    ok("send_email() rechaza email invalido — retorna False")
except Exception as e:
    fail("send_email() email invalido", e)
finally:
    os.environ["SAAF_EMAIL_ENABLED"] = "0"


# ==========================================================
section("alerts.py — send_threat_alert con mock")
# ==========================================================
try:
    os.environ["SAAF_EMAIL_ENABLED"] = "1"
    os.environ["SAAF_ALERT_RECIPIENTS"] = "admin@empresa.com"
    os.environ["SAAF_SMTP_SERVER"] = "smtp.test.com"
    os.environ["SAAF_SMTP_USER"] = "u"
    os.environ["SAAF_SMTP_PASSWORD"] = "p"
    os.environ["SAAF_ALERT_CRITICAL"] = "1"
    os.environ["SAAF_ALERT_HIGH"] = "1"

    threats_new = [make_threat("obfuscated_js", "CRITICAL", "JS ofuscado")]

    with patch("smtplib.SMTP") as mock_smtp:
        mock_instance = MagicMock()
        mock_smtp.return_value.__enter__ = lambda s: mock_instance
        mock_smtp.return_value.__exit__ = MagicMock(return_value=False)
        sent = send_threat_alert(site, threats_new)

    assert sent["emails_sent"] == 1
    ok("send_threat_alert() — envia 1 email para amenaza CRITICAL nueva")
except Exception as e:
    fail("send_threat_alert()", e)
finally:
    os.environ["SAAF_EMAIL_ENABLED"] = "0"
    if "SAAF_ALERT_RECIPIENTS" in os.environ:
        del os.environ["SAAF_ALERT_RECIPIENTS"]

try:
    # Amenaza MEDIUM — no debe enviar
    threats_medio = [make_threat("external_script", "MEDIUM", "Script")]
    sent = send_threat_alert(site, threats_medio)
    assert sent["emails_sent"] == 0
    ok("send_threat_alert() — no envia para MEDIUM (email deshabilitado)")
except Exception as e:
    fail("send_threat_alert() MEDIUM", e)

try:
    # Amenaza no nueva — no debe enviar
    t_old = make_threat("hidden_spam_link", "HIGH", "Link")
    t_old.is_new = False
    sent = send_threat_alert(site, [t_old])
    assert sent["emails_sent"] == 0
    ok("send_threat_alert() — no envia amenaza con is_new=False")
except Exception as e:
    fail("send_threat_alert() is_new=False", e)


# ==========================================================
section("alerts.py — send_site_down_alert con mock")
# ==========================================================
try:
    os.environ["SAAF_EMAIL_ENABLED"] = "1"
    os.environ["SAAF_ALERT_RECIPIENTS"] = "admin@empresa.com"
    os.environ["SAAF_SMTP_SERVER"] = "smtp.test.com"
    os.environ["SAAF_SMTP_USER"] = "u"
    os.environ["SAAF_SMTP_PASSWORD"] = "p"
    os.environ["SAAF_ALERT_DOWN"] = "1"

    with patch("smtplib.SMTP") as mock_smtp:
        mock_instance = MagicMock()
        mock_smtp.return_value.__enter__ = lambda s: mock_instance
        mock_smtp.return_value.__exit__ = MagicMock(return_value=False)
        sent = send_site_down_alert(site, error_msg="503 Service Unavailable")

    assert sent["emails_sent"] == 1
    ok("send_site_down_alert() — envia 1 email para sitio caido")
except Exception as e:
    fail("send_site_down_alert()", e)
finally:
    os.environ["SAAF_EMAIL_ENABLED"] = "0"
    if "SAAF_ALERT_RECIPIENTS" in os.environ:
        del os.environ["SAAF_ALERT_RECIPIENTS"]


# ==========================================================
section("database.py — cycle_logs")
# ==========================================================
try:
    from database import init_db, start_cycle_log, finish_cycle_log, get_cycle_logs

    init_db()
    log_id = start_cycle_log()
    assert isinstance(log_id, int) and log_id > 0
    ok(f"start_cycle_log() retorna id={log_id}")
except Exception as e:
    fail("start_cycle_log()", e)


try:
    finish_cycle_log(
        log_id,
        status="ok",
        sites_total=5,
        sites_ok=4,
        sites_issues=1,
        sites_down=0,
        sites_error=0,
    )
    logs = get_cycle_logs(limit=5)
    assert len(logs) >= 1
    last = logs[0]
    assert last["status"] == "ok"
    assert last["sites_total"] == 5
    assert last["sites_ok"] == 4
    ok(f"finish_cycle_log() + get_cycle_logs() correctos: {dict(last)}")
except Exception as e:
    fail("finish_cycle_log()", e)

try:
    log_id2 = start_cycle_log()
    finish_cycle_log(log_id2, status="error", error_msg="Test error")
    logs = get_cycle_logs(limit=5)
    assert any(l["status"] == "error" for l in logs)
    ok("finish_cycle_log() con status=error correcto")
except Exception as e:
    fail("finish_cycle_log() error", e)


# ==========================================================
section("scheduler.py — importacion y run_scheduled_cycle mock")
# ==========================================================
try:
    from scheduler import run_scheduled_cycle, _save_report_file

    ok("scheduler.py importado correctamente")
except ImportError as e:
    if "apscheduler" in str(e).lower():
        print(f"  [SKIP] APScheduler no instalado — instalar con:")
        print(
            f"         /home/admin_ubuntu/Desktop/proyecto_saaf/opt/saaf/venv/bin/pip install 'apscheduler==3.10.4'"
        )
    else:
        fail("scheduler.py import", e)
except Exception as e:
    fail("scheduler.py import inesperado", e)

try:
    report_path = str(TMP / "test_report.txt")
    summary = {
        "sites_total": 2,
        "sites_ok": 1,
        "sites_issues": 1,
        "sites_down": 0,
        "sites_error": 0,
        "duration_sec": 45,
    }
    results = [
        {
            "site": site,
            "status": "COMPLETED",
            "severity_max": None,
            "threats": [],
            "is_up": True,
        }
    ]
    _save_report_file(report_path, summary, results)
    assert Path(report_path).exists()
    content = Path(report_path).read_text()
    assert "SAAF Pro" in content
    ok("_save_report_file() crea archivo correctamente")
except Exception as e:
    fail("_save_report_file()", e)


# ==========================================================
section("orchestrator.py Fase 4 — run_cycle retorna resultados")
# ==========================================================
try:
    from orchestrator import run_cycle

    sig = run_cycle.__code__.co_varnames
    assert "cycle_log_id" in sig
    ok("run_cycle() acepta cycle_log_id como parametro")
except Exception as e:
    fail("run_cycle() firma", e)

try:
    from orchestrator import audit_site

    sig = audit_site.__code__.co_varnames
    assert "cycle_log_id" in sig
    assert "cycle_started_at" in sig
    ok("audit_site() acepta cycle_log_id y cycle_started_at")
except Exception as e:
    fail("audit_site() firma", e)

# ==========================================================
print(f"\n{'='*55}")
print(f"  Resultado: {PASS} OK  |  {FAIL} FAIL")
print(f"{'='*55}")

if FAIL > 0:
    print("  [!] Hay tests fallidos. Revisar antes de continuar con Fase 5.")
    sys.exit(1)
else:
    print("  [OK] Todos los tests de Fase 4 pasaron.")
    print("  [->] Listo para continuar con Fase 5 (Frontend).")
    sys.exit(0)
