#!/home/admin_ubuntu/Desktop/proyecto_saaf/opt/saaf/venv/bin/python
# =============================================================
# SAAF Pro — orchestrator.py
# Orquestador principal del ciclo de auditoría
# Ruta: /home/admin_ubuntu/Desktop/proyecto_saaf/opt/saaf/orchestrator.py
#
# Fase 1: Lee CSV, sincroniza BD, imprime sitios cargados.
# Fases 2-4: Se completará con crawler, analyzer, scheduler.
# =============================================================

import logging
import signal
import sqlite3
import sys
import os
import time
import threading
from pathlib import Path
from datetime import datetime, timezone
from urllib.parse import urlparse, urlunparse

# ------------------------------------------------------------------
# Logging — archivo + consola
# ------------------------------------------------------------------
LOG_DIR = Path("/home/admin_ubuntu/Desktop/proyecto_saaf/opt/saaf/logs")
LOG_DIR.mkdir(parents=True, exist_ok=True)
DATA_DIR = Path("/home/admin_ubuntu/Desktop/proyecto_saaf/opt/saaf/data")
DATA_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-8s %(name)s — %(message)s",
    handlers=[
        logging.FileHandler(LOG_DIR / "saaf.log", encoding="utf-8"),
        logging.StreamHandler(sys.stdout),
    ],
)
logger = logging.getLogger("orchestrator")

# ------------------------------------------------------------------
# Imports internos (rutas relativas al mismo directorio)
# ------------------------------------------------------------------
import json
import subprocess

_BASE = Path(__file__).parent
sys.path.insert(0, str(_BASE))
sys.path.insert(0, str(_BASE / "scripts" / "python"))

try:
    from config_loader import (
        load_sites_from_csv,
        get_active_sites,
        create_example_csv,
        CSV_PATH,
    )
except ImportError as e:
    logger.error("No se pudo importar config_loader: %s", e)
    sys.exit(1)

try:
    from database import (
        start_cycle_log,
        finish_cycle_log,
        init_db,
        upsert_site,
        get_all_sites,
        get_dashboard_summary,
        start_audit,
        finish_audit,
        add_uptime,
        get_site_by_url,
        get_audit,
        mark_audit_running,
        touch_audit,
        reap_stale_audits,
        get_spam_domains,
        get_baseline_threats,
        get_known_resource_hosts,
        get_effective_allowlist,
        record_allowlist_hits,
        add_threat,
    )
except ImportError as e:
    logger.error("No se pudo importar database: %s", e)
    sys.exit(1)

try:
    from crawler import get_urls, CrawlResult
except ImportError as e:
    logger.error("No se pudo importar crawler: %s", e)
    sys.exit(1)

try:
    from analyzer import analyze_html, Threat
except ImportError as e:
    logger.error("No se pudo importar analyzer: %s", e)
    sys.exit(1)

try:
    from claude_analyzer import analyze as claude_analyze
except ImportError as e:
    logger.error("No se pudo importar claude_analyzer: %s", e)
    sys.exit(1)

try:
    from severity import (
        classify_threats, summarize_severities, should_alert, max_severity, INFO,
    )
    from audit_state import (
        PENDING, RUNNING, COMPLETED, COMPLETED_WITH_WARNINGS, FAILED, CANCELLED,
        AuditCancelled, AuditAborted, AuditError, classify_exception,
    )
    from allowlist import AllowlistMatcher, extract_resource_url
    from url_utils import get_host
except ImportError as e:
    logger.error("No se pudo importar severity/audit_state/allowlist: %s", e)
    sys.exit(1)

try:
    from alerts import send_threat_alert, send_site_down_alert
except ImportError as e:
    logger.error("No se pudo importar alerts: %s", e)
    logger.error(
        "  Verificar que existe: %s",
        _BASE / "scripts" / "python" / "alerts.py",
    )
    sys.exit(1)


SCRAPER_PATH = Path(
    "/home/admin_ubuntu/Desktop/proyecto_saaf/opt/saaf/scripts/node/scraper.js"
)

# =============================================================
# Utilidades
# =============================================================

# UTM y parámetros de tracking que se deben ignorar en deduplicación
_UTM_PARAMS = {
    "utm_source",
    "utm_medium",
    "utm_campaign",
    "utm_term",
    "utm_content",
    "fbclid",
    "gclid",
    "msclkid",
    "ref",
    "source",
}

def _normalize_url_for_dedup(url: str) -> str:
    """
    Normaliza una URL para comparación en la deduplicación del baseline.
 
    MEJORA: Elimina trailing slashes inconsistentes, fragmentos (#),
    y parámetros de tracking (UTM, fbclid, etc.) que generan duplicados
    cuando la misma URL aparece con y sin estos elementos en ciclos distintos.
 
    Ejemplo:
      https://site.com/page/ == https://site.com/page
      https://site.com/page?utm_source=email == https://site.com/page
    """
    if not url:
        return ""
    try:
        parsed = urlparse(url)
        # Eliminar fragmento
        # Eliminar parámetros de tracking de la query string
        if parsed.query:
            from urllib.parse import parse_qs, urlencode
            params = parse_qs(parsed.query, keep_blank_values=True)
            clean_params = {k: v for k, v in params.items() if k.lower() not in _UTM_PARAMS}
            clean_query = urlencode(clean_params, doseq=True)
        else:
            clean_query = ""
        # Normalizar path: eliminar trailing slash excepto en raíz "/"
        path = parsed.path
        if path != "/" and path.endswith("/"):
            path = path.rstrip("/")
        normalized = parsed._replace(
            path=path,
            query=clean_query,
            fragment="",
        )
        return normalized.geturl().lower()
    except Exception:
        return url.lower()

# =============================================================
# FASE 1 — Cargar sitios desde CSV y sincronizar con BD
# =============================================================


def load_and_sync_sites(csv_path: Path = None) -> list:
    """
    Lee el CSV de sitios, los valida e inserta/actualiza en la BD.
    Retorna la lista de sitios activos listos para auditar.
    """
    path = csv_path or CSV_PATH

    # Sincronizar CSV -> BD solo si el archivo existe
    if path.exists():
        logger.info("Sincronizando sitios desde CSV: %s", path)
        try:
            csv_sites = load_sites_from_csv(path)
            synced = 0
            for s in csv_sites:
                try:
                    upsert_site(
                        name=s["name"],
                        url=s["url"],
                        sitemap_url=s.get("sitemap_url"),
                        niche=s.get("niche", "general"),
                        priority=s.get("priority", "normal"),
                        active=s.get("active", True),
                    )
                    synced += 1
                except Exception as e:
                    logger.error("Error sincronizando '%s': %s", s.get("url"), e)
            logger.info("CSV sincronizado: %d/%d sitios", synced, len(csv_sites))
        except Exception as e:
            logger.warning("No se pudo leer el CSV (%s) — usando solo BD", e)
    else:
        logger.info("CSV no encontrado en %s — usando sitios de la BD", path)

    db_sites = get_all_sites(active_only=True)
    if not db_sites:
        logger.warning("No hay sitios activos en la BD")
        return []

    # Convertir sqlite3.Row a dict para compatibilidad
    active = [dict(s) for s in db_sites]
    logger.info("Sitios activos para auditar: %d (fuente: BD)", len(active))
    return active


# =============================================================
# FASE 2+ — Auditar un sitio (stub — se completa en Fase 2)
# =============================================================


def _extract_json_from_output(stdout: str) -> dict:
    """
    Extrae el ultimo objeto JSON valido de stdout del scraper.
    Necesario porque Puppeteer/Chromium puede emitir logs en stdout
    antes del JSON real (DevTools listening, warnings, etc.).

    Estrategia:
      1. Intento directo (caso mas comun — stdout limpio).
      2. Busca desde el ultimo '{' hacia atras hasta encontrar
         un objeto JSON valido completo.
    """
    stdout = stdout.strip()
    if not stdout:
        raise ValueError("stdout vacio")

    # Intento directo
    try:
        return json.loads(stdout)
    except json.JSONDecodeError:
        pass

    # Buscar el ultimo '{' y decodificar desde ahi hacia adelante
    decoder = json.JSONDecoder()
    last_brace = stdout.rfind("{")
    if last_brace == -1:
        raise ValueError("No se encontro '{' en stdout")

    try:
        obj, end = decoder.raw_decode(stdout, last_brace)
        # Verificar que despues del JSON solo haya whitespace
        if end == len(stdout) or stdout[end:].strip() == "":
            return obj
        # Si hay basura despues, buscar '{' anterior
        i = last_brace - 1
        while i >= 0:
            if stdout[i] == "{":
                try:
                    obj2, end2 = decoder.raw_decode(stdout, i)
                    if end2 > i and isinstance(obj2, dict):
                        return obj2
                except json.JSONDecodeError:
                    pass
            i -= 1
    except json.JSONDecodeError:
        pass

    raise ValueError("No se encontro un objeto JSON valido en stdout")


def _run_scraper(url: str) -> dict:
    """
    Llama a scraper.js via subprocess y devuelve el resultado JSON.
    Usa _extract_json_from_output() para manejar ruido en stdout
    (logs de Chromium/Puppeteer que aparecen antes del JSON real).
    """
    error_template = {
        "html": None,
        "url": url,
        "status_code": None,
        "redirect_url": None,
        "response_time_ms": None,
    }
    try:
        proc = subprocess.run(
            ["node", str(SCRAPER_PATH), url], capture_output=True, text=True, timeout=35
        )
        return _extract_json_from_output(proc.stdout)

    except subprocess.TimeoutExpired:
        logger.warning("Timeout en scraper para %s", url)
        return {**error_template, "error": "Timeout en scraper (60s)"}

    except ValueError as e:
        # _extract_json_from_output no encontro JSON valido
        logger.error("No se pudo extraer JSON del scraper para %s: %s", url, e)
        return {**error_template, "error": f"JSON invalido en stdout: {e}"}

    except Exception as e:
        logger.error("Error inesperado en scraper para %s: %s", url, e)
        return {**error_template, "error": str(e)}


# =============================================================
# Seguimiento de una auditoria en curso (latido, cancelacion, limite de tiempo)
# =============================================================

# Duracion maxima de UNA auditoria de sitio. Un crawl de 200 paginas con
# Puppeteer tarda normalmente 5-20 min; pasado este limite se considera colgada.
MAX_AUDIT_MINUTES = float(os.environ.get("SAAF_AUDIT_MAX_MINUTES", "360"))

# Si el proveedor de IA falla (creditos agotados, auth, timeout...), la
# auditoria se marca FAILED con el motivo (Mejoras_auditoria_y_alertas, punto 3).
# Las amenazas encontradas por patrones SE GUARDAN y las alertas SE ENVIAN igual.
# Con SAAF_AI_ERROR_FAILS_AUDIT=0 pasa a COMPLETED_WITH_WARNINGS.
AI_ERROR_FAILS_AUDIT = os.environ.get("SAAF_AI_ERROR_FAILS_AUDIT", "1") != "0"


class _AuditRun:
    """
    Acompaña a una auditoria: en cada etapa registra el latido (ultima
    actividad, etapa, progreso) y detecta si hay que parar:
      - AuditCancelled : el usuario pidio cancelar
      - AuditAborted   : otro actor (el vigilante) ya cerro esta auditoria
      - AuditError     : se supero el tiempo maximo
    """

    def __init__(self, audit_id: int):
        self.audit_id = audit_id
        self.t0 = time.monotonic()
        self.stage = "Iniciando"
        self.warnings = []

    def checkpoint(self, stage=None, progress=None, **kw):
        if time.monotonic() - self.t0 > MAX_AUDIT_MINUTES * 60:
            raise AuditError(
                f"La auditoría superó el tiempo máximo permitido ({MAX_AUDIT_MINUTES:.0f} min).",
                "timeout",
            )
        if stage:
            self.stage = stage
        try:
            alive, cancel = touch_audit(self.audit_id, stage=stage, progress=progress, **kw)
        except sqlite3.OperationalError as e:
            # BD momentaneamente bloqueada: no abortar la auditoria por un latido
            logger.warning("No se pudo registrar el latido de la auditoria %s: %s", self.audit_id, e)
            return
        if not alive:
            raise AuditAborted()
        if cancel:
            raise AuditCancelled()

    def warn(self, text: str):
        if text not in self.warnings:
            self.warnings.append(text)
            logger.warning("  Aviso: %s", text)


def _threat_key(threat_type, url_found, resource_url) -> tuple:
    """Clave de deduplicacion: tipo + PAGINA + RECURSO.
    Incluir el recurso evita que un script malicioso NUEVO en una pagina que ya
    tenia otro script externo registrado se considere 'ya conocido' (y no alerte)."""
    return (
        threat_type,
        _normalize_url_for_dedup(url_found),
        _normalize_url_for_dedup(resource_url or ""),
    )


class _Baseline:
    """Amenazas previas del sitio (para decidir cuales son nuevas / ya omitidas)."""

    # Las descripciones antiguas recortaban la URL a 100 caracteres: un recurso
    # reconstruido con >= 100 caracteres puede estar truncado, asi que se
    # compara tambien por prefijo para no re-alertar amenazas ya conocidas.
    _TRUNC = 100

    def __init__(self, rows):
        self._known, self._ignored = set(), set()
        self._known_trunc, self._ignored_trunc = [], []
        for b in rows:
            res = b["resource_url"] or extract_resource_url(
                b["threat_type"], b["description"], b["code_snippet"], b["url_found"]
            ) or ""
            key = _threat_key(b["threat_type"], b["url_found"], res)
            self._known.add(key)
            if len(res) >= self._TRUNC:
                self._known_trunc.append(key)
            if b["ignored"]:
                self._ignored.add(key)
                if len(res) >= self._TRUNC:
                    self._ignored_trunc.append(key)

    @staticmethod
    def _hit(keys, trunc, key):
        if key in keys:
            return True
        t, p, r = key
        return any(t == bt and p == bp and r.startswith(br) for bt, bp, br in trunc)

    def is_known(self, key):
        return self._hit(self._known, self._known_trunc, key)

    def is_ignored(self, key):
        return self._hit(self._ignored, self._ignored_trunc, key)


def _fail_result(result: dict, audit_id, status: str, error: str) -> dict:
    result.update(status=status, error=error, audit_id=audit_id)
    return result


def _run_enhancements(site, site_id, audit_id, threats, html_results, result):
    """
    Post-proceso OPCIONAL (paquete enhancements: agrupacion, IA contextual,
    historial, correccion autorizada y reportes por Teams/correo).
    Totalmente aislado: no imprime nada en consola, no altera `result` y
    cualquier error queda solo en logs/enhancements.log.
    """
    try:
        from enhancements import run_after_audit

        run_after_audit(site, site_id, audit_id, threats, html_results,
                        audit_status=result.get("status"))
    except Exception:
        try:
            from enhancements import get_logger

            get_logger().error("Fallo en el post-proceso de la auditoría %s", audit_id, exc_info=True)
        except Exception:
            pass
        

def audit_site(
    site: dict, cycle_log_id: int = None, cycle_started_at=None, audit_id: int = None
) -> dict:
    """
    Ejecuta el ciclo de auditoría completo para un sitio y deja SIEMPRE un
    estado final veraz en la BD (COMPLETED, COMPLETED_WITH_WARNINGS, FAILED o
    CANCELLED), con el motivo cuando corresponde.

    Etapas (cada una registra un latido y comprueba cancelacion / tiempo):
      crawl -> disponibilidad -> descarga de paginas -> analisis -> lista
      permitida -> IA -> clasificacion -> guardado -> alertas.

    Args:
        audit_id: auditoria PENDING creada por run_cycle() (o por la UI). Si es
                  None se crea una nueva ya en RUNNING.
    """
    logger.info("  → Auditando: %s (%s)", site["name"], site["url"])

    result = {
        "site": site,
        "site_id": None,
        "audit_id": audit_id,
        "status": FAILED,
        "has_issues": False,
        "threats": [],
        "html_results": [],
        "crawl": None,
        "error": None,
        "warnings": "",
        "is_up": None,
        "severity_max": None,
    }

    db_site = get_site_by_url(site["url"])
    if not db_site:
        logger.error("Sitio no encontrado en BD: %s", site["url"])
        if audit_id:
            finish_audit(audit_id, "none", 0, FAILED, error_msg="Sitio no encontrado en BD")
        return _fail_result(result, audit_id, FAILED, "Sitio no encontrado en BD")

    site_id = db_site["id"]
    result["site_id"] = site_id

    if audit_id is None:
        audit_id = start_audit(site_id, cycle_log_id=cycle_log_id)  # RUNNING
    elif not mark_audit_running(audit_id):
        # Cancelada (o cerrada) mientras esperaba en la cola
        row = get_audit(audit_id)
        if row and row["status"] in (PENDING, RUNNING):
            finish_audit(audit_id, "none", 0, CANCELLED, error_msg="Auditoría cancelada manualmente.")
            row = get_audit(audit_id)
        st = row["status"] if row else CANCELLED
        logger.info("  ⛔ %s — no se ejecuta (estado %s)", site["name"], st)
        return _fail_result(result, audit_id, st, row["error_msg"] if row else None)
    result["audit_id"] = audit_id

    run = _AuditRun(audit_id)
    crawl_method, urls_analyzed = "none", 0
    severity_max, allowlisted = None, 0
    ai_error = None
    classified = []
    enh_ctx = None  # se llena solo si la auditoria termino y quedo cerrada por este proceso

    try:
        # --- Paso 1: obtener URLs a auditar ---
        run.checkpoint("Obteniendo URLs del sitio", 3)
        crawl_result = get_urls(site, on_progress=lambda t: run.checkpoint(t, 3))
        crawl_method = crawl_result.method
        result["crawl"] = crawl_result
        logger.info("  Crawl [%s]: %d URLs", crawl_result.method, len(crawl_result.urls))

        # --- Paso 2a: uptime desde la homepage explicita ---
        # Siempre medir uptime en site['url'], independientemente del orden del crawl.
        # Esto evita falsos DOWN cuando la primera URL del crawl es una pagina interna.
        run.checkpoint("Verificando disponibilidad", 8)
        homepage_url = site["url"]
        homepage_result = _run_scraper(homepage_url)
        is_up = not bool(homepage_result.get("error")) and bool(homepage_result.get("html"))
        status_code = homepage_result.get("status_code")
        response_time = homepage_result.get("response_time_ms")
        result["is_up"] = is_up

        if is_up:
            add_uptime(site_id, is_up=True, status_code=status_code, response_time_ms=response_time)
            logger.info("  Uptime: UP (status=%s, time=%sms)", status_code, response_time)
        else:
            add_uptime(
                site_id, is_up=False, status_code=status_code,
                error_msg=homepage_result.get("error") or "Sin respuesta",
            )
            logger.warning("  Uptime: CAIDO — %s", homepage_result.get("error"))
            try:
                send_site_down_alert(site, homepage_result.get("error"))
            except Exception as e:
                run.warn(f"No se pudo enviar la alerta de sitio caído: {e}")

        # --- Paso 2b: fetch HTML de todas las URLs del crawl ---
        html_results = [homepage_result]  # homepage ya scrapeada, incluir en analisis
        pending_urls = [
            u for u in crawl_result.urls if u.rstrip("/") != homepage_url.rstrip("/")
        ]
        total_pages = len(pending_urls) + 1
        for i, url in enumerate(pending_urls, 1):
            run.checkpoint(
                f"Descargando páginas ({i + 1}/{total_pages})",
                10 + int(60 * i / total_pages),
                pages_done=i, pages_total=total_pages,
            )
            logger.debug(" Scraping: %s", url)
            html_results.append(_run_scraper(url))
        result["html_results"] = html_results
        urls_analyzed = len(html_results)
        logger.info("  HTML scrapeado: %d páginas", len(html_results))

        failed_pages = [r for r in html_results if r.get("error") or not r.get("html")]
        if len(failed_pages) == len(html_results):
            first = (failed_pages[0].get("error") or "sin contenido")[:160]
            raise AuditError(
                f"No se pudo descargar ninguna página del sitio ({first}).", "connection"
            )
        if failed_pages:
            first = (failed_pages[0].get("error") or "sin contenido")[:100]
            run.warn(
                f"{len(failed_pages)} de {len(html_results)} páginas no se pudieron "
                f"descargar (ej.: {first})."
            )

        # --- Paso 3: analisis de patrones fijos ---
        run.checkpoint("Analizando HTML", 72)
        spam_domains = get_spam_domains()
        # Convertir old_domains (string CSV en BD) a lista para el analyzer
        _old = db_site["old_domains"] if "old_domains" in db_site.keys() else None
        if _old:
            site = dict(site)  # no mutar el original
            site["old_domains"] = [d.strip() for d in _old.split(",") if d.strip()]
        raw_threats = analyze_html(
            html_results, site, spam_domains,
            progress_cb=lambda i, n: run.checkpoint(
                f"Analizando HTML ({i}/{n} páginas)", 72 + int(8 * i / max(n, 1))
            ),
        )
        logger.info("  Patrones: %d amenazas en %s", len(raw_threats), site["name"])

        # --- Paso 3b: lista permitida ---
        # El recurso SE DETECTA igual, pero si coincide con una exclusion aprobada
        # se reconoce como legitimo y no se presenta como riesgo. Se aplica ANTES
        # de Claude: asi no se gastan creditos de IA en recursos ya aprobados.
        run.checkpoint("Aplicando lista permitida", 81)
        matcher = AllowlistMatcher(get_effective_allowlist(site_id))
        kept = []
        for t in raw_threats:
            rule = matcher.match(t.resource_url, site_id, t.threat_type) if t.resource_url else None
            if rule:
                allowlisted += 1
                logger.debug("  Permitido por regla %s: %s", rule["id"], t.resource_url)
            else:
                kept.append(t)
        if allowlisted:
            record_allowlist_hits(matcher.hits)
            logger.info("  Lista permitida: %d recursos reconocidos como legitimos", allowlisted)
        raw_threats = kept
        run.checkpoint(allowlisted_count=allowlisted)

        # --- Paso 4: analisis inteligente con Claude API ---
        # Claude solo se activa si analyzer encontro algo sospechoso
        run.checkpoint("Análisis con IA", 84)
        claude_result = claude_analyze(html_results, site, pattern_threats=raw_threats)
        ai_threats = []
        if claude_result.triggered and claude_result.has_anomalies():
            for a in claude_result.anomalies:
                ai_threats.append(
                    Threat(
                        threat_type=a.get("threat_type", "claude_anomaly"),
                        description=a.get("description", ""),
                        code_snippet=a.get("code_snippet", ""),
                        url_found=a.get("url_found", site["url"]),
                    )
                )
            logger.info("  Claude API: %d anomalias adicionales", len(ai_threats))
        elif getattr(claude_result, "failed", bool(claude_result.error)):
            ai_error = getattr(claude_result, "error_human", None) or claude_result.error
            logger.warning("  Claude API error: %s", claude_result.error)
        elif claude_result.error:
            logger.info("  Claude API omitido: %s", claude_result.error)
        run.checkpoint("Análisis con IA", 88)

        # --- Paso 5: clasificar severidad ---
        run.checkpoint("Clasificando alertas", 90)
        all_threats = raw_threats + ai_threats
        known_hosts = get_known_resource_hosts(site_id)
        base_host = get_host(site["url"])
        for t in all_threats:
            h = get_host(t.resource_url) if t.resource_url else ""
            if known_hosts and h and h not in known_hosts:
                t.extra_context["new_domain"] = True
        niche = site.get("niche", "general")
        classified = classify_threats(all_threats, niche, base_domain=base_host)
        summary = summarize_severities(classified)
        logger.info(" Severidad: %s", summary)

        # --- Paso 6: deduplicacion — marcar solo amenazas NUEVAS ---
        run.checkpoint("Guardando resultados", 94)
        cycle_start = cycle_started_at.isoformat() if cycle_started_at else None
        baseline = _Baseline(get_baseline_threats(site_id, cycle_started_at=cycle_start))

        # --- Paso 7: guardar amenazas en BD ---
        new_threats_count = 0
        for threat in classified:
            key = _threat_key(threat.threat_type, threat.url_found, threat.resource_url)
            is_new = not baseline.is_known(key)
            was_ignored = baseline.is_ignored(key)
            add_threat(
                audit_id=audit_id,
                site_id=site_id,
                threat_type=threat.threat_type,
                severity=threat.severity,
                description=threat.description,
                code_snippet=threat.code_snippet,
                url_found=threat.url_found,
                is_new=is_new,
                ignored=was_ignored,
                resource_url=threat.resource_url,
                signals=threat.signals,
            )
            threat.is_new = is_new
            threat.ignored = was_ignored
            if is_new:
                new_threats_count += 1

        result["threats"] = classified
        logger.info(
            " Amenazas guardadas: %d total, %d nuevas, %d ya omitidas (falso positivo)",
            len(classified), new_threats_count,
            sum(1 for t in classified if getattr(t, "ignored", False)),
        )

        # --- Paso 8: enviar alertas si hay amenazas CRITICAL/HIGH nuevas ---
        run.checkpoint("Enviando alertas", 97)
        new_threats = [t for t in classified if getattr(t, "is_new", False)]
        if new_threats:
            try:
                send_threat_alert(
                    site, new_threats,
                    cycle_started_at=cycle_started_at.isoformat() if cycle_started_at else None,
                )
            except Exception as e:
                run.warn(f"No se pudo enviar la alerta por email/SMS: {e}")

        # --- Paso 9: severidad y estado final ---
        # Se excluyen las ya omitidas (falso positivo) y las INFO (informativas):
        # no deben pintar el sitio como ALTO/CRITICO.
        relevant = [
            t for t in classified
            if not getattr(t, "ignored", False) and t.severity != INFO
        ]
        severity_max = max_severity(t.severity for t in relevant) if relevant else None
        result["has_issues"] = bool(relevant)
        result["severity_max"] = severity_max

        error_msg = None
        if ai_error and AI_ERROR_FAILS_AUDIT:
            final_status, error_msg = FAILED, ai_error
        else:
            if ai_error:
                run.warn(f"Análisis con IA no disponible: {ai_error}")
            final_status = COMPLETED_WITH_WARNINGS if run.warnings else COMPLETED
        warnings_txt = "\n".join(run.warnings)

        closed = finish_audit(
            audit_id, crawl_method=crawl_method, urls_analyzed=urls_analyzed,
            status=final_status, error_msg=error_msg, severity_max=severity_max,
            warnings=warnings_txt or None, allowlisted_count=allowlisted,
        )
        result.update(status=final_status, error=error_msg, warnings=warnings_txt, is_up=is_up)
        if not closed:
            logger.warning("  La auditoría %d ya estaba cerrada por otro proceso", audit_id)
            row = get_audit(audit_id)
            result.update(status=row["status"], error=row["error_msg"])
        logger.info(
            "  %s %s — %d URLs, %d amenazas (%d nuevas) (audit_id=%d)",
            {"COMPLETED": "✓", "COMPLETED_WITH_WARNINGS": "⚠", "FAILED": "✗"}.get(result["status"], "•"),
            site["name"], urls_analyzed, len(classified), new_threats_count, audit_id,
        )
        if closed:
            enh_ctx = (classified, html_results)

    except AuditCancelled:
        finish_audit(audit_id, crawl_method, urls_analyzed, CANCELLED,
                     error_msg=f"Auditoría cancelada manualmente (etapa: {run.stage}).",
                     warnings="\n".join(run.warnings) or None)
        result.update(status=CANCELLED, error="Auditoría cancelada manualmente.")
        logger.info(" ⛔ %s — cancelada", site["name"])

    except AuditAborted:
        row = get_audit(audit_id)
        result.update(status=row["status"] if row else FAILED, error=row["error_msg"] if row else None)
        logger.warning(" ✗ %s — la auditoría fue cerrada por el vigilante: %s", site["name"], result["error"])

    except BaseException as e:  # incluye KeyboardInterrupt / SystemExit (SIGTERM)
        code, msg = classify_exception(e, "el servicio externo")
        reason = f"{msg} (etapa: {run.stage})"
        # severidad de lo ya clasificado (si se llego a ese punto) para no perderla
        sev = max_severity(t.severity for t in classified if not getattr(t, "ignored", False) and t.severity != INFO) if classified else None
        finish_audit(audit_id, crawl_method, urls_analyzed, FAILED, error_msg=reason,
                     severity_max=sev, warnings="\n".join(run.warnings) or None)
        result.update(status=FAILED, error=reason)
        logger.error(" ✗ %s — %s", site["name"], reason, exc_info=code == "internal")
        if isinstance(e, (KeyboardInterrupt, SystemExit)):
            raise
        
    # --- Mejoras posteriores a la auditoria (aisladas; ver paquete enhancements) ---
    if enh_ctx is not None:
        _run_enhancements(site, site_id, audit_id, enh_ctx[0], enh_ctx[1], result)

    return result


# =============================================================
# CICLO PRINCIPAL
# =============================================================


def run_cycle(csv_path: Path = None, dry_run: bool = False, cycle_log_id: int = None,
              scheduled: bool = False):
    """
    Ejecuta un ciclo completo de auditoría para todos los sitios activos.

    Todas las auditorias del ciclo se crean de entrada en estado PENDING (asi
    la interfaz muestra la cola) y pasan a RUNNING una a una.

    Args:
        csv_path: Ruta al CSV. Si es None usa el path por defecto.
        dry_run:  Si True, carga y muestra los sitios pero no audita.
        scheduled: True solo cuando lo llama el scheduler: aplica la programacion
                  por campania (paquete enhancements). Por defecto False = se
                  auditan todos los sitios activos, como siempre.
    """
    started_at = datetime.now(timezone.utc)
    logger.info("=" * 60)
    logger.info(
        "SAAF Pro — Inicio de ciclo: %s", started_at.strftime("%Y-%m-%d %H:%M:%S UTC")
    )
    logger.info("=" * 60)

    # --- Paso 1: Inicializar BD ---
    try:
        init_db()
        logger.info("Base de datos lista")
    except Exception as e:
        logger.error("Error inicializando la BD: %s", e)
        raise RuntimeError(f"Error inicializando BD: {e}")

    # Cerrar auditorias que quedaron colgadas de ejecuciones anteriores
    try:
        for c in reap_stale_audits():
            logger.warning("Auditoría %s cerrada por el vigilante: %s", c["id"], c["reason"])
    except Exception as e:
        logger.warning("No se pudo ejecutar el vigilante de auditorías: %s", e)

    # --- Paso 2: Cargar y sincronizar sitios ---
    try:
        active_sites = load_and_sync_sites(csv_path)
    except Exception as e:
        logger.error("Error cargando sitios: %s", e)
        raise RuntimeError(f"Error cargando sitios: {e}")

    if not active_sites:
        logger.warning("No hay sitios activos para auditar. Ciclo terminado.")
        return []
    
    if scheduled:
        try:
            from enhancements import filter_sites_for_cycle

            active_sites = filter_sites_for_cycle(active_sites)
        except Exception:
            pass  # sin el paquete (o con error) se auditan todos, como siempre
        if not active_sites:
            logger.info("Ninguna campaña le corresponde al ciclo general (programación propia o auditoría automática desactivada)")
            return []

    logger.info("Sitios activos a auditar: %d", len(active_sites))
    for s in active_sites:
        logger.info(" • [%s] %s — %s", s["priority"], s["name"], s["url"])

    if dry_run:
        logger.info("Modo dry-run: no se ejecuta la auditoría")
        _print_summary(active_sites)
        return []

    # --- Paso 3: Auditar cada sitio ---
    if cycle_log_id is None:
        cycle_log_id = start_cycle_log()
        logger.info("cycle_log_id = %d", cycle_log_id)

    # Cola: una auditoria PENDING por sitio
    queue = {}
    for site in active_sites:
        db_site = get_site_by_url(site["url"])
        if db_site:
            queue[site["url"]] = start_audit(db_site["id"], cycle_log_id=cycle_log_id, status=PENDING)

    results = {"ok": 0, "issues": 0, "error": 0, "cancelled": 0}
    site_results = []

    try:
        for site in active_sites:
            try:
                result = audit_site(
                    site, cycle_log_id=cycle_log_id, cycle_started_at=started_at,
                    audit_id=queue.get(site["url"]),
                )
                site_results.append(result)
                st = result["status"]
                if st == FAILED:
                    results["error"] += 1
                    logger.warning("Error en '%s': %s", site.get("url"), result.get("error"))
                elif st == CANCELLED:
                    results["cancelled"] += 1
                elif result.get("has_issues"):
                    results["issues"] += 1
                else:
                    results["ok"] += 1
            except Exception as e:
                # No deberia ocurrir (audit_site cierra su estado), pero si pasa
                # se registra y el ciclo continua con el siguiente sitio.
                logger.error("Excepción inesperada auditando '%s': %s", site.get("url"), e, exc_info=True)
                results["error"] += 1
                aid = queue.get(site["url"])
                if aid:
                    finish_audit(aid, "none", 0, FAILED, error_msg=f"Excepción no controlada: {e}")
                site_results.append({
                    "site": site, "status": FAILED, "severity_max": None, "is_up": None,
                    "has_issues": False, "threats": [], "error": str(e),
                })
    finally:
        # Si el ciclo se corta (SIGTERM, Ctrl+C), ninguna auditoria debe quedar PENDING
        for aid in queue.values():
            row = get_audit(aid)
            if row and row["status"] == PENDING:
                finish_audit(aid, "none", 0, FAILED, error_msg="El ciclo terminó antes de auditar este sitio.")

    # --- Paso 4: Resumen final ---
    finished_at = datetime.now(timezone.utc)
    duration = (finished_at - started_at).total_seconds()

    logger.info("=" * 60)
    logger.info("Ciclo completado en %.1f segundos", duration)
    logger.info("  OK: %d", results["ok"])
    logger.info("  Issues: %d", results["issues"])
    logger.info("  Errores: %d", results["error"])
    logger.info("  Canceladas: %d", results["cancelled"])
    logger.info("=" * 60)

    try:
        notes = []
        if results["error"]:
            notes.append(f"{results['error']} auditoría(s) fallaron")
        if results["cancelled"]:
            notes.append(f"{results['cancelled']} cancelada(s) manualmente")
        finish_cycle_log(
            cycle_log_id,
            status="ok" if not notes else "error",
            sites_total=len(active_sites),
            sites_ok=results["ok"],
            sites_issues=results["issues"],
            # is_up None = el sitio no pudo auditarse (error interno), NO que
            # este caido. Solo is_up False cuenta como caido.
            sites_down=sum(1 for r in site_results if r.get("is_up") is False),
            sites_error=results["error"],
            error_msg="; ".join(notes) or None,
        )
    except Exception as e:
        logger.warning("No se pudo cerrar cycle_log: %s", e)

    _print_summary(active_sites)
    return site_results


def _print_summary(active_sites: list):
    """Imprime un resumen del estado actual en consola."""
    try:
        summary = get_dashboard_summary()
        print("\n" + "=" * 50)
        print("SAAF Pro — Estado actual")
        print("=" * 50)
        print(f"  Sitios activos: {summary['total_sites']}")
        print(f"  Sitios caídos: {summary['sites_down']}")
        print(f"  Amenazas CRITICAL: {summary['open_critical']}")
        print(f"  Amenazas HIGH: {summary['open_high']}")
        print(f"  Amenazas totales: {summary['open_total']}")
        print("=" * 50)
        print("\nSitios cargados para auditoría:")
        for s in active_sites:
            sitemap = s["sitemap_url"] or "(sin sitemap — crawl automático)"
            print(f"  [{s['priority']:<6}] {s['name']:<25} {s['url']}")
            print(f"  nicho: {s['niche']:<12} sitemap: {sitemap}")
    except Exception as e:
        logger.warning("No se pudo mostrar el resumen: %s", e)


# =============================================================
# ENTRYPOINT
# =============================================================

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="SAAF Pro — Orquestador de auditoría")
    parser.add_argument(
        "--csv",
        type=Path,
        default=None,
        help="Ruta al archivo sites.csv (default: /home/admin_ubuntu/Desktop/proyecto_saaf/opt/saaf/config/sites.csv)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Solo carga y muestra los sitios sin ejecutar la auditoría",
    )
    args = parser.parse_args()

    # systemd stop envia SIGTERM: convertirlo en SystemExit permite que
    # audit_site() deje la auditoria en FAILED ("interrumpida") en vez de RUNNING.
    if threading.current_thread() is threading.main_thread():
        signal.signal(signal.SIGTERM, lambda signum, frame: sys.exit(143))

    run_cycle(csv_path=args.csv, dry_run=args.dry_run)
