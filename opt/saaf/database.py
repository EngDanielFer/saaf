#!/home/admin_ubuntu/Desktop/proyecto_saaf/opt/saaf/venv/bin/python
# =============================================================
# SAAF Pro — database.py
# Esquema SQLite, conexión y funciones CRUD completas
# Ruta: /home/admin_ubuntu/Desktop/proyecto_saaf/opt/saaf/database.py
# =============================================================

import sqlite3
import logging
import os
import socket
from datetime import datetime, timezone
from zoneinfo import ZoneInfo
from pathlib import Path
from contextlib import contextmanager

from audit_state import (
    PENDING, RUNNING, COMPLETED, COMPLETED_WITH_WARNINGS, FAILED, CANCELLED,
    TERMINAL_STATUSES, normalize_status,
)
from severity import normalize_severity

logger = logging.getLogger(__name__)

# Ruta de la BD — sobreescribible con variable de entorno para tests
DB_PATH = Path(
    os.environ.get(
        "SAAF_DB_PATH", "/home/admin_ubuntu/Desktop/proyecto_saaf/opt/saaf/data/saaf.db"
    )
)


# =============================================================
# CONEXIÓN
# =============================================================


@contextmanager
def get_conn():
    """
    Context manager que abre y cierra la conexión SQLite automáticamente.
    Hace commit en éxito y rollback en excepción.
    """
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH), detect_types=sqlite3.PARSE_DECLTYPES)
    conn.row_factory = sqlite3.Row  # Acceso a columnas por nombre
    conn.execute("PRAGMA journal_mode=WAL")  # Escrituras concurrentes seguras
    conn.execute("PRAGMA foreign_keys=ON")  # Integridad referencial activa
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# =============================================================
# ESQUEMA — CREACIÓN DE TABLAS
# =============================================================

SCHEMA_SQL = """
-- --------------------------------------------------------
-- Sitios a monitorear (cada sitio = una campaña)
-- --------------------------------------------------------
CREATE TABLE IF NOT EXISTS sites (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    url TEXT NOT NULL UNIQUE,
    sitemap_url TEXT,
    niche TEXT NOT NULL DEFAULT 'general',
    priority TEXT NOT NULL DEFAULT 'normal' CHECK(priority IN ('high', 'normal', 'low')),
    active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

-- --------------------------------------------------------
-- Log de ejecuciones del ciclo automático (scheduler)
-- --------------------------------------------------------
CREATE TABLE IF NOT EXISTS cycle_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    status TEXT NOT NULL DEFAULT 'running' CHECK(status IN ('running', 'ok', 'error')),
    sites_total INTEGER DEFAULT 0,
    sites_ok INTEGER DEFAULT 0,
    sites_issues INTEGER DEFAULT 0,
    sites_down INTEGER DEFAULT 0,
    sites_error INTEGER DEFAULT 0,
    error_msg TEXT
);

-- --------------------------------------------------------
-- Ciclos de auditoría (una fila por sitio por ejecución)
-- Estados: PENDING, RUNNING, COMPLETED, COMPLETED_WITH_WARNINGS,
--          FAILED, CANCELLED  (ver audit_state.py)
-- last_activity_at: latido del proceso; permite detectar auditorías
-- que dejaron de ejecutarse sin reportar error.
-- --------------------------------------------------------
CREATE TABLE IF NOT EXISTS audits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    site_id INTEGER NOT NULL REFERENCES sites(id)
ON DELETE CASCADE,
    started_at TEXT NOT NULL,
    finished_at TEXT,
    crawl_method TEXT CHECK(crawl_method IN ('sitemap', 'crawl', 'none')),
    urls_analyzed INTEGER DEFAULT 0,
    status TEXT NOT NULL DEFAULT 'RUNNING' CHECK(status IN ('PENDING','RUNNING','COMPLETED','COMPLETED_WITH_WARNINGS','FAILED','CANCELLED')),
    severity_max TEXT CHECK(severity_max IN ('CRITICAL','HIGH','MEDIUM','LOW','INFO') OR severity_max IS NULL),
    error_msg TEXT,
    cycle_log_id INTEGER REFERENCES cycle_logs(id),
    last_activity_at TEXT,
    current_stage TEXT,
    progress INTEGER NOT NULL DEFAULT 0,
    worker_pid INTEGER,
    worker_host TEXT,
    cancel_requested INTEGER NOT NULL DEFAULT 0,
    warnings TEXT,
    pages_total INTEGER DEFAULT 0,
    pages_done INTEGER DEFAULT 0,
    allowlisted_count INTEGER DEFAULT 0
);

-- --------------------------------------------------------
-- Lista de exclusiones (recursos legitimos ya aprobados)
-- scope='global' -> todas las campañas ; scope='site' -> solo site_id
-- --------------------------------------------------------
CREATE TABLE IF NOT EXISTS allowlist_rules (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scope TEXT NOT NULL CHECK(scope IN ('global', 'site')),
    site_id INTEGER REFERENCES sites(id) ON DELETE CASCADE,
    match_type TEXT NOT NULL DEFAULT 'url' CHECK(match_type IN ('url', 'contains', 'regex')),
    pattern TEXT NOT NULL,
    threat_type TEXT,
    reason TEXT,
    active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now')),
    created_by TEXT DEFAULT 'manual',
    source_threat_id INTEGER,
    hit_count INTEGER NOT NULL DEFAULT 0,
    last_hit_at TEXT,
    CHECK((scope = 'global' AND site_id IS NULL) OR (scope = 'site' AND site_id IS NOT NULL))
);

-- --------------------------------------------------------
-- Amenazas / problemas detectados en cada auditoría
-- resource_url: recurso sospechoso (src/href) — distinto de url_found,
--               que es la PAGINA donde se encontro.
-- signals:      JSON con las señales que justifican la severidad.
-- allowlist_rule_id: regla que dejo la amenaza como permitida (ignored=1).
-- --------------------------------------------------------

CREATE TABLE IF NOT EXISTS threats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    audit_id INTEGER NOT NULL REFERENCES audits(id) ON DELETE CASCADE,
    site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    detected_at TEXT NOT NULL DEFAULT (datetime('now')),
    threat_type TEXT NOT NULL,
    severity TEXT NOT NULL CHECK (severity in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO')),
    description TEXT NOT NULL,
    code_snippet TEXT,
    url_found TEXT,
    resolved INTEGER NOT NULL DEFAULT 0,
    resolved_at TEXT,
    is_new INTEGER NOT NULL DEFAULT 1,
    ignored INTEGER NOT NULL DEFAULT 0,
    ignored_at TEXT,
    resource_url TEXT,
    signals TEXT,
    allowlist_rule_id INTEGER REFERENCES allowlist_rules(id) ON DELETE SET NULL
);

-- --------------------------------------------------------
-- Registro de uptime (una fila por verificación por sitio)
-- --------------------------------------------------------
CREATE TABLE IF NOT EXISTS uptime (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    checked_at TEXT NOT NULL DEFAULT (datetime('now')),
    is_up INTEGER NOT NULL,
    status_code INTEGER,
    response_time_ms INTEGER,
    error_msg TEXT
);

-- --------------------------------------------------------
-- Reportes generados (diarios y por sitio)
-- --------------------------------------------------------
CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    generated_at TEXT NOT NULL DEFAULT (datetime('now')),
    report_type TEXT NOT NULL CHECK(report_type IN ('daily', 'site')),
    site_id INTEGER REFERENCES sites(id) ON DELETE SET NULL,
    file_path TEXT NOT NULL,
    summary TEXT
);

-- --------------------------------------------------------
-- Dominios spam conocidos (editable desde el frontend)
-- --------------------------------------------------------
CREATE TABLE IF NOT EXISTS spam_domains (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    domain TEXT NOT NULL UNIQUE,
    added_at TEXT NOT NULL DEFAULT (datetime('now')),
    added_by TEXT DEFAULT 'manual'
);

-- --------------------------------------------------------
-- Configuracion general de la app (clave/valor) — incluye
-- la frecuencia del ciclo automatico (diaria/semanal)
-- --------------------------------------------------------
CREATE TABLE IF NOT EXISTS app_settings (
    key TEXT PRIMARY KEY,
    value TEXT,
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);
"""

# Los indices se crean DESPUES de las migraciones (init_db): en una BD
# preexistente las tablas se reconstruyen (ver _migrate_to_v2) y al
# reconstruirlas SQLite elimina sus indices; ademas algunos usan columnas
# que solo existen tras migrar.
INDEXES_SQL = """
CREATE INDEX IF NOT EXISTS idx_audits_site ON audits(site_id, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_audits_active ON audits(status, last_activity_at);
CREATE INDEX IF NOT EXISTS idx_threats_site ON threats(site_id, detected_at DESC);
CREATE INDEX IF NOT EXISTS idx_threats_open ON threats(resolved, severity);
CREATE INDEX IF NOT EXISTS idx_threats_open2 ON threats(resolved, ignored, site_id);
CREATE INDEX IF NOT EXISTS idx_threats_rule ON threats(allowlist_rule_id);
CREATE INDEX IF NOT EXISTS idx_uptime_site ON uptime(site_id, checked_at DESC);
CREATE INDEX IF NOT EXISTS idx_allowlist_active ON allowlist_rules(active, scope, site_id);
CREATE UNIQUE INDEX IF NOT EXISTS uq_allowlist_rule ON allowlist_rules(
    scope, IFNULL(site_id, 0), match_type, pattern, IFNULL(threat_type, '')
);
"""

SCHEMA_VERSION = 2

DEFAULT_SPAM_DOMAINS = [
    "casino.com",
    "poker.com",
    "viagra.com",
    "cialis.com",
    "xvideos.com",
    "pornhub.com",
    "onlinecasino.com",
    "casinobonus.com",
    "freeslots.com",
    "adult-xxx.com",
    "pharmastore.com",
    "cheapmeds.com",
    "buypills.com",
]

_LEGACY_SEVERITY_SQL = (
    "CASE {col} WHEN 'CRITICO' THEN 'CRITICAL' WHEN 'ALTO' THEN 'HIGH' "
    "WHEN 'MEDIO' THEN 'MEDIUM' WHEN 'BAJO' THEN 'LOW' ELSE {col} END"
)


def _table_columns(conn, table):
    return [r[1] for r in conn.execute(f"PRAGMA table_info({table})").fetchall()]


def _rebuild_table(conn, table, create_sql_new, select_exprs):
    """
    Reconstruye `table` (receta oficial de SQLite para cambiar CHECKs):
    crea <table>_new, copia, elimina la vieja y renombra. Requiere
    foreign_keys=OFF y una transaccion abierta. select_exprs: {col_nueva: expr_sql}
    solo para las columnas que existen en la tabla vieja o tienen valor calculado.
    """
    old_seq = conn.execute(
        "SELECT seq FROM sqlite_sequence WHERE name=?", (table,)
    ).fetchone()
    conn.execute(f"DROP TABLE IF EXISTS {table}_new")
    conn.execute(create_sql_new)
    cols = list(select_exprs.keys())
    conn.execute(
        f"INSERT INTO {table}_new ({', '.join(cols)}) "
        f"SELECT {', '.join(select_exprs[c] for c in cols)} FROM {table}"
    )
    conn.execute(f"DROP TABLE {table}")
    conn.execute(f"ALTER TABLE {table}_new RENAME TO {table}")
    if old_seq:
        cur = conn.execute("SELECT seq FROM sqlite_sequence WHERE name=?", (table,)).fetchone()
        if cur is None:
            conn.execute("INSERT INTO sqlite_sequence (name, seq) VALUES (?, ?)", (table, old_seq[0]))
        elif cur[0] < old_seq[0]:
            conn.execute("UPDATE sqlite_sequence SET seq=? WHERE name=?", (old_seq[0], table))


def _create_sql_of(table):
    """Extrae del SCHEMA_SQL el CREATE TABLE de `table`, apuntando a <table>_new."""
    start = SCHEMA_SQL.index(f"CREATE TABLE IF NOT EXISTS {table} (")
    end = SCHEMA_SQL.index("\n);", start) + 3
    return SCHEMA_SQL[start:end].replace(
        f"CREATE TABLE IF NOT EXISTS {table} (", f"CREATE TABLE {table}_new (", 1
    )


def _migrate_to_v2():
    """
    Migra una BD de la version anterior (CRITICO/ALTO/MEDIO/BAJO y estados
    running/ok/issues/error) al esquema v2. Idempotente y segura ante dos
    procesos arrancando a la vez (BEGIN IMMEDIATE + re-chequeo de user_version).

      * audits : nuevos estados + columnas de latido/etapa/progreso/cancelacion.
                 Una auditoria 'running' heredada NO puede estar ejecutandose
                 (no tiene latido) -> pasa a FAILED con motivo explicito.
      * threats: severidades en ingles + INFO; columnas resource_url, signals,
                 allowlist_rule_id; resource_url se reconstruye de la descripcion.
    """
    from allowlist import extract_resource_url

    raw = sqlite3.connect(str(DB_PATH), timeout=30, isolation_level=None)
    raw.row_factory = sqlite3.Row
    try:
        raw.execute("PRAGMA foreign_keys=OFF")  # no se puede cambiar dentro de una transaccion
        raw.execute("BEGIN IMMEDIATE")
        try:
            if raw.execute("PRAGMA user_version").fetchone()[0] >= SCHEMA_VERSION:
                raw.execute("COMMIT")
                return False
            audit_cols = _table_columns(raw, "audits")
            threat_cols = _table_columns(raw, "threats")
            already_new = "last_activity_at" in audit_cols and "resource_url" in threat_cols
            migrated = False
            if not already_new:
                migrated = True
                # ---- audits ----
                a_old = set(audit_cols)
                a_exprs = {
                    "id": "id", "site_id": "site_id", "started_at": "started_at",
                    "finished_at": "finished_at", "crawl_method": "crawl_method",
                    "urls_analyzed": "urls_analyzed",
                    "status": (
                        "CASE status WHEN 'running' THEN 'FAILED' WHEN 'ok' THEN 'COMPLETED' "
                        "WHEN 'issues' THEN 'COMPLETED' ELSE 'FAILED' END"
                    ),
                    "severity_max": (
                        _LEGACY_SEVERITY_SQL.format(col="severity_max")
                        if "severity_max" in a_old else "NULL"
                    ),
                    "error_msg": (
                        "CASE WHEN status='running' AND error_msg IS NULL THEN "
                        "'Auditoría interrumpida (estado heredado de la versión anterior: nunca terminó)' "
                        "ELSE error_msg END"
                    ),
                    "cycle_log_id": "cycle_log_id" if "cycle_log_id" in a_old else "NULL",
                    "last_activity_at": "COALESCE(finished_at, started_at)",
                    "progress": "CASE WHEN status IN ('ok','issues') THEN 100 ELSE 0 END",
                }
                a_exprs = {k: v for k, v in a_exprs.items()
                           if k in ("last_activity_at", "progress", "status", "severity_max",
                                    "error_msg", "cycle_log_id") or k in a_old}
                _rebuild_table(raw, "audits", _create_sql_of("audits"), a_exprs)

                # ---- threats ----
                t_old = set(threat_cols)
                base = ["id", "audit_id", "site_id", "detected_at", "threat_type", "description",
                        "code_snippet", "url_found", "resolved", "resolved_at", "is_new"]
                t_exprs = {c: c for c in base if c in t_old}
                t_exprs["severity"] = _LEGACY_SEVERITY_SQL.format(col="severity")
                if "ignored" in t_old:
                    t_exprs["ignored"] = "ignored"
                if "ignored_at" in t_old:
                    t_exprs["ignored_at"] = "ignored_at"
                _rebuild_table(raw, "threats", _create_sql_of("threats"), t_exprs)

                # Reconstruir resource_url de las amenazas antiguas
                rows = raw.execute(
                    "SELECT id, threat_type, description, code_snippet, url_found FROM threats"
                ).fetchall()
                updates = []
                for r in rows:
                    res = extract_resource_url(
                        r["threat_type"], r["description"], r["code_snippet"], r["url_found"]
                    )
                    if res:
                        updates.append((res, r["id"]))
                raw.executemany("UPDATE threats SET resource_url=? WHERE id=?", updates)
                logger.info(
                    "Migracion v2: %d amenazas con resource_url reconstruido (de %d)",
                    len(updates), len(rows),
                )

            raw.execute(f"PRAGMA user_version={SCHEMA_VERSION}")
            raw.execute("COMMIT")
        except Exception:
            raw.execute("ROLLBACK")
            raise
        if migrated:
            bad = raw.execute("PRAGMA foreign_key_check").fetchall()
            if bad:
                logger.warning("Migracion v2: %d filas con FK inconsistente", len(bad))
            logger.info("Migracion v2 aplicada (esquema %d)", SCHEMA_VERSION)
        return migrated
    finally:
        raw.close()


def init_db():
    """
    Crea todas las tablas si no existen, migra BDs antiguas y siembra datos
    iniciales. Seguro de llamar múltiples veces (idempotente).
    """
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with get_conn() as conn:
        conn.executescript(SCHEMA_SQL)
        # Sembrar dominios spam por defecto
        conn.executemany(
            "INSERT OR IGNORE INTO spam_domains (domain, added_by) VALUES (?, ?)",
            [(d, "seed") for d in DEFAULT_SPAM_DOMAINS],
        )
    with get_conn() as conn:
        cols = [r[1] for r in conn.execute("PRAGMA table_info(audits)").fetchall()]
        if "severity_max" not in cols:
            conn.execute("ALTER TABLE audits ADD COLUMN severity_max TEXT")
            logger.info("Migracion: columna severity_max agregada a audits")
        # Migración: agregar columnas ignored/ignored_at a threats (BDs existentes)
        threat_cols = [
            r[1] for r in conn.execute("PRAGMA table_info(threats)").fetchall()
        ]
        if "ignored" not in threat_cols:
            conn.execute(
                "ALTER TABLE threats ADD COLUMN ignored INTEGER NOT NULL DEFAULT 0"
            )
            logger.info("Migracion: columna ignored agregada a threats")
        if "ignored_at" not in threat_cols:
            conn.execute("ALTER TABLE threats ADD COLUMN ignored_at TEXT")
            logger.info("Migracion: columna ignored_at agregada a threats")
        # Migración: agregar old_domains a sites (dominios antiguos del sitio,
        # separados por coma — usado por detect_broken_internal_links)
        site_cols = [r[1] for r in conn.execute("PRAGMA table_info(sites)").fetchall()]
        if "old_domains" not in site_cols:
            conn.execute("ALTER TABLE sites ADD COLUMN old_domains TEXT")
            logger.info("Migracion: columna old_domains agregada a sites")
    # Esquema v2 (estados nuevos, severidades en ingles, exclusiones)
    _migrate_to_v2()
    with get_conn() as conn:
        conn.executescript(INDEXES_SQL)
        logger.info("Base de datos inicializada en %s", DB_PATH)


# =============================================================
# CONFIGURACION GENERAL (clave/valor) Y FRECUENCIA DEL CICLO
# =============================================================

# =============================================================
# Zona horaria de Colombia — usada para el scheduler (cuando se
# ejecuta el bot) y para MOSTRAR timestamps en la interfaz.
# La base de datos sigue guardando todo en UTC internamente (es la
# practica correcta: evita ambiguedades y no rompe la logica de
# deduplicacion/baseline que compara timestamps) — la conversion a
# hora de Colombia se hace solo al presentar datos al usuario.
# Colombia NO tiene horario de verano, siempre es UTC-5 todo el año.
# =============================================================

COLOMBIA_TZ = ZoneInfo("America/Bogota")


def to_local_str(raw_ts, fmt: str = "%Y-%m-%d %H:%M") -> str:
    """
    Convierte un timestamp UTC almacenado en la BD (isoformat() de Python
    con 'T' y offset, o el formato de SQLite 'YYYY-MM-DD HH:MM:SS') a
    hora de Colombia, lista para mostrar en la interfaz.
 
    Si el valor viene vacio o no se puede interpretar, devuelve el
    valor original recortado (comportamiento seguro, nunca revienta
    la UI de Streamlit).
    """
    if not raw_ts:
        return "—"
    s = str(raw_ts).strip()
    try:
        dt = datetime.fromisoformat(s.replace(" ", "T", 1) if "T" not in s else s)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)  # SQLite datetime('now') siempre es UTC
        return dt.astimezone(COLOMBIA_TZ).strftime(fmt)
    except (ValueError, TypeError):
        return s[:16]
    
 
WEEKDAY_LABELS = {
    "mon": "Lunes",
    "tue": "Martes",
    "wed": "Miércoles",
    "thu": "Jueves",
    "fri": "Viernes",
    "sat": "Sábado",
    "sun": "Domingo",
}
 
DEFAULT_SCHEDULE_CONFIG = {
    "frequency": "daily",  # 'daily' o 'weekly'
    "hour": 8,
    "minute": 0,
    "weekday": "mon",  # solo se usa si frequency == 'weekly'
}


def get_setting(key: str, default=None):
    """Lee un valor de configuracion general por clave. None/​default si no existe."""
    with get_conn() as conn:
        row = conn.execute(
            "SELECT value FROM app_settings WHERE key=?", (key,)
        ).fetchone()
    return row["value"] if row else default
 
 
def set_setting(key: str, value: str):
    """Crea o actualiza un valor de configuracion general."""
    with get_conn() as conn:
        conn.execute(
            """INSERT INTO app_settings (key, value, updated_at)
               VALUES (?, ?, ?)
               ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at""",
            (key, value, datetime.now(timezone.utc).isoformat()),
        )
    logger.info("Setting actualizado: %s=%s", key, value)
    

def get_schedule_config() -> dict:
    """
    Devuelve la configuracion de frecuencia del ciclo automatico:
    {'frequency': 'daily'|'weekly', 'hour': int, 'minute': int, 'weekday': 'mon'..'sun'}
    Si no se ha configurado nunca desde el Dashboard, devuelve los valores
    por defecto (diaria, 08:00 hora de Colombia).
    """
    import json
 
    raw = get_setting("schedule_config")
    if not raw:
        return dict(DEFAULT_SCHEDULE_CONFIG)
    try:
        cfg = json.loads(raw)
        merged = dict(DEFAULT_SCHEDULE_CONFIG)
        merged.update({k: v for k, v in cfg.items() if v is not None})
        return merged
    except (ValueError, TypeError):
        logger.warning("schedule_config invalido en BD, usando default")
        return dict(DEFAULT_SCHEDULE_CONFIG)
    

def set_schedule_config(frequency: str, hour: int, minute: int, weekday: str = "mon"):
    """
    Guarda la configuracion de frecuencia del ciclo automatico.
 
    Args:
        frequency: 'daily' o 'weekly'
        hour:      0-23 (hora de Colombia, America/Bogota — igual que scheduler.py)
        minute:    0-59
        weekday:   'mon','tue','wed','thu','fri','sat','sun' — solo aplica si frequency='weekly'
    """
    import json
 
    if frequency not in ("daily", "weekly"):
        raise ValueError("frequency debe ser 'daily' o 'weekly'")
    if not (0 <= hour <= 23):
        raise ValueError("hour debe estar entre 0 y 23")
    if not (0 <= minute <= 59):
        raise ValueError("minute debe estar entre 0 y 59")
    if weekday not in WEEKDAY_LABELS:
        raise ValueError(f"weekday invalido: {weekday}")
 
    cfg = {
        "frequency": frequency,
        "hour": int(hour),
        "minute": int(minute),
        "weekday": weekday,
    }
    set_setting("schedule_config", json.dumps(cfg))
    return cfg


# -------------------------------------------------------------
# Ejecucion UNICA (one-shot) — independiente de la frecuencia
# diaria/semanal. Se guarda en app_settings bajo la clave 'once_run'
# como JSON {"date": "YYYY-MM-DD", "hour": int, "minute": int}
# (hora de Colombia). scheduler.py la lee, la programa y la borra
# despues de ejecutarla.
# -------------------------------------------------------------


def get_once_run():
    """Devuelve {'date','hour','minute'} de la ejecucion unica pendiente, o None."""
    import json

    raw = get_setting("once_run")
    if not raw:
        return None
    try:
        cfg = json.loads(raw)
        datetime.strptime(cfg["date"], "%Y-%m-%d")
        return {
            "date": cfg["date"],
            "hour": int(cfg["hour"]),
            "minute": int(cfg["minute"]),
        }
    except (ValueError, TypeError, KeyError):
        logger.warning("once_run invalido en BD, se ignora")
        return None


def set_once_run(date_str: str, hour: int, minute: int):
    """Programa una ejecucion unica. date_str = 'YYYY-MM-DD' (hora de Colombia)."""
    import json

    datetime.strptime(date_str, "%Y-%m-%d")  # valida formato
    if not (0 <= hour <= 23):
        raise ValueError("hour debe estar entre 0 y 23")
    if not (0 <= minute <= 59):
        raise ValueError("minute debe estar entre 0 y 59")
    cfg = {"date": date_str, "hour": int(hour), "minute": int(minute)}
    set_setting("once_run", json.dumps(cfg))
    return cfg


def clear_once_run():
    """Cancela / limpia la ejecucion unica pendiente."""
    set_setting("once_run", "")


# =============================================================
# CRUD — SITES
# =============================================================


def upsert_site(
    name, url, sitemap_url=None, niche="general", priority="normal", active=True, old_domains=None
):
    """
    Inserta el sitio si no existe, o actualiza si ya existe (por URL).
    Retorna el id del sitio.

    Usa INSERT OR IGNORE + UPDATE en lugar de SELECT + INSERT para eliminar
    la race condition: si dos procesos llaman a upsert_site al mismo tiempo
    con la misma URL, ninguno falla — el INSERT OR IGNORE del segundo es
    simplemente ignorado y el UPDATE actualiza el registro existente.
    Una sola transaccion atomica, sin ventana de colision.
    """
    url = url.rstrip("/")
    now = datetime.now(timezone.utc).isoformat()
    with get_conn() as conn:
        # Paso 1: insertar solo si no existe (atomico, sin race condition)
        conn.execute(
            """INSERT OR IGNORE INTO sites (name, url, sitemap_url, niche, priority, active, old_domains, created_at, updated_at)
            VALUES (?,?,?,?,?,?,?,?,?)""",
            (name, url, sitemap_url, niche, priority, 1 if active else 0, old_domains, now, now),
        )
        # Paso 2: actualizar siempre (si ya existia o recien insertado)
        conn.execute(
            """UPDATE sites
            SET name=?, sitemap_url=?, niche=?, priority=?, active=?, old_domains=?, updated_at=?
            WHERE url=?""",
            (name, sitemap_url, niche, priority, 1 if active else 0, old_domains, now, url),
        )
        site_id = conn.execute("SELECT id FROM sites WHERE url=?", (url,)).fetchone()[
            "id"
        ]
        logger.debug("Sitio upserted: %s (id=%d)", url, site_id)
        return site_id


def get_all_sites(active_only=False):
    with get_conn() as conn:
        if active_only:
            return conn.execute(
                "SELECT * FROM sites WHERE active=1 ORDER BY priority DESC, name"
            ).fetchall()
        return conn.execute("SELECT * FROM sites ORDER BY name").fetchall()


def get_site(site_id):
    with get_conn() as conn:
        return conn.execute("SELECT * FROM sites WHERE id=?", (site_id,)).fetchone()


def get_site_by_url(url):
    with get_conn() as conn:
        return conn.execute(
            "SELECT * FROM sites WHERE url=?", (url.rstrip("/"),)
        ).fetchone()


def update_site(site_id, **kwargs):
    allowed = {"name", "url", "sitemap_url", "niche", "priority", "active"}
    fields = {k: v for k, v in kwargs.items() if k in allowed}
    if not fields:
        return
    fields["updated_at"] = datetime.now(timezone.utc).isoformat()
    set_clause = ", ".join(f"{k}=?" for k in fields)
    with get_conn() as conn:
        conn.execute(
            f"UPDATE sites SET {set_clause} WHERE id=?",
            list(fields.values()) + [site_id],
        )


def delete_site(site_id):
    with get_conn() as conn:
        conn.execute("DELETE FROM sites WHERE id=?", (site_id,))
        logger.info("Sitio eliminado: id=%d", site_id)


# =============================================================
# CRUD — AUDITS
# =============================================================


# =============================================================
# CRUD — AUDITS (ciclo de vida: PENDING -> RUNNING -> estado final)
# =============================================================

# Una auditoria RUNNING sin latido durante este tiempo se considera detenida.
# El peor hueco legitimo entre latidos es una pagina lenta (~35 s) o un
# request de crawl (15 s), asi que 10 min es muy conservador.
AUDIT_STALE_MINUTES = float(os.environ.get("SAAF_AUDIT_STALE_MINUTES", "10"))
# Si ademas el PID del proceso ya no existe, basta con esta gracia.
AUDIT_DEAD_GRACE_SECONDS = float(os.environ.get("SAAF_AUDIT_DEAD_GRACE_SECONDS", "90"))
MAX_WARNINGS_CHARS = 4000


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _parse_ts(raw):
    """Timestamp de la BD (isoformat o 'YYYY-MM-DD HH:MM:SS' de SQLite) -> datetime UTC."""
    if not raw:
        return None
    s = str(raw).strip()
    try:
        dt = datetime.fromisoformat(s.replace(" ", "T", 1) if "T" not in s else s)
    except ValueError:
        return None
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)


parse_ts = _parse_ts  # alias publico (lo usan las vistas)


def _pid_alive(pid):
    """True/False si el proceso existe en ESTE host; None si no se puede saber."""
    if not pid:
        return None
    try:
        os.kill(int(pid), 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True  # existe, es de otro usuario
    except (OSError, ValueError, OverflowError):
        return None
    try:  # un zombi responde a kill(0) pero ya no ejecuta nada
        with open(f"/proc/{int(pid)}/stat") as f:
            return f.read().rsplit(")", 1)[1].split()[0] != "Z"
    except (OSError, IndexError):
        return True


def start_audit(site_id, cycle_log_id=None, status=RUNNING):
    """
    Crea una auditoria y registra el proceso que la ejecutara (PID + host).
    status=PENDING deja la auditoria en cola (el ciclo la pasa a RUNNING con
    mark_audit_running); status=RUNNING (default) la inicia de inmediato.
    """
    status = normalize_status(status)
    if status not in (PENDING, RUNNING):
        raise ValueError("start_audit solo admite PENDING o RUNNING")
    now = _now_iso()
    with get_conn() as conn:
        cur = conn.execute(
            """INSERT INTO audits (site_id, started_at, cycle_log_id, status,
                   last_activity_at, current_stage, progress, worker_pid, worker_host)
               VALUES (?,?,?,?,?,?,0,?,?)""",
            (site_id, now, cycle_log_id, status, now,
             "En cola" if status == PENDING else "Iniciando",
             os.getpid(), socket.gethostname()),
        )
        return cur.lastrowid


def mark_audit_running(audit_id, stage="Iniciando") -> bool:
    """PENDING -> RUNNING. False si ya no estaba PENDING (cancelada o cerrada)."""
    now = _now_iso()
    with get_conn() as conn:
        cur = conn.execute(
            """UPDATE audits SET status='RUNNING', started_at=?, last_activity_at=?,
                   current_stage=?, progress=0, worker_pid=?, worker_host=?
               WHERE id=? AND status='PENDING' AND cancel_requested=0""",
            (now, now, stage, os.getpid(), socket.gethostname(), audit_id),
        )
        return cur.rowcount == 1


def touch_audit(audit_id, stage=None, progress=None, pages_done=None,
                pages_total=None, warning=None, allowlisted_count=None):
    """
    Latido de una auditoria: registra ultima actividad, etapa y progreso.
    Devuelve (sigue_running, cancelacion_solicitada). Si sigue_running es False
    la auditoria ya fue cerrada por otro actor (p. ej. el vigilante): el worker
    debe detenerse sin sobrescribir ese estado.
    """
    now = _now_iso()
    sets, params = ["last_activity_at=?"], [now]
    if stage is not None:
        sets.append("current_stage=?"); params.append(stage)
    if progress is not None:
        sets.append("progress=?"); params.append(max(0, min(100, int(progress))))
    if pages_done is not None:
        sets.append("pages_done=?"); params.append(int(pages_done))
    if pages_total is not None:
        sets.append("pages_total=?"); params.append(int(pages_total))
    if allowlisted_count is not None:
        sets.append("allowlisted_count=?"); params.append(int(allowlisted_count))
    with get_conn() as conn:
        if warning:
            row = conn.execute("SELECT warnings FROM audits WHERE id=?", (audit_id,)).fetchone()
            prev = (row["warnings"] if row and row["warnings"] else "")
            if warning not in prev:
                merged = (prev + "\n" + warning).strip()[-MAX_WARNINGS_CHARS:]
                sets.append("warnings=?"); params.append(merged)
        cur = conn.execute(
            f"UPDATE audits SET {', '.join(sets)} WHERE id=? AND status='RUNNING'",
            params + [audit_id],
        )
        if cur.rowcount == 0:
            return (False, False)
        row = conn.execute(
            "SELECT cancel_requested, cycle_log_id FROM audits WHERE id=?", (audit_id,)
        ).fetchone()
        if row["cycle_log_id"] is not None:
            # El ciclo sigue vivo: sus auditorias en cola tambien muestran actividad reciente
            conn.execute(
                "UPDATE audits SET last_activity_at=? WHERE cycle_log_id=? AND status='PENDING'",
                (now, row["cycle_log_id"]),
            )
        return (True, bool(row["cancel_requested"]))


def finish_audit(
    audit_id, crawl_method, urls_analyzed, status, error_msg=None,
    severity_max=None, warnings=None, allowlisted_count=None,
):
    """
    Cierra una auditoria con su resultado final. Devuelve True si la cerro y
    False si ya estaba cerrada (p. ej. el vigilante la marco FAILED): nunca
    sobrescribe un estado final.
    status: cualquier estado final (tambien acepta los valores antiguos
            'ok'/'issues'/'error'). severity_max: severidad maxima de las
            amenazas relevantes (o None).
    """
    status = normalize_status(status)
    if status not in TERMINAL_STATUSES:
        raise ValueError(f"finish_audit requiere un estado final, recibido: {status!r}")
    sev = normalize_severity(severity_max) if severity_max else None
    sets = ["finished_at=?", "crawl_method=?", "urls_analyzed=?", "status=?",
            "severity_max=?", "error_msg=?", "last_activity_at=?"]
    params = [_now_iso(), crawl_method, urls_analyzed, status, sev, error_msg, _now_iso()]
    if status in (COMPLETED, COMPLETED_WITH_WARNINGS):
        sets += ["progress=100", "current_stage='Finalizada'"]
    if warnings is not None:
        sets.append("warnings=?"); params.append(str(warnings)[-MAX_WARNINGS_CHARS:] or None)
    if allowlisted_count is not None:
        sets.append("allowlisted_count=?"); params.append(int(allowlisted_count))
    with get_conn() as conn:
        cur = conn.execute(
            f"UPDATE audits SET {', '.join(sets)} WHERE id=? AND status IN ('PENDING','RUNNING')",
            params + [audit_id],
        )
        return cur.rowcount == 1


def get_audit(audit_id):
    with get_conn() as conn:
        return conn.execute("SELECT * FROM audits WHERE id=?", (audit_id,)).fetchone()


def get_active_audits(site_id=None):
    """Auditorias PENDING/RUNNING (de un sitio o de todos), mas recientes primero."""
    with get_conn() as conn:
        q = ("SELECT a.*, s.name AS site_name FROM audits a JOIN sites s ON s.id=a.site_id "
             "WHERE a.status IN ('PENDING','RUNNING')")
        params = []
        if site_id is not None:
            q += " AND a.site_id=?"; params.append(site_id)
        return conn.execute(q + " ORDER BY a.status DESC, a.started_at", params).fetchall()


def get_cycle_audits(cycle_log_id):
    with get_conn() as conn:
        return conn.execute(
            "SELECT a.*, s.name AS site_name FROM audits a JOIN sites s ON s.id=a.site_id "
            "WHERE a.cycle_log_id=? ORDER BY a.id", (cycle_log_id,)
        ).fetchall()


def get_recent_audits(limit=30):
    """Ultimas auditorias de todos los sitios (para el panel del Dashboard)."""
    with get_conn() as conn:
        return conn.execute(
            "SELECT a.*, s.name AS site_name FROM audits a JOIN sites s ON s.id=a.site_id "
            "ORDER BY a.id DESC LIMIT ?", (limit,)
        ).fetchall()


def request_cancel_audits(site_id=None, cycle_log_id=None, audit_id=None) -> int:
    """
    Solicita la cancelacion manual de auditorias activas (todas si no se filtra).
    Es cooperativa: el worker la detecta en su siguiente latido y cierra como
    CANCELLED. Si el worker ya no existe, el vigilante la cierra de inmediato.
    """
    q, params = "UPDATE audits SET cancel_requested=1 WHERE status IN ('PENDING','RUNNING')", []
    for col, val in (("site_id", site_id), ("cycle_log_id", cycle_log_id), ("id", audit_id)):
        if val is not None:
            q += f" AND {col}=?"; params.append(val)
    with get_conn() as conn:
        n = conn.execute(q, params).rowcount
    if n:
        reap_stale_audits()
    return n


def reap_stale_audits(stale_minutes=None, dead_grace_seconds=None, now=None) -> list:
    """
    Vigilante: cierra auditorias que quedaron PENDING/RUNNING pero ya no se
    ejecutan, para que el estado mostrado sea siempre el real.

      * cancelacion pedida y nadie la atiende           -> CANCELLED
      * el proceso (PID) ya no existe (+ gracia)        -> FAILED
      * sin latido por mas de `stale_minutes`           -> FAILED
    Tambien cierra cycle_logs 'running' sin auditorias activas.
    Devuelve [{id, site_id, status, reason}] de lo cerrado. Barata y segura de
    llamar con frecuencia y desde varios procesos (solo actualiza si sigue activa).
    """
    stale_s = (AUDIT_STALE_MINUTES if stale_minutes is None else stale_minutes) * 60
    grace = AUDIT_DEAD_GRACE_SECONDS if dead_grace_seconds is None else dead_grace_seconds
    now = now or datetime.now(timezone.utc)
    me = socket.gethostname()
    closed = []
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM audits WHERE status IN ('PENDING','RUNNING')"
        ).fetchall()
        for a in rows:
            last = _parse_ts(a["last_activity_at"]) or _parse_ts(a["started_at"]) or now
            idle = (now - last).total_seconds()
            alive = _pid_alive(a["worker_pid"]) if (not a["worker_host"] or a["worker_host"] == me) else None
            stage = a["current_stage"] or "desconocida"
            last_s = to_local_str(last.isoformat(), "%H:%M:%S")
            new_status = reason = None
            if a["cancel_requested"] and (alive is False or idle > grace):
                new_status, reason = CANCELLED, "Auditoría cancelada manualmente."
            elif alive is False and idle > grace:
                new_status = FAILED
                reason = (
                    "La auditoría nunca llegó a iniciar: el proceso que la creó dejó de responder."
                    if a["status"] == PENDING else
                    f"El proceso dejó de responder durante la etapa «{stage}» "
                    f"(el proceso ya no está activo; última actividad {last_s})."
                )
            elif idle > stale_s:
                new_status = FAILED
                reason = (f"El proceso dejó de responder durante la etapa «{stage}» "
                          f"(sin actividad desde {last_s}).")
            if new_status:
                cur = conn.execute(
                    """UPDATE audits SET status=?, error_msg=?, finished_at=?
                       WHERE id=? AND status IN ('PENDING','RUNNING')""",
                    (new_status, reason, now.isoformat(), a["id"]),
                )
                if cur.rowcount:
                    closed.append({"id": a["id"], "site_id": a["site_id"],
                                   "status": new_status, "reason": reason})
                    logger.warning("Vigilante: auditoria %d -> %s (%s)", a["id"], new_status, reason)

        # cycle_logs 'running' sin auditorias activas (el ciclo murio)
        for c in conn.execute("SELECT * FROM cycle_logs WHERE status='running'").fetchall():
            started = _parse_ts(c["started_at"]) or now
            if (now - started).total_seconds() < 300:
                continue
            active = conn.execute(
                "SELECT COUNT(*) FROM audits WHERE cycle_log_id=? AND status IN ('PENDING','RUNNING')",
                (c["id"],),
            ).fetchone()[0]
            if active:
                continue
            cnt = {r["status"]: r["n"] for r in conn.execute(
                "SELECT status, COUNT(*) n FROM audits WHERE cycle_log_id=? GROUP BY status", (c["id"],))}
            conn.execute(
                """UPDATE cycle_logs SET status='error', finished_at=?, error_msg=?,
                       sites_total=?, sites_ok=?, sites_error=? WHERE id=? AND status='running'""",
                (now.isoformat(),
                 "El ciclo terminó de forma inesperada (el proceso dejó de responder).",
                 sum(cnt.values()),
                 cnt.get(COMPLETED, 0) + cnt.get(COMPLETED_WITH_WARNINGS, 0),
                 cnt.get(FAILED, 0), c["id"]),
            )
    return closed


def get_last_audit(site_id):
    with get_conn() as conn:
        return conn.execute(
            "SELECT * FROM audits WHERE site_id=? ORDER BY started_at DESC LIMIT 1",
            (site_id,),
        ).fetchone()


def get_site_audits(site_id, limit=50):
    with get_conn() as conn:
        return conn.execute(
            "SELECT * FROM audits WHERE site_id=? ORDER BY started_at DESC LIMIT ?",
            (site_id, limit),
        ).fetchall()


# =============================================================
# CRUD — THREATS
# =============================================================


def _signals_json(signals):
    """Acepta lista de Signal/dict, un JSON ya serializado o None."""
    if signals is None or signals == "":
        return None
    if isinstance(signals, str):
        return signals
    import json

    return json.dumps(
        [s.to_dict() if hasattr(s, "to_dict") else dict(s) for s in signals],
        ensure_ascii=False,
    )


def add_threat(
    audit_id,
    site_id,
    threat_type,
    severity,
    description,
    code_snippet=None,
    url_found=None,
    is_new=True,
    ignored=False,
    resource_url=None,
    signals=None,
    allowlist_rule_id=None,
):
    """
    Inserta una amenaza detectada.

    severity:     CRITICAL/HIGH/MEDIUM/LOW/INFO (acepta los nombres antiguos).
    url_found:    PAGINA donde se encontro.
    resource_url: recurso sospechoso (src/href) — base de la lista permitida.
    signals:      señales que justifican la severidad (lista de Signal o JSON).
    ignored:      si True, la amenaza nace ya marcada como falso positivo
                  (coincide con una que el usuario omitio previamente — ver
                  orchestrator.py). Evita que reaparezca como alerta abierta.
    """
    sev = normalize_severity(severity)
    if sev is None:
        raise ValueError(f"Severidad invalida: {severity!r}")
    with get_conn() as conn:
        cur = conn.execute(
            """INSERT INTO threats
            (audit_id, site_id, threat_type, severity, description, code_snippet, url_found,
             is_new, ignored, ignored_at, resource_url, signals, allowlist_rule_id)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                audit_id,
                site_id,
                threat_type,
                sev,
                description,
                code_snippet,
                url_found,
                1 if is_new else 0,
                1 if ignored else 0,
                datetime.now(timezone.utc).isoformat() if ignored else None,
                resource_url,
                _signals_json(signals),
                allowlist_rule_id,
            ),
        )
        return cur.lastrowid


_SEVERITY_SORT_SQL = (
    "CASE t.severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2 "
    "WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 4 ELSE 5 END"
)


def get_open_threats(site_id=None, include_info=True):
    """
    Amenazas abiertas (no resueltas ni omitidas), de mayor a menor severidad.
    include_info=False excluye las INFO (informativas, no son alertas).
    """
    where = "t.resolved=0 AND t.ignored=0"
    params = []
    if site_id:
        where += " AND t.site_id=?"; params.append(site_id)
    if not include_info:
        where += " AND t.severity != 'INFO'"
    with get_conn() as conn:
        return conn.execute(
            f"""SELECT t.*, s.name as site_name FROM threats t
            JOIN sites s ON s.id=t.site_id
            WHERE {where}
            ORDER BY {_SEVERITY_SORT_SQL}, t.detected_at DESC""",
            params,
        ).fetchall()


def get_baseline_threats(site_id, cycle_started_at: str = None):
    """
    Devuelve todas las amenazas no resueltas detectadas ANTES del ciclo actual.
    Se usa para deduplicacion: si una amenaza ya existia antes del ciclo,
    no se considera nueva aunque se vuelva a detectar hoy.

    Args:
        site_id:          ID del sitio a consultar.
        cycle_started_at: ISO timestamp del inicio del ciclo actual.
                          Si es None, devuelve todas las no resueltas sin
                          filtro de fecha (comportamiento seguro).

    NOTA: SQLite almacena timestamps como 'YYYY-MM-DD HH:MM:SS' (sin T ni
    offset). Python isoformat() genera 'YYYY-MM-DDTHH:MM:SS+00:00'. La
    comparacion de strings falla porque ' ' (0x20) < 'T' (0x54), haciendo
    que cualquier timestamp SQLite parezca anterior a cualquier isoformat.
    Solucion: normalizar cycle_started_at a formato SQLite antes de comparar.
    
    NOTA 2: se incluye la columna 'ignored' en el resultado para que
    orchestrator.py pueda propagar el estado de "falso positivo omitido"
    a la nueva fila que se inserta en el ciclo actual (ver add_threat).
    Sin esto, una amenaza ya omitida por el usuario "reaparece" como
    alerta abierta en cada ejecucion nueva.
    """
    if cycle_started_at:
        # Normalizar ISO -> 'YYYY-MM-DD HH:MM:SS' para compatibilidad con SQLite
        try:
            from datetime import datetime, timezone

            dt = datetime.fromisoformat(cycle_started_at)
            # Convertir a UTC si tiene offset
            if dt.tzinfo is not None:
                dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
            cycle_started_at_norm = dt.strftime("%Y-%m-%d %H:%M:%S")
        except (ValueError, TypeError):
            cycle_started_at_norm = cycle_started_at  # fallback: usar como viene

    with get_conn() as conn:
        if cycle_started_at:
            return conn.execute(
                """SELECT threat_type, url_found, ignored, resource_url, description, code_snippet
                FROM threats
                WHERE site_id=? AND resolved=0
                AND detected_at < ?""",
                (site_id, cycle_started_at_norm),
            ).fetchall()
        return conn.execute(
            """SELECT threat_type, url_found, ignored, resource_url, description, code_snippet
               FROM threats
               WHERE site_id=? AND resolved=0""",
            (site_id,),
        ).fetchall()


def get_known_resource_hosts(site_id) -> set:
    """
    Hosts de los recursos externos que este sitio ya habia presentado en
    auditorias anteriores (cualquier estado). Sirve para la señal 'dominio
    nuevo': un recurso de un dominio que el sitio nunca habia cargado.
    """
    from url_utils import get_host

    with get_conn() as conn:
        rows = conn.execute(
            "SELECT DISTINCT resource_url FROM threats WHERE site_id=? AND resource_url IS NOT NULL",
            (site_id,),
        ).fetchall()
    return {h for h in (get_host(r[0]) for r in rows) if h}


def resolve_threat(threat_id):
    with get_conn() as conn:
        conn.execute(
            "UPDATE threats SET resolved=1, resolved_at=? WHERE id=?",
            (datetime.now(timezone.utc).isoformat(), threat_id),
        )
    logger.info("Amenaza resuelta: id=%d", threat_id)


def ignore_threat(threat_id):
    """
    Marca una amenaza como ignorada (falso positivo).
    No se considera 'resuelta' (el problema puede seguir) pero
    se excluye de las alertas activas y no vuelve a generar notificaciones.
    El bot tampoco la contará como 'nueva' en ciclos futuros
    porque la baseline la incluye como amenaza existente.
    """
    with get_conn() as conn:
        conn.execute(
            "UPDATE threats SET ignored=1, ignored_at=? WHERE id=?",
            (datetime.now(timezone.utc).isoformat(), threat_id),
        )
    logger.info("Amenaza ignorada (falso positivo): id=%d", threat_id)
    
    
def resolve_threats_bulk(threat_ids: list):
    """Marca varias amenazas como resueltas en una sola transaccion (accion en lote)."""
    ids = [i for i in (threat_ids or []) if i is not None]
    if not ids:
        return 0
    now = datetime.now(timezone.utc).isoformat()
    with get_conn() as conn:
        conn.executemany(
            "UPDATE threats SET resolved=1, resolved_at=? WHERE id=?",
            [(now, tid) for tid in ids],
        )
    logger.info("Amenazas resueltas en lote: %d", len(ids))
    return len(ids)


def ignore_threats_bulk(threat_ids: list):
    """Marca varias amenazas como falso positivo (omitidas) en una sola transaccion."""
    ids = [i for i in (threat_ids or []) if i is not None]
    if not ids:
        return 0
    now = datetime.now(timezone.utc).isoformat()
    with get_conn() as conn:
        conn.executemany(
            "UPDATE threats SET ignored=1, ignored_at=? WHERE id=?",
            [(now, tid) for tid in ids],
        )
    logger.info("Amenazas omitidas (falso positivo) en lote: %d", len(ids))
    return len(ids)


def get_all_threats(site_id=None, limit=200):
    with get_conn() as conn:
        if site_id:
            return conn.execute(
                """SELECT t.*, s.name as site_name FROM threats t
                   JOIN sites s ON s.id=t.site_id
                   WHERE t.site_id=? ORDER BY t.detected_at DESC LIMIT ?""",
                (site_id, limit),
            ).fetchall()
        return conn.execute(
            """SELECT t.*, s.name as site_name FROM threats t
            JOIN sites s ON s.id=t.site_id
            ORDER BY t.detected_at DESC LIMIT ?""",
            (limit,),
        ).fetchall()


# =============================================================
# CRUD — LISTA PERMITIDA (exclusiones)
# =============================================================


def get_allowlist_rules(site_id=None, scope=None, include_inactive=True):
    """
    Reglas con el nombre de su campaña. site_id filtra las reglas de ESA
    campaña (no incluye las globales; usa scope/get_effective_allowlist).
    """
    q = ("SELECT r.*, s.name AS site_name FROM allowlist_rules r "
         "LEFT JOIN sites s ON s.id=r.site_id WHERE 1=1")
    params = []
    if scope:
        q += " AND r.scope=?"; params.append(scope)
    if site_id is not None:
        q += " AND r.site_id=?"; params.append(site_id)
    if not include_inactive:
        q += " AND r.active=1"
    with get_conn() as conn:
        return conn.execute(q + " ORDER BY r.scope, s.name, r.pattern", params).fetchall()


def get_allowlist_rule(rule_id):
    with get_conn() as conn:
        return conn.execute("SELECT * FROM allowlist_rules WHERE id=?", (rule_id,)).fetchone()


def get_effective_allowlist(site_id) -> list:
    """Reglas ACTIVAS que aplican a un sitio: las globales + las de esa campaña."""
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT * FROM allowlist_rules WHERE active=1 AND (scope='global' OR site_id=?)",
            (site_id,),
        ).fetchall()
    return [dict(r) for r in rows]


def add_allowlist_rule(scope, pattern, match_type="url", site_id=None,
                       threat_type=None, reason="", created_by="manual",
                       source_threat_id=None) -> int:
    """Crea una regla (validada). ValueError con mensaje claro si es invalida o duplicada."""
    from allowlist import validate_rule

    pattern, match_type, site_id = validate_rule(scope, pattern, match_type, site_id)
    now = _now_iso()
    try:
        with get_conn() as conn:
            cur = conn.execute(
                """INSERT INTO allowlist_rules (scope, site_id, match_type, pattern, threat_type,
                       reason, active, created_at, updated_at, created_by, source_threat_id)
                   VALUES (?,?,?,?,?,?,1,?,?,?,?)""",
                (scope, site_id, match_type, pattern, threat_type or None,
                 (reason or "").strip() or None, now, now, created_by, source_threat_id),
            )
            return cur.lastrowid
    except sqlite3.IntegrityError:
        raise ValueError("Ya existe una exclusión igual (mismo alcance, campaña, tipo y patrón).")


def update_allowlist_rule(rule_id, apply_to_open=True, **fields) -> bool:
    """
    Edita una regla (scope, site_id, match_type, pattern, threat_type, reason).
    Libera las amenazas que habia permitido y vuelve a aplicar la regla editada.
    """
    from allowlist import validate_rule

    cur_rule = get_allowlist_rule(rule_id)
    if not cur_rule:
        return False
    merged = dict(cur_rule)
    merged.update({k: v for k, v in fields.items()
                   if k in ("scope", "site_id", "match_type", "pattern", "threat_type", "reason")})
    pattern, match_type, site_id = validate_rule(
        merged["scope"], merged["pattern"], merged["match_type"], merged.get("site_id"))
    try:
        with get_conn() as conn:
            conn.execute(
                """UPDATE allowlist_rules SET scope=?, site_id=?, match_type=?, pattern=?,
                       threat_type=?, reason=?, updated_at=? WHERE id=?""",
                (merged["scope"], site_id, match_type, pattern, merged.get("threat_type") or None,
                 (merged.get("reason") or "").strip() or None, _now_iso(), rule_id),
            )
    except sqlite3.IntegrityError:
        raise ValueError("Ya existe una exclusión igual (mismo alcance, campaña, tipo y patrón).")
    release_rule_threats(rule_id)
    if apply_to_open and cur_rule["active"]:
        apply_rule_to_open_threats(rule_id)
    return True


def set_allowlist_rule_active(rule_id, active: bool, apply_to_open=True) -> bool:
    """Activa/desactiva. Al desactivar, las amenazas que permitia vuelven a ser alertas."""
    with get_conn() as conn:
        n = conn.execute(
            "UPDATE allowlist_rules SET active=?, updated_at=? WHERE id=?",
            (1 if active else 0, _now_iso(), rule_id),
        ).rowcount
    if not n:
        return False
    if active:
        if apply_to_open:
            apply_rule_to_open_threats(rule_id)
    else:
        release_rule_threats(rule_id)
    return True


def delete_allowlist_rule(rule_id) -> bool:
    """Elimina la regla; las amenazas que permitia vuelven a ser alertas."""
    release_rule_threats(rule_id)
    with get_conn() as conn:
        return conn.execute("DELETE FROM allowlist_rules WHERE id=?", (rule_id,)).rowcount > 0


def release_rule_threats(rule_id) -> int:
    """Devuelve a 'abiertas' las amenazas que esta regla habia dejado como permitidas."""
    with get_conn() as conn:
        return conn.execute(
            """UPDATE threats SET ignored=0, ignored_at=NULL, allowlist_rule_id=NULL
               WHERE allowlist_rule_id=? AND resolved=0""",
            (rule_id,),
        ).rowcount


def apply_rule_to_open_threats(rule_id) -> int:
    """
    Marca como permitidas (ignored=1, allowlist_rule_id=rule) las amenazas
    ABIERTAS que ya coinciden con la regla, para que dejen de mostrarse sin
    esperar a la siguiente auditoria. Devuelve cuantas.
    """
    from allowlist import rule_matches, extract_resource_url

    rule = get_allowlist_rule(rule_id)
    if not rule or not rule["active"]:
        return 0
    q = ("SELECT id, site_id, threat_type, resource_url, description, code_snippet, url_found "
         "FROM threats WHERE resolved=0 AND ignored=0")
    params = []
    if rule["scope"] == "site":
        q += " AND site_id=?"; params.append(rule["site_id"])
    if rule["threat_type"]:
        q += " AND threat_type=?"; params.append(rule["threat_type"])
    now = _now_iso()
    n = 0
    with get_conn() as conn:
        for t in conn.execute(q, params).fetchall():
            res = t["resource_url"] or extract_resource_url(
                t["threat_type"], t["description"], t["code_snippet"], t["url_found"])
            if res and rule_matches(rule, res, t["threat_type"], t["site_id"]):
                conn.execute(
                    "UPDATE threats SET ignored=1, ignored_at=?, allowlist_rule_id=? WHERE id=?",
                    (now, rule_id, t["id"]),
                )
                n += 1
    if n:
        logger.info("Regla %d aplicada a %d amenazas abiertas", rule_id, n)
    return n


def record_allowlist_hits(hits: dict):
    """Suma aciertos por regla ({rule_id: n}) y registra la ultima vez que coincidio."""
    if not hits:
        return
    now = _now_iso()
    with get_conn() as conn:
        conn.executemany(
            "UPDATE allowlist_rules SET hit_count = hit_count + ?, last_hit_at=? WHERE id=?",
            [(n, now, rid) for rid, n in hits.items()],
        )


# =============================================================
# CRUD — UPTIME
# =============================================================


def add_uptime(site_id, is_up, status_code=None, response_time_ms=None, error_msg=None):
    with get_conn() as conn:
        conn.execute(
            """INSERT INTO uptime
            (site_id, is_up, status_code, response_time_ms, error_msg)
            VALUES (?,?,?,?,?)""",
            (site_id, 1 if is_up else 0, status_code, response_time_ms, error_msg),
        )


def get_uptime_stats(site_id, days=30):
    """Retorna porcentaje de uptime en los últimos N días (0-100 o None)."""
    with get_conn() as conn:
        row = conn.execute(
            """SELECT COUNT(*) as total, SUM(is_up) as up_count
            FROM uptime
            WHERE site_id=? AND checked_at >= datetime('now', ? || ' days')""",
            (site_id, f"-{days}"),
        ).fetchone()
    if not row or not row["total"]:
        return None
    return round((row["up_count"] / row["total"]) * 100, 1)


def is_site_currently_up(site_id):
    with get_conn() as conn:
        # ORDER BY id DESC como desempate: cuando varios registros tienen el mismo
        # checked_at (resolucion de 1 segundo), garantiza devolver el ultimo insertado.
        row = conn.execute(
            "SELECT is_up FROM uptime WHERE site_id=? ORDER BY checked_at DESC, id DESC LIMIT 1",
            (site_id,),
        ).fetchone()
    return bool(row["is_up"]) if row else None


def get_uptime_history(site_id, limit=100):
    with get_conn() as conn:
        return conn.execute(
            "SELECT * FROM uptime WHERE site_id=? ORDER BY checked_at DESC LIMIT ?",
            (site_id, limit),
        ).fetchall()


# =============================================================
# CRUD — SPAM DOMAINS
# =============================================================


def get_spam_domains() -> list:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT domain FROM spam_domains ORDER BY domain"
        ).fetchall()
    return [r["domain"] for r in rows]


def add_spam_domain(domain: str):
    with get_conn() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO spam_domains (domain) VALUES (?)",
            (domain.lower().strip(),),
        )


def delete_spam_domain(domain: str):
    with get_conn() as conn:
        conn.execute(
            "DELETE FROM spam_domains WHERE domain=?", (domain.lower().strip(),)
        )


# =============================================================
# CRUD — CYCLE LOGS
# =============================================================


def start_cycle_log():
    with get_conn() as conn:
        cur = conn.execute(
            "INSERT INTO cycle_logs (started_at) VALUES (?)",
            (datetime.now(timezone.utc).isoformat(),),
        )
        return cur.lastrowid


def finish_cycle_log(
    log_id,
    status,
    sites_total=0,
    sites_ok=0,
    sites_issues=0,
    sites_down=0,
    sites_error=0,
    error_msg=None,
):
    with get_conn() as conn:
        conn.execute(
            """UPDATE cycle_logs
            SET finished_at=?, status=?, sites_total=?, sites_ok=?, sites_issues=?, sites_down=?, sites_error=?, error_msg=?
            WHERE id=?""",
            (
                datetime.now(timezone.utc).isoformat(),
                status,
                sites_total,
                sites_ok,
                sites_issues,
                sites_down,
                sites_error,
                error_msg,
                log_id,
            ),
        )


def get_cycle_logs(limit=30):
    with get_conn() as conn:
        return conn.execute(
            "SELECT * FROM cycle_logs ORDER BY started_at DESC LIMIT ?", (limit,)
        ).fetchall()


# =============================================================
# CRUD — REPORTS
# =============================================================


def add_report(report_type, file_path, site_id=None, summary=None):
    with get_conn() as conn:
        cur = conn.execute(
            "INSERT INTO reports (report_type, site_id, file_path, summary) VALUES (?,?,?,?)",
            (report_type, site_id, file_path, summary),
        )
        return cur.lastrowid


def get_reports(report_type=None, site_id=None, limit=50):
    with get_conn() as conn:
        conditions, params = [], []
        if report_type:
            conditions.append("report_type=?")
            params.append(report_type)
        if site_id:
            conditions.append("site_id=?")
            params.append(site_id)
        where = ("WHERE " + " AND ".join(conditions)) if conditions else ""
        params.append(limit)
        return conn.execute(
            f"SELECT * FROM reports {where} ORDER BY generated_at DESC LIMIT ?", params
        ).fetchall()


# =============================================================
# UTILIDADES GENERALES
# =============================================================


def get_dashboard_summary() -> dict:
    """
    Metricas globales para la vista principal del dashboard.

    sites_down: cuenta sitios activos cuyo ultimo registro de uptime
    es is_up=0, O que nunca han tenido registro de uptime.
    Usa LEFT JOIN para ser robusto incluso antes de la primera auditoria.
    """
    with get_conn() as conn:
        total_sites = conn.execute(
            "SELECT COUNT(*) FROM sites WHERE active=1"
        ).fetchone()[0]
        # LEFT JOIN: incluye sitios sin ningun registro de uptime (nunca auditados)
        # Un sitio se considera caido si: nunca fue chequeado O su ultimo estado es is_up=0
        sites_down = conn.execute("""SELECT COUNT(*) FROM sites s
            LEFT JOIN (
                SELECT site_id, is_up
                FROM uptime
                WHERE (site_id, checked_at) IN (
                    SELECT site_id, MAX(checked_at) FROM uptime GROUP BY site_id
                )
            ) last_uptime ON s.id = last_uptime.site_id
            WHERE s.active=1
            AND (last_uptime.site_id IS NULL OR last_uptime.is_up=0)""").fetchone()[0]
        # NOTA: se excluyen las amenazas 'ignored=1' (falsos positivos omitidos
        # por el usuario) — de lo contrario reaparecen en los contadores
        # globales del Dashboard aunque ya no se muestren en Amenazas.
        open_critical = conn.execute(
            "SELECT COUNT(*) FROM threats WHERE resolved=0 AND ignored=0 AND severity='CRITICAL'"
        ).fetchone()[0]
        open_high = conn.execute(
            "SELECT COUNT(*) FROM threats WHERE resolved=0 AND ignored=0 AND severity='HIGH'"
        ).fetchone()[0]
        open_total = conn.execute(
            "SELECT COUNT(*) FROM threats WHERE resolved=0 AND ignored=0 AND severity!='INFO'"
        ).fetchone()[0]
        active_audits = conn.execute(
            "SELECT COUNT(*) FROM audits WHERE status IN ('PENDING','RUNNING')"
        ).fetchone()[0]
    return {
        "total_sites": total_sites,
        "sites_down": sites_down,
        "open_critical": open_critical,
        "open_high": open_high,
        "open_total": open_total,
        "active_audits": active_audits,
    }


# =============================================================
# ENTRYPOINT — inicializa la BD
# =============================================================

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s"
    )
    init_db()
    print(f"\n[OK] Base de datos lista en {DB_PATH}")
    summary = get_dashboard_summary()
    print(f"Sitios activos: {summary['total_sites']}")
    print(f"Amenazas abiertas: {summary['open_total']}")
    spam = get_spam_domains()
    print(f"Dominios spam: {len(spam)}")
