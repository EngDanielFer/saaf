# =============================================================
# SAAF Pro — enhancements/store.py
# Tablas PROPIAS de las mejoras (prefijo enh_). No se toca database.py ni
# su esquema: las tablas se crean con CREATE TABLE IF NOT EXISTS la primera
# vez que se usan, sobre la misma BD y con la misma conexion (get_conn).
#
# Nota: no hay FK hacia audits/threats a proposito (la migracion v2 de
# database.py reconstruye esas tablas); si hay FK hacia sites (CASCADE) para
# que al borrar una campania se limpie todo lo suyo.
# =============================================================

import json
import threading
from datetime import datetime, timezone

from database import get_conn, DB_PATH

SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS enh_site_config (
    site_id INTEGER PRIMARY KEY REFERENCES sites(id) ON DELETE CASCADE,
    config TEXT NOT NULL,
    updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS enh_kv (
    key TEXT PRIMARY KEY,
    value TEXT,
    updated_at TEXT NOT NULL
);

-- Un reporte por auditoria (resumen numerico + analisis + agrupacion)
CREATE TABLE IF NOT EXISTS enh_reports (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    audit_id INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    ai_used INTEGER NOT NULL DEFAULT 0,
    ai_error TEXT,
    report TEXT NOT NULL,
    dispatch TEXT
);

-- Hallazgos de cada auditoria (una fila por alerta/elemento)
CREATE TABLE IF NOT EXISTS enh_findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    audit_id INTEGER NOT NULL,
    fingerprint TEXT NOT NULL,
    source TEXT NOT NULL,
    threat_id INTEGER,
    threat_type TEXT,
    severity TEXT,
    category TEXT,
    confidence INTEGER,
    page_url TEXT,
    resource_url TEXT,
    description TEXT,
    snippet TEXT,
    lifecycle TEXT,
    status TEXT,
    legit INTEGER NOT NULL DEFAULT 0,
    reason TEXT,
    extra TEXT,
    created_at TEXT NOT NULL
);

-- Estado acumulado de cada hallazgo (historial entre auditorias)
CREATE TABLE IF NOT EXISTS enh_finding_state (
    site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    fingerprint TEXT NOT NULL,
    category TEXT,
    threat_type TEXT,
    page_url TEXT,
    resource_url TEXT,
    status TEXT NOT NULL,
    first_audit_id INTEGER,
    first_seen_at TEXT,
    last_audit_id INTEGER,
    last_seen_at TEXT,
    resolved_at TEXT,
    resolved_audit_id INTEGER,
    times_seen INTEGER NOT NULL DEFAULT 1,
    remediation_attempts INTEGER NOT NULL DEFAULT 0,
    note TEXT,
    PRIMARY KEY (site_id, fingerprint)
);

-- Recursos externos analizados (los legitimos NO son alertas)
CREATE TABLE IF NOT EXISTS enh_resources (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    audit_id INTEGER NOT NULL,
    host TEXT NOT NULL,
    sample_url TEXT,
    links_count INTEGER DEFAULT 0,
    pages_count INTEGER DEFAULT 0,
    sample_pages TEXT,
    anchors TEXT,
    verdict TEXT NOT NULL,
    confidence INTEGER,
    reason TEXT,
    source TEXT,
    created_at TEXT NOT NULL
);

-- Bitacora de correcciones: que se intento, que se corrigio, que fallo y
-- que quedo pendiente de autorizacion.
CREATE TABLE IF NOT EXISTS enh_remediations (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    site_id INTEGER NOT NULL REFERENCES sites(id) ON DELETE CASCADE,
    audit_id INTEGER,
    fingerprint TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    action TEXT NOT NULL,
    target_url TEXT,
    resource_url TEXT,
    category TEXT,
    wp_rest_base TEXT,
    wp_id INTEGER,
    status TEXT NOT NULL,
    mode TEXT,
    confidence INTEGER,
    threshold INTEGER,
    message TEXT,
    backup TEXT,
    prev_status TEXT,
    decided_by TEXT,
    decided_at TEXT
);
"""

INDEXES_SQL = """
CREATE UNIQUE INDEX IF NOT EXISTS uq_enh_reports_audit ON enh_reports(audit_id);
CREATE INDEX IF NOT EXISTS idx_enh_reports_site ON enh_reports(site_id, id DESC);
CREATE INDEX IF NOT EXISTS idx_enh_findings_audit ON enh_findings(site_id, audit_id);
CREATE INDEX IF NOT EXISTS idx_enh_findings_fp ON enh_findings(site_id, fingerprint);
CREATE INDEX IF NOT EXISTS idx_enh_state_status ON enh_finding_state(site_id, status);
CREATE INDEX IF NOT EXISTS idx_enh_resources_audit ON enh_resources(site_id, audit_id);
CREATE INDEX IF NOT EXISTS idx_enh_rem_status ON enh_remediations(status, site_id);
CREATE INDEX IF NOT EXISTS idx_enh_rem_fp ON enh_remediations(site_id, fingerprint);
"""

_ready = set()
_lock = threading.Lock()


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def ensure_schema():
    """Crea las tablas si no existen (barato: una vez por proceso y BD)."""
    key = str(DB_PATH)
    if key in _ready:
        return
    with _lock:
        if key in _ready:
            return
        with get_conn() as conn:
            conn.executescript(SCHEMA_SQL)
            conn.executescript(INDEXES_SQL)
        _ready.add(key)


def reset_cache():
    """Para pruebas: fuerza a recrear tablas al cambiar de BD."""
    _ready.clear()


# ------------------------------------------------------------------
# kv simple
# ------------------------------------------------------------------
def kv_get(key: str, default=None):
    ensure_schema()
    with get_conn() as conn:
        row = conn.execute("SELECT value FROM enh_kv WHERE key=?", (key,)).fetchone()
    return row["value"] if row else default


def kv_set(key: str, value: str):
    ensure_schema()
    with get_conn() as conn:
        conn.execute(
            """INSERT INTO enh_kv (key, value, updated_at) VALUES (?,?,?)
               ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at""",
            (key, value, now_iso()),
        )


def kv_delete(key: str):
    ensure_schema()
    with get_conn() as conn:
        conn.execute("DELETE FROM enh_kv WHERE key=?", (key,))


def jdump(obj) -> str:
    return json.dumps(obj, ensure_ascii=False, default=str)


def jload(raw, default=None):
    if raw in (None, ""):
        return default
    try:
        return json.loads(raw)
    except (ValueError, TypeError):
        return default
