# =============================================================
# SAAF Pro — enhancements/history.py
# Historial de hallazgos y comparacion entre auditorias.
#
# Estados (punto 5 del documento):
#   NEW                    aparecio por primera vez
#   PERSISTENT             continua presente
#   RESOLVED               ya no aparece
#   REOPENED               habia desaparecido y volvio
#   PENDING_AUTHORIZATION  espera autorizacion para corregirse
#   REMEDIATED             el sistema aplico una correccion
#
# "Ya no aparece" solo cuenta como RESOLVED si se pudo VERIFICAR: la pagina
# donde estaba se descargo bien en esta auditoria (o ya no existe / se
# corrigio). Si la pagina no se pudo descargar, el hallazgo se deja como
# estaba (no verificado) para no declarar resuelto algo que simplemente no
# se pudo revisar.
# =============================================================

from database import get_conn

from . import store
from .items import norm_page

NEW = "NEW"
PERSISTENT = "PERSISTENT"
RESOLVED = "RESOLVED"
REOPENED = "REOPENED"
PENDING_AUTHORIZATION = "PENDING_AUTHORIZATION"
REMEDIATED = "REMEDIATED"

ALL_STATES = (NEW, PERSISTENT, RESOLVED, REOPENED, PENDING_AUTHORIZATION, REMEDIATED)
OPEN_STATES = (NEW, PERSISTENT, REOPENED, PENDING_AUTHORIZATION, REMEDIATED)

STATE_LABEL = {
    NEW: "Nuevo",
    PERSISTENT: "Persistente",
    RESOLVED: "Resuelto",
    REOPENED: "Reabierto",
    PENDING_AUTHORIZATION: "Pendiente de autorización",
    REMEDIATED: "Corregido por el sistema",
}
STATE_ICON = {
    NEW: "🆕", PERSISTENT: "♻️", RESOLVED: "✅", REOPENED: "🔁",
    PENDING_AUTHORIZATION: "⏳", REMEDIATED: "🛠️",
}


def previous_report(site_id: int, before_audit_id: int):
    """(audit_id, created_at) del reporte anterior del sitio, o None."""
    store.ensure_schema()
    with get_conn() as conn:
        row = conn.execute(
            "SELECT audit_id, created_at FROM enh_reports WHERE site_id=? AND audit_id<? ORDER BY audit_id DESC LIMIT 1",
            (site_id, before_audit_id),
        ).fetchone()
    return (row["audit_id"], row["created_at"]) if row else None


def apply_history(site_id: int, audit_id: int, items: list, fetched_ok: set, gone_pages: set,
                  complete: bool) -> dict:
    """
    Actualiza el estado acumulado con los elementos de ESTA auditoria y devuelve:
      {"resolved": [filas de estado que pasaron a RESOLVED],
       "unverified": n,
       "previous_audit_id": id | None}
    A cada item le anade: lifecycle (NEW|PERSISTENT|REOPENED), first_seen_at,
    times_seen y history_note.
    """
    store.ensure_schema()
    now = store.now_iso()
    prev = previous_report(site_id, audit_id)
    resolved, unverified = [], 0
    current = {}
    for it in items:
        current[it["fingerprint"]] = it  # un fingerprint -> un elemento por auditoria

    with get_conn() as conn:
        rows = {
            r["fingerprint"]: dict(r)
            for r in conn.execute("SELECT * FROM enh_finding_state WHERE site_id=?", (site_id,))
        }

        for fp, it in current.items():
            st = rows.get(fp)
            note = None
            if st is None:
                life = NEW
                conn.execute(
                    """INSERT INTO enh_finding_state (site_id, fingerprint, category, threat_type, page_url,
                           resource_url, status, first_audit_id, first_seen_at, last_audit_id, last_seen_at,
                           times_seen) VALUES (?,?,?,?,?,?,?,?,?,?,?,1)""",
                    (site_id, fp, it.get("category"), it.get("threat_type"), it.get("page_url"),
                     it.get("resource_url"), NEW, audit_id, now, audit_id, now),
                )
                it.update(first_seen_at=now, times_seen=1)
            else:
                if st["status"] == RESOLVED:
                    life, note = REOPENED, "había desaparecido y volvió a aparecer"
                else:
                    life = PERSISTENT
                    if st["status"] == REMEDIATED:
                        note = "la corrección aplicada anteriormente no eliminó el problema"
                conn.execute(
                    """UPDATE enh_finding_state SET category=?, status=?, last_audit_id=?, last_seen_at=?,
                           times_seen=times_seen+1, resolved_at=NULL, resolved_audit_id=NULL, note=?
                       WHERE site_id=? AND fingerprint=?""",
                    (it.get("category"), life, audit_id, now, note, site_id, fp),
                )
                it.update(first_seen_at=st["first_seen_at"], times_seen=(st["times_seen"] or 0) + 1)
            it["lifecycle"] = life
            it["status"] = life
            it["history_note"] = note
            it["remediation_attempts"] = (rows.get(fp) or {}).get("remediation_attempts", 0)

        # Los que estaban abiertos y ya no aparecen
        for fp, st in rows.items():
            if fp in current or st["status"] not in OPEN_STATES:
                continue
            page = norm_page(st.get("page_url"))
            verified = complete and (
                st["status"] == REMEDIATED
                or fp.startswith("link|")
                or page in fetched_ok
                or page in gone_pages
            )
            if verified:
                conn.execute(
                    """UPDATE enh_finding_state SET status=?, resolved_at=?, resolved_audit_id=?, note=?
                       WHERE site_id=? AND fingerprint=?""",
                    (RESOLVED, now, audit_id,
                     "verificado: ya no aparece tras la corrección" if st["status"] == REMEDIATED
                     else "ya no aparece en la auditoría", site_id, fp),
                )
                resolved.append({**st, "status": RESOLVED, "resolved_audit_id": audit_id,
                                 "was_remediated": st["status"] == REMEDIATED})
            else:
                unverified += 1

    return {"resolved": resolved, "unverified": unverified,
            "previous_audit_id": prev[0] if prev else None}


def set_state(site_id: int, fingerprint: str, status: str, note: str = None, attempt: bool = False):
    store.ensure_schema()
    with get_conn() as conn:
        conn.execute(
            f"""UPDATE enh_finding_state SET status=?, note=COALESCE(?, note)
                {', remediation_attempts=remediation_attempts+1' if attempt else ''}
                WHERE site_id=? AND fingerprint=?""",
            (status, note, site_id, fingerprint),
        )


def get_attempts(site_id: int, fingerprint: str) -> int:
    store.ensure_schema()
    with get_conn() as conn:
        r = conn.execute(
            "SELECT remediation_attempts FROM enh_finding_state WHERE site_id=? AND fingerprint=?",
            (site_id, fingerprint),
        ).fetchone()
    return r["remediation_attempts"] if r else 0


def state_counts(site_id: int) -> dict:
    store.ensure_schema()
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT status, COUNT(*) n FROM enh_finding_state WHERE site_id=? GROUP BY status", (site_id,)
        ).fetchall()
    return {r["status"]: r["n"] for r in rows}
