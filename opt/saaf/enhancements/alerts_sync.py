# =============================================================
# SAAF Pro — enhancements/alerts_sync.py
# Menos ruido en la pantalla ALERTAS original y en sus notificaciones.
#
# Usa el mecanismo que ya existe en el proyecto para los falsos positivos
# (threats.ignored = 1, igual que el boton "Omitir" de la pantalla Alertas):
#   * las alertas omitidas no salen en get_open_threats() -> desaparecen de
#     la pantalla Alertas y del calculo de severidad del sitio;
#   * la deduplicacion las conserva en la baseline, asi que en el siguiente
#     ciclo nacen ya omitidas y NO vuelven a notificar.
# No se toca ninguna otra columna ni ningun archivo original.
#
# Todo queda registrado en enh_muted_alerts con el motivo, y se puede
# DESHACER desde Auditoria IA -> Alertas omitidas (vuelve a ignored=0).
#
# Limite conocido: el correo/SMS de la auditoria EN CURSO lo envia el
# orquestador (paso 8) ANTES de que este paquete analice, asi que la primera
# notificacion de una amenaza nueva se manda igual. El efecto se ve en la
# pantalla desde ese momento y en las notificaciones de los ciclos siguientes.
#
# Reglas (deliberadamente conservadoras): ver puede_omitirse().
# =============================================================

from database import get_conn

from . import store
from .items import page_path, res_key
from .log import get_logger

log = get_logger()

# Modos del ajuste global "mute_alerts"
OFF = "off"              # no cambiar nada (valor por defecto)
LEGIT = "legit"          # solo recursos juzgados validos (IA o servicio declarado)
LEGIT_FP = "legit_fp"    # ademas, posibles falsos positivos / sin evidencia
MODES = (OFF, LEGIT, LEGIT_FP)

MODE_LABEL = {
    OFF: "No cambiar la pantalla Alertas (por defecto)",
    LEGIT: "Omitir los recursos que la auditoría IA considera válidos",
    LEGIT_FP: "Omitir también los posibles falsos positivos y lo que no tiene evidencia",
}

MUTED = "MUTED"
RESTORED = "RESTORED"

KIND_LABEL = {"legit": "Recurso válido", "false_positive": "Posible falso positivo"}


def mode_of(glob: dict) -> str:
    m = str((glob or {}).get("mute_alerts") or OFF)
    return m if m in MODES else OFF


def puede_omitirse(item: dict, glob: dict):
    """
    (kind, motivo) si esta alerta original puede omitirse, o None.

    Nunca se omite algo que:
      - no venga de una alerta original (sin threat_id);
      - sea CRITICAL;
      - tenga indicadores deterministas (terminos de spam, senales fuertes,
        dominio en lista de spam, huellas de codigo malicioso, idioma);
      - venga del motor de idiomas (es una pagina real en otro idioma).
    """
    mode = mode_of(glob)
    if mode == OFF or not item.get("threat_id"):
        return None
    if item.get("severity") == "CRITICAL":
        return None
    if item.get("corroborated") or item.get("has_indicator"):
        return None
    if item.get("source") == "language":
        return None

    if item.get("legit") and item.get("legit_by") in ("ia", "campaña"):
        quien = "la IA" if item.get("legit_by") == "ia" else "la campaña (servicio declarado)"
        motivo = item.get("legit_reason") or item.get("reason") or ""
        return "legit", f"{quien} lo considera un recurso válido" + (f": {motivo}" if motivo else "")

    if mode == LEGIT_FP:
        conf = int(item.get("confidence") or 0)
        minimo = int((glob or {}).get("min_auth_confidence") or 50)
        if conf < minimo:
            motivo = item.get("reason") or ""
            return "false_positive", (f"confianza {conf}% por debajo del mínimo ({minimo}%) y sin indicadores"
                                      + (f": {motivo}" if motivo else ""))
    return None


def _already_muted(conn, threat_id) -> bool:
    row = conn.execute("SELECT 1 FROM enh_muted_alerts WHERE threat_id=? AND status=?",
                       (threat_id, MUTED)).fetchone()
    return bool(row)


def _ya_omitida_por_el_original(conn, threat_id) -> bool:
    """
    True si la alerta YA estaba omitida sin que este paquete tuviera nada que ver:
    el boton «Omitir» de la pantalla Alertas, una regla de la lista de exclusiones,
    o la deduplicacion (nace omitida porque su gemela lo estaba).
    Nunca se toca: si la registraramos, «Restaurar» desharia una decision ajena.
    """
    row = conn.execute("SELECT ignored, allowlist_rule_id FROM threats WHERE id=?", (threat_id,)).fetchone()
    if row is None:
        return True  # la amenaza ya no existe
    return bool(row["ignored"]) or row["allowlist_rule_id"] is not None


def apply_to_alerts(site_id: int, audit_id: int, items: list, glob: dict) -> dict:
    """
    Omite en la tabla original las alertas que cumplan las reglas y lo registra.
    Devuelve {'muted': n, 'legit': n, 'false_positive': n}.
    """
    out = {"muted": 0, "legit": 0, "false_positive": 0}
    if mode_of(glob) == OFF:
        return out
    store.ensure_schema()
    from database import ignore_threat

    for it in items or []:
        d = puede_omitirse(it, glob)
        if not d:
            continue
        kind, motivo = d
        tid = it["threat_id"]
        try:
            with get_conn() as conn:
                if _already_muted(conn, tid) or _ya_omitida_por_el_original(conn, tid):
                    continue
                conn.execute(
                    """INSERT INTO enh_muted_alerts
                       (site_id, audit_id, threat_id, fingerprint, kind, reason, page_url, resource_url,
                        severity, confidence, status, created_at)
                       VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                    (site_id, audit_id, tid, it.get("fingerprint"), kind, motivo[:400],
                     it.get("page_url"), it.get("resource_url"), it.get("severity"),
                     int(it.get("confidence") or 0), MUTED, store.now_iso()))
            ignore_threat(tid)
            it["muted_in_alerts"] = kind
            out["muted"] += 1
            out[kind] += 1
            log.info("Alerta original omitida (%s): #%s %s — %s", kind, tid,
                     page_path(it.get("page_url")), motivo[:120])
        except Exception:
            log.warning("No se pudo omitir la alerta original #%s", tid, exc_info=True)
    return out


def sweep_open_alerts(site_id: int = None, glob: dict = None, limit: int = 5000) -> dict:
    """
    Revisa las alertas que YA estaban abiertas (de auditorias anteriores) y omite
    las que cumplen las mismas reglas. Es una accion MANUAL desde la pantalla:
    el analisis de cada auditoria solo ve sus propios hallazgos, asi que esto
    sirve para limpiar lo acumulado. Igual de reversible que el resto.
    """
    import json as _json

    from database import get_open_threats, get_site, get_spam_domains

    from . import config as cfgmod
    from . import items as itm

    glob = glob or cfgmod.get_global()
    out = {"revisadas": 0, "muted": 0, "legit": 0, "false_positive": 0}
    if mode_of(glob) == OFF:
        return out
    store.ensure_schema()
    try:
        spam_domains = set(get_spam_domains() or [])
    except Exception:
        spam_domains = set()
    niches, items_by_site = {}, {}
    for r in get_open_threats(site_id)[:limit]:
        sid = r["site_id"]
        if sid not in niches:
            try:
                s = get_site(sid)
                niches[sid] = (s["niche"] if s and "niche" in s.keys() else "general") or "general"
            except Exception:
                niches[sid] = "general"
        it = {"source": "threat", "threat_id": r["id"], "threat_type": r["threat_type"],
              "severity": r["severity"], "page_url": r["url_found"], "resource_url": r["resource_url"] or "",
              "description": r["description"] or "", "snippet": r["code_snippet"] or "",
              "signals": _json.loads(r["signals"]) if r["signals"] else [],
              "hidden": r["threat_type"] in ("hidden_iframe", "hidden_spam_link")}
        try:
            itm.classify_item(it, niches[sid], spam_domains)
        except Exception:
            log.warning("No se pudo clasificar la alerta #%s", r["id"], exc_info=True)
            continue
        it["fingerprint"] = itm.fingerprint(it)
        items_by_site.setdefault(sid, []).append(it)
        out["revisadas"] += 1
    for sid, its in items_by_site.items():
        res = apply_to_alerts(sid, None, its, glob)
        for k in ("muted", "legit", "false_positive"):
            out[k] += res[k]
    log.info("Revisión de alertas acumuladas: %d revisadas, %d omitidas", out["revisadas"], out["muted"])
    return out


def list_muted(site_id: int = None, status: str = MUTED, limit: int = 200) -> list:
    """Alertas omitidas por el paquete, con el nombre de la campaña."""
    store.ensure_schema()
    where, params = ["m.status=?"], [status]
    if site_id:
        where.append("m.site_id=?")
        params.append(site_id)
    params.append(limit)
    with get_conn() as conn:
        rows = conn.execute(
            f"""SELECT m.*, s.name AS site_name,
                       t.severity AS threat_severity, t.description AS threat_description, t.ignored AS threat_ignored
                  FROM enh_muted_alerts m
                  JOIN sites s ON s.id = m.site_id
                  LEFT JOIN threats t ON t.id = m.threat_id
                 WHERE {' AND '.join(where)}
                 ORDER BY m.id DESC LIMIT ?""", params).fetchall()
    return [dict(r) for r in rows]


def count_muted(site_id: int = None) -> int:
    store.ensure_schema()
    with get_conn() as conn:
        if site_id:
            return conn.execute("SELECT COUNT(*) FROM enh_muted_alerts WHERE status=? AND site_id=?",
                                (MUTED, site_id)).fetchone()[0]
        return conn.execute("SELECT COUNT(*) FROM enh_muted_alerts WHERE status=?", (MUTED,)).fetchone()[0]


def restore(mute_id: int, user: str = "dashboard") -> dict:
    """Devuelve la alerta a la pantalla Alertas (ignored=0), como el original."""
    store.ensure_schema()
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM enh_muted_alerts WHERE id=?", (mute_id,)).fetchone()
        if not row:
            return {"ok": False, "message": "No se encontró el registro."}
        if row["status"] != MUTED:
            return {"ok": False, "message": "Ya se había restaurado."}
        conn.execute("UPDATE threats SET ignored=0, ignored_at=NULL WHERE id=?", (row["threat_id"],))
        conn.execute("UPDATE enh_muted_alerts SET status=?, restored_at=?, restored_by=? WHERE id=?",
                     (RESTORED, store.now_iso(), user, mute_id))
    log.info("Alerta original restaurada: #%s (por %s)", row["threat_id"], user)
    return {"ok": True, "message": "La alerta vuelve a aparecer en la pantalla Alertas."}


def restore_all(site_id: int = None, user: str = "dashboard") -> int:
    """Deshace TODO lo omitido por el paquete (deja el proyecto como el original)."""
    n = 0
    for row in list_muted(site_id=site_id, limit=5000):
        if restore(row["id"], user=user)["ok"]:
            n += 1
    log.info("Alertas originales restauradas en lote: %d", n)
    return n


def describe(row: dict) -> str:
    """Una línea legible para la pantalla."""
    where = page_path(row.get("page_url")) or "(sitio)"
    res = res_key(row["resource_url"]) if row.get("resource_url") else ""
    return f"{where}{f' → {res}' if res else ''}"
