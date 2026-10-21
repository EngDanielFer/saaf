# =============================================================
# SAAF Pro — enhancements/remediation.py
# Decide y ejecuta correcciones en WordPress.
#
# La CONFIANZA de la clasificacion y el PERMISO para actuar son cosas
# distintas (punto 3 del documento). Una correccion se aplica sola SOLO si
# se cumplen TODAS estas condiciones:
#   1. la campania tiene WordPress configurado y "corregir automaticamente" activo;
#   2. la accion esta entre las permitidas para correccion automatica;
#   3. la accion NO es sensible (retirar scripts siempre pide autorizacion);
#   4. confianza >= umbral configurado (por defecto 70%);
#   5. el hallazgo esta corroborado por indicadores deterministicos
#      (la IA sola no basta);
#   6. no se supero el tope de acciones automaticas por auditoria;
#   7. el elemento no se intento corregir ya 2 veces sin exito.
# Si no, y la confianza es al menos la minima (50%), queda
# PENDING_AUTHORIZATION para que una persona lo autorice o rechace.
# Todo se registra en enh_remediations: lo intentado, lo corregido, lo que
# fallo y lo pendiente.
# =============================================================

from database import get_conn

from . import config as cfgmod
from . import history, store
from . import taxonomy as tx
from .items import norm_page, res_key
from .log import get_logger
from .wordpress import (
    WPClient, WPError, is_front_page, strip_code, strip_links, MAX_CONTENT_BYTES,
)

log = get_logger()

# Estados de una correccion
APPLIED = "APPLIED"
FAILED = "FAILED"
PENDING = "PENDING_AUTHORIZATION"
REJECTED = "REJECTED"
DRY_RUN = "DRY_RUN"
EXPIRED = "EXPIRED"
REVERTED = "REVERTED"

STATUS_LABEL = {
    APPLIED: "Aplicada", FAILED: "Falló", PENDING: "Pendiente de autorización",
    REJECTED: "Rechazada", DRY_RUN: "Simulada (sin cambios)", EXPIRED: "Ya no aplica",
    REVERTED: "Revertida",
}

AUTO_CATEGORIES = tx.SPAM_CATEGORIES | {"language", "injected_links"}
MAX_ATTEMPTS = 2
MAX_LINKS_PER_EDIT = 20


# ------------------------------------------------------------------
# Que accion corresponde a cada elemento
# ------------------------------------------------------------------
def action_for(item: dict):
    t = item.get("threat_type")
    if item.get("source") == "language":
        return "trash_post"
    if t == "casino_pharma_adult":
        return "trash_post"
    if t == "hidden_spam_link":
        return "remove_link"
    if t in ("external_script", "hidden_iframe"):
        return "remove_code"
    return None  # obfuscated_js, enlaces por revisar, etc.: intervencion manual


def get_client(site_id: int, cfg: dict = None):
    cfg = cfg or cfgmod.get_site_config(site_id)
    w = cfg["wp"]
    pw = cfgmod.get_wp_password(site_id)
    if not (w["enabled"] and w["base_url"] and w["username"] and pw):
        return None
    try:
        return WPClient(w["base_url"], w["username"], pw)
    except WPError:
        return None


# ------------------------------------------------------------------
# Decision
# ------------------------------------------------------------------
def decide(item: dict, cfg: dict, glob: dict, threshold: int, auto_used: int) -> dict:
    """{'action','mode': auto|authorization|none,'reason'}"""
    action = action_for(item)
    if not action:
        return {"action": None, "mode": "none", "reason": "sin acción automática disponible"}
    w = cfg["wp"]
    conf = int(item.get("confidence") or 0)
    meta = cfgmod.ACTIONS[action]
    if conf < glob["min_auth_confidence"]:
        return {"action": action, "mode": "none",
                "reason": f"confianza {conf}% por debajo del mínimo para proponer una acción ({glob['min_auth_confidence']}%)"}
    if item.get("category") not in AUTO_CATEGORIES and not meta["sensitive"]:
        return {"action": action, "mode": "authorization", "reason": "categoría no elegible para corrección automática"}

    why = []
    if not w["auto_fix"]:
        why.append("la corrección automática está desactivada en esta campaña")
    if action not in w["allowed_actions"]:
        why.append("la acción no está permitida para corrección automática")
    if meta["sensitive"]:
        why.append("acción sensible: requiere autorización siempre")
    if conf < threshold:
        why.append(f"confianza {conf}% < umbral {threshold}%")
    if not item.get("corroborated"):
        why.append("sin indicadores deterministas que respalden a la IA")
    if int(item.get("remediation_attempts") or 0) >= MAX_ATTEMPTS:
        why.append("ya se intentó corregir sin éxito")
    if auto_used >= glob["max_auto_actions"]:
        why.append(f"se alcanzó el tope de {glob['max_auto_actions']} acciones automáticas por auditoría")
    if why:
        return {"action": action, "mode": "authorization", "reason": "; ".join(why)}
    return {"action": action, "mode": "auto", "reason": f"confianza {conf}% ≥ umbral {threshold}%"}


# ------------------------------------------------------------------
# Ejecucion de una accion sobre WordPress
# ------------------------------------------------------------------
def run_action(client: WPClient, site_url: str, action: str, target_url: str,
               resource_url: str = "", hint_id: int = None, dry_run: bool = False) -> dict:
    """Devuelve {'status','message','wp_id','rest_base','backup','prev_status'}."""
    out = {"status": FAILED, "message": "", "wp_id": None, "rest_base": None,
           "backup": None, "prev_status": None}
    try:
        if is_front_page(site_url, target_url):
            out["message"] = "La portada está protegida: no se modifica automáticamente."
            return out
        post = client.resolve(target_url, hint_id)
        if not post:
            out["message"] = ("No se encontró contenido de WordPress cuyo enlace coincida exactamente con "
                              "esta URL (¿no es una página/entrada, o está en el tema/plugin?). Requiere intervención manual.")
            return out
        out.update(wp_id=post["id"], rest_base=post["rest_base"], prev_status=post.get("status"))
        if post.get("status") == "trash":
            # No la envio el sistema: se informa pero no se ofrece revertir (ver revert()).
            out.update(status=APPLIED, message="Ya estaba en la papelera.", prev_status="trash")
            return out

        if action == "trash_post":
            if dry_run:
                out.update(status=DRY_RUN, message=f"Simulación: se enviaría a la papelera ({post['rest_base']} #{post['id']}).")
                return out
            client.trash(post["rest_base"], post["id"])
            out.update(status=APPLIED, message=f"Enviado a la papelera ({post['rest_base']} #{post['id']}). Reversible desde WordPress.")
            return out

        if action in ("remove_link", "remove_code"):
            if not resource_url:
                out["message"] = "El hallazgo no tiene un recurso (URL) identificable para retirar."
                return out
            raw = client.get_content(post["rest_base"], post["id"])
            if len(raw.encode("utf-8", "ignore")) > MAX_CONTENT_BYTES:
                out["message"] = "El contenido es demasiado grande para editarlo automáticamente."
                return out
            new, n = (strip_links if action == "remove_link" else strip_code)(raw, resource_url)
            if n == 0:
                out["message"] = ("No se encontró el elemento en el contenido editable de la página "
                                  "(probablemente lo carga el tema, un widget o un plugin). Requiere intervención manual.")
                return out
            if n > MAX_LINKS_PER_EDIT or len(new) >= len(raw):
                out["message"] = f"Cambio descartado por seguridad ({n} elementos a retirar)."
                return out
            out["backup"] = raw
            if dry_run:
                out.update(status=DRY_RUN, message=f"Simulación: se retirarían {n} elemento(s) del contenido ({post['rest_base']} #{post['id']}).")
                out["backup"] = None
                return out
            client.set_content(post["rest_base"], post["id"], new)
            check = client.get_content(post["rest_base"], post["id"])
            left = (strip_links if action == "remove_link" else strip_code)(check, resource_url)[1]
            if left:
                client.set_content(post["rest_base"], post["id"], raw)  # deshacer
                out.update(status=FAILED, message="WordPress no conservó el cambio; se restauró el contenido original.", backup=None)
                return out
            out.update(status=APPLIED, message=f"Se retiraron {n} elemento(s) del contenido ({post['rest_base']} #{post['id']}). Copia guardada para revertir.")
            return out

        out["message"] = f"Acción desconocida: {action}"
        return out
    except WPError as e:
        out["message"] = f"WordPress respondió con error: {e}"[:300]
        return out


# ------------------------------------------------------------------
# Bitacora (tabla enh_remediations)
# ------------------------------------------------------------------
def _find_existing(conn, site_id, fp, action=None, target=None, resource=None):
    """Ultimo registro de la misma huella o de la misma accion sobre la misma pagina/recurso
    (dos alertas distintas pueden pedir la misma accion sobre la misma pagina)."""
    return conn.execute(
        """SELECT * FROM enh_remediations WHERE site_id=?
             AND (fingerprint=? OR (action=? AND target_url=? AND COALESCE(resource_url,'')=?))
           ORDER BY id DESC LIMIT 1""",
        (site_id, fp, action, target, resource or "")).fetchone()


def _insert(conn, site_id, audit_id, item, action, status, mode, threshold, message, res=None):
    res = res or {}
    now = store.now_iso()
    cur = conn.execute(
        """INSERT INTO enh_remediations (site_id, audit_id, fingerprint, created_at, updated_at, action,
               target_url, resource_url, category, wp_rest_base, wp_id, status, mode, confidence, threshold,
               message, backup, prev_status) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
        (site_id, audit_id, item["fingerprint"], now, now, action, item.get("page_url"),
         item.get("resource_url"), item.get("category"), res.get("rest_base"), res.get("wp_id"),
         status, mode, item.get("confidence"), threshold, message, res.get("backup"), res.get("prev_status")),
    )
    return cur.lastrowid


def process_items(site: dict, site_id: int, audit_id: int, items: list, cfg: dict, glob: dict,
                  hint_ids: dict, resolved_fps: set) -> dict:
    """
    Recorre los elementos, decide y (si corresponde) corrige. Modifica cada item:
      rem_action, rem_mode, rem_status, rem_message, status (REMEDIATED / PENDING_AUTHORIZATION).
    Devuelve contadores: {'auto_applied','dry_run','failed','pending','skipped'}.
    """
    store.ensure_schema()
    counters = {"auto_applied": 0, "dry_run": 0, "failed": 0, "pending": 0, "skipped": 0}
    w = cfg["wp"]
    threshold = cfgmod.effective_threshold(cfg, glob)

    # Pendientes cuyo hallazgo ya desaparecio por su cuenta -> ya no aplican
    with get_conn() as conn:
        for fp in resolved_fps:
            conn.execute(
                """UPDATE enh_remediations SET status=?, updated_at=?, message=COALESCE(message,'') || ' (el hallazgo ya no aparece)'
                   WHERE site_id=? AND fingerprint=? AND status=?""",
                (EXPIRED, store.now_iso(), site_id, fp, PENDING))

    client = get_client(site_id, cfg)
    if not client:
        return counters  # sin WordPress configurado no hay nada que corregir ni que autorizar

    auto_used = 0
    handled = {}  # (accion, pagina, recurso) -> item que la gestiono en esta auditoria
    # Mayor confianza primero: si se agota el tope, se corrige lo mas seguro
    for item in sorted(items, key=lambda i: -int(i.get("confidence") or 0)):
        if item.get("legit"):
            continue
        d = decide(item, cfg, glob, threshold, auto_used)
        item["rem_action"], item["rem_mode"], item["rem_reason"] = d["action"], d["mode"], d["reason"]
        if d["mode"] == "none":
            counters["skipped"] += 1
            continue
        fp, action = item["fingerprint"], d["action"]

        # Otra alerta de esta misma auditoria ya pidio la MISMA accion sobre la MISMA pagina/recurso
        # (p. ej. amenaza de farmacia + idioma inesperado en una pagina): se hace una sola vez.
        hkey = (action, norm_page(item["page_url"]), res_key(item.get("resource_url")))
        if hkey in handled:
            first = handled[hkey]
            item["rem_status"], item["rem_message"] = first.get("rem_status"), first.get("rem_message")
            if first.get("rem_status") == APPLIED:
                item["status"] = history.REMEDIATED
                history.set_state(site_id, fp, history.REMEDIATED, note="corregido junto con otra alerta de la misma página")
            elif first.get("rem_status") == PENDING:
                item["status"] = history.PENDING_AUTHORIZATION
                history.set_state(site_id, fp, history.PENDING_AUTHORIZATION)
            continue

        with get_conn() as conn:
            prev = _find_existing(conn, site_id, fp, action, item.get("page_url"), item.get("resource_url"))
        if prev and prev["status"] == REJECTED:
            item["rem_status"], item["rem_message"] = REJECTED, "Rechazada anteriormente por una persona."
            counters["skipped"] += 1
            handled[hkey] = item
            continue

        if d["mode"] == "authorization":
            msg = "Requiere autorización: " + d["reason"]
            with get_conn() as conn:
                if prev and prev["status"] == PENDING:
                    conn.execute(
                        """UPDATE enh_remediations SET audit_id=?, confidence=?, threshold=?, message=?, updated_at=?,
                               target_url=?, resource_url=?, category=? WHERE id=?""",
                        (audit_id, item.get("confidence"), threshold, msg, store.now_iso(),
                         item.get("page_url"), item.get("resource_url"), item.get("category"), prev["id"]))
                else:
                    _insert(conn, site_id, audit_id, item, action, PENDING, "authorization", threshold, msg)
            item["rem_status"], item["rem_message"] = PENDING, msg
            item["status"] = history.PENDING_AUTHORIZATION
            history.set_state(site_id, fp, history.PENDING_AUTHORIZATION)
            counters["pending"] += 1
            handled[hkey] = item
            continue

        # mode == auto
        auto_used += 1
        res = run_action(client, site["url"], action, item["page_url"], item.get("resource_url", ""),
                         hint_ids.get(norm_page(item["page_url"])), dry_run=w["dry_run"])
        with get_conn() as conn:
            _insert(conn, site_id, audit_id, item, action, res["status"], "auto", threshold, res["message"], res)
        item["rem_status"], item["rem_message"] = res["status"], res["message"]
        handled[hkey] = item
        if res["status"] == APPLIED:
            item["status"] = history.REMEDIATED
            history.set_state(site_id, fp, history.REMEDIATED, note="corregido automáticamente", attempt=True)
            counters["auto_applied"] += 1
        elif res["status"] == DRY_RUN:
            counters["dry_run"] += 1
        else:
            history.set_state(site_id, fp, item.get("lifecycle", history.PERSISTENT), attempt=True)
            # Fallo: queda registrado y cuenta como intento; tras el maximo de intentos
            # (ver decide) deja de reintentarse y se informa como fallido en el reporte.
            counters["failed"] += 1
        log.info("[%s] %s %s -> %s", site.get("name"), action, norm_page(item["page_url"]), res["status"])
    return counters


# ------------------------------------------------------------------
# Autorizar / rechazar / revertir (desde la interfaz)
# ------------------------------------------------------------------
def get_remediation(rem_id: int):
    store.ensure_schema()
    with get_conn() as conn:
        r = conn.execute("SELECT * FROM enh_remediations WHERE id=?", (rem_id,)).fetchone()
    return dict(r) if r else None


def list_remediations(site_id: int = None, statuses=None, limit: int = 200) -> list:
    store.ensure_schema()
    q = ("SELECT r.*, s.name AS site_name FROM enh_remediations r JOIN sites s ON s.id=r.site_id WHERE 1=1")
    params = []
    if site_id:
        q += " AND r.site_id=?"; params.append(site_id)
    if statuses:
        q += f" AND r.status IN ({','.join('?' * len(statuses))})"; params += list(statuses)
    q += " ORDER BY r.id DESC LIMIT ?"; params.append(limit)
    with get_conn() as conn:
        return [dict(r) for r in conn.execute(q, params).fetchall()]


def authorize(rem_id: int, user: str = "dashboard") -> dict:
    """Ejecuta una correccion pendiente (accion real, no simulacion)."""
    r = get_remediation(rem_id)
    if not r:
        return {"ok": False, "message": "No existe esa solicitud."}
    if r["status"] != PENDING:
        return {"ok": False, "message": f"La solicitud ya está en estado {STATUS_LABEL.get(r['status'], r['status'])}."}
    with get_conn() as conn:
        site = conn.execute("SELECT * FROM sites WHERE id=?", (r["site_id"],)).fetchone()
    if not site:
        return {"ok": False, "message": "La campaña ya no existe."}
    client = get_client(r["site_id"])
    if not client:
        return {"ok": False, "message": "WordPress no está configurado para esta campaña."}
    res = run_action(client, site["url"], r["action"], r["target_url"], r["resource_url"] or "", None, dry_run=False)
    with get_conn() as conn:
        conn.execute(
            """UPDATE enh_remediations SET status=?, message=?, updated_at=?, decided_by=?, decided_at=?,
                   wp_rest_base=?, wp_id=?, backup=?, prev_status=?, mode='authorization' WHERE id=?""",
            (res["status"], res["message"], store.now_iso(), user, store.now_iso(), res["rest_base"],
             res["wp_id"], res["backup"], res["prev_status"], rem_id))
        if res["status"] == APPLIED:
            conn.execute(
                "UPDATE enh_findings SET status=? WHERE site_id=? AND fingerprint=? AND audit_id=(SELECT MAX(audit_id) FROM enh_findings WHERE site_id=? AND fingerprint=?)",
                (history.REMEDIATED, r["site_id"], r["fingerprint"], r["site_id"], r["fingerprint"]))
    if res["status"] == APPLIED:
        history.set_state(r["site_id"], r["fingerprint"], history.REMEDIATED,
                          note=f"corregido con autorización de {user}", attempt=True)
    log.info("Autorización #%s por %s -> %s", rem_id, user, res["status"])
    return {"ok": res["status"] == APPLIED, "message": res["message"], "status": res["status"]}


def reject(rem_id: int, user: str = "dashboard") -> dict:
    r = get_remediation(rem_id)
    if not r or r["status"] != PENDING:
        return {"ok": False, "message": "La solicitud ya no está pendiente."}
    with get_conn() as conn:
        conn.execute(
            "UPDATE enh_remediations SET status=?, updated_at=?, decided_by=?, decided_at=?, message=? WHERE id=?",
            (REJECTED, store.now_iso(), user, store.now_iso(), "Rechazada por una persona.", rem_id))
    history.set_state(r["site_id"], r["fingerprint"], history.PERSISTENT)
    log.info("Solicitud #%s rechazada por %s", rem_id, user)
    return {"ok": True, "message": "Solicitud rechazada. No se volverá a proponer mientras el hallazgo siga igual."}


def revert(rem_id: int, user: str = "dashboard") -> dict:
    """Deshace una correccion aplicada (restaura el contenido o saca de la papelera)."""
    r = get_remediation(rem_id)
    if not r or r["status"] != APPLIED:
        return {"ok": False, "message": "Solo se pueden revertir correcciones aplicadas."}
    if r["action"] == "trash_post" and (r["prev_status"] or "") == "trash":
        return {"ok": False, "message": "La página ya estaba en la papelera antes de la corrección; no la envió el sistema."}
    client = get_client(r["site_id"])
    if not client:
        return {"ok": False, "message": "WordPress no está configurado para esta campaña."}
    try:
        if r["action"] == "trash_post":
            client.untrash(r["wp_rest_base"], r["wp_id"], r["prev_status"] or "publish")
        elif r["backup"]:
            client.set_content(r["wp_rest_base"], r["wp_id"], r["backup"])
        else:
            return {"ok": False, "message": "No hay copia para revertir esta acción."}
    except WPError as e:
        return {"ok": False, "message": f"No se pudo revertir: {e}"}
    with get_conn() as conn:
        conn.execute(
            "UPDATE enh_remediations SET status=?, updated_at=?, decided_by=?, decided_at=?, message=? WHERE id=?",
            (REVERTED, store.now_iso(), user, store.now_iso(), "Corrección revertida por una persona.", rem_id))
    history.set_state(r["site_id"], r["fingerprint"], history.PERSISTENT, note="corrección revertida manualmente")
    log.info("Corrección #%s revertida por %s", rem_id, user)
    return {"ok": True, "message": "Corrección revertida."}
