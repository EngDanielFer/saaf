# =============================================================
# SAAF Pro — enhancements/teams_browser.py
# Envio de reportes a Microsoft Teams SIN webhook, Power Automate ni Workflows.
#
# Mecanismo: una cuenta de usuario normal de Teams (con permiso para escribir
# en el chat/canal destino) inicia sesion UNA vez, de forma legitima y
# manual (incluido el MFA), en un perfil de Chromium propio de SAAF. Despues
# el servicio abre Teams Web con ese perfil (sin pantalla), entra al chat,
# escribe el reporte y lo envia.
#
# Un envio solo se da por bueno si se VERIFICA: tras pulsar «Enviar» el
# modulo busca en la lista de mensajes del chat una referencia unica
# (SAAF-xxxxxx), recarga la pagina y vuelve a comprobarla, y guarda una
# captura como evidencia. Si no aparece, el resultado es un ERROR, nunca un
# «exito» por haber hecho clic.
#
# NO se elude MFA ni ningun control de acceso: si la sesion caduca o Microsoft
# pide volver a autenticar, el envio falla con SESSION_EXPIRED, se avisa por
# correo y hay que repetir  `python scripts/python/teams_login.py`.
# =============================================================

import contextlib
import json
import os
import re
import time
import uuid
from pathlib import Path
from urllib.parse import urlparse

from .log import BASE_DIR, LOG_DIR, get_logger

log = get_logger()

PROFILE_DIR = Path(os.environ.get("SAAF_TEAMS_PROFILE_DIR", str(BASE_DIR / "data" / "teams_profile")))
PROOF_DIR = Path(os.environ.get("SAAF_TEAMS_PROOF_DIR", str(LOG_DIR / "teams_proof")))
CHROMIUM_PATH = os.environ.get("SAAF_CHROMIUM_PATH", "").strip() or None
HEADLESS = os.environ.get("SAAF_TEAMS_HEADLESS", "1").strip() != "0"
NAV_TIMEOUT_MS = int(float(os.environ.get("SAAF_TEAMS_NAV_TIMEOUT", "60")) * 1000)
VERIFY_TIMEOUT_S = float(os.environ.get("SAAF_TEAMS_VERIFY_TIMEOUT", "25"))
LOCK_WAIT_S = float(os.environ.get("SAAF_TEAMS_LOCK_WAIT", "180"))
MAX_ATTEMPTS = int(os.environ.get("SAAF_TEAMS_ATTEMPTS", "3"))
MAX_CHARS = 6000
TEAMS_URL = "https://teams.microsoft.com/v2/"

TEAMS_HOSTS = ("teams.microsoft.com", "teams.cloud.microsoft", "teams.live.com")
LOGIN_HOSTS = ("login.microsoftonline.com", "login.live.com", "login.microsoft.com", "account.live.com",
               "sts.", "adfs.")

# Codigos de resultado
OK = "OK"
SESSION_EXPIRED = "SESSION_EXPIRED"
NO_PLAYWRIGHT = "NO_PLAYWRIGHT"
NO_BROWSER = "NO_BROWSER"
NO_TARGET = "NO_TARGET"
TARGET_NOT_FOUND = "TARGET_NOT_FOUND"
WRONG_CHAT = "WRONG_CHAT"
COMPOSER_NOT_FOUND = "COMPOSER_NOT_FOUND"
NOT_DELIVERED = "NOT_DELIVERED"
NETWORK = "NETWORK"
BUSY = "BUSY"
ERROR = "ERROR"

# Selectores de la interfaz de Teams Web (la UI cambia con el tiempo). Se pueden
# reemplazar sin tocar el codigo: SAAF_TEAMS_SELECTORS='{"composer": ["..."]}'
# (JSON en la variable o ruta a un archivo .json). Ver  teams_login.py --diagnose.
SELECTORS = {
    "composer": ['[data-tid="ckeditor"][contenteditable="true"]', '[data-tid="ckeditor"]',
                 'div[role="textbox"][contenteditable="true"]'],
    "send": ['button[data-tid="newMessageCommands-send"]', 'button[aria-label^="Send"]',
             'button[aria-label^="Enviar"]'],
    "messages": ['[data-tid="chat-pane-message"]', '[data-tid="channel-pane-message"]',
                 '[data-tid="message-body"]', '[data-tid="messageBodyContent"]', 'div[id^="message-body-"]'],
    "title": ['[data-tid="chat-title"]', '[data-tid="chat-header-title"]', '[data-tid="thread-header"]',
              '[data-tid="channel-header-title"]'],
    "chat_list_item": ['[data-tid="chat-list-item"]', '[data-tid="chat-list"] [role="treeitem"]',
                       '[role="tree"] [role="treeitem"]', '[data-tid="chat-list"] [role="listitem"]'],
    "web_app_link": ['[data-tid="joinOnWeb"]', 'a:has-text("Use the web app instead")',
                     'a:has-text("Usar la aplicación web")', 'a:has-text("Continue on this browser")',
                     'a:has-text("Continuar en este explorador")'],
    "ready": ['[data-tid="app-bar-wrapper"]', '[data-tid="app-layout-area--nav-bar"]',
              'nav[aria-label="Teams"]', '[data-tid="app-bar-chat"]'],
}
_FAILED_TEXT = re.compile(r"(failed to send|couldn.t send|no se pudo enviar|error al enviar|retry|reintentar)", re.I)


def _load_selector_overrides():
    raw = os.environ.get("SAAF_TEAMS_SELECTORS", "").strip()
    if not raw:
        return
    try:
        data = json.loads(Path(raw).read_text(encoding="utf-8")) if not raw.startswith("{") else json.loads(raw)
        for k, v in data.items():
            if k in SELECTORS and isinstance(v, list) and all(isinstance(x, str) for x in v):
                SELECTORS[k] = v + [s for s in SELECTORS[k] if s not in v]
    except Exception as e:  # noqa
        log.warning("SAAF_TEAMS_SELECTORS no es válido: %s", e.__class__.__name__)


_load_selector_overrides()


# ------------------------------------------------------------------
# Validacion de destino y texto
# ------------------------------------------------------------------
def valid_chat_url(url: str) -> bool:
    try:
        u = urlparse((url or "").strip())
    except Exception:
        return False
    if u.scheme != "https" or not u.netloc:
        # solo para pruebas locales (servidor falso)
        return os.environ.get("SAAF_TEAMS_ALLOW_ANY_HOST") == "1" and u.scheme in ("http", "https") and bool(u.netloc)
    host = u.hostname or ""
    return os.environ.get("SAAF_TEAMS_ALLOW_ANY_HOST") == "1" or any(host == h or host.endswith("." + h) for h in TEAMS_HOSTS)


def new_marker(prefix: str = "SAAF") -> str:
    return f"{prefix}-{uuid.uuid4().hex[:6].upper()}"


def sanitize_line(line: str) -> str:
    """Evita que el editor de Teams interprete el texto (emoji, menciones, listas, enlaces)."""
    s = (line or "").replace("\r", "").replace("\t", " ")
    s = re.sub(r":(?=[A-Za-z0-9_+\-]{2})", ": ", s)        # ":ok" abre el selector de emoji
    s = s.replace("@", "(at)")                              # menciones
    s = re.sub(r"^(\s*)([-*+]|\d+[.)])\s", r"\1• ", s)      # listas automaticas
    return s.rstrip()


def prepare_lines(lines, marker: str) -> list:
    out, total = [], 0
    for ln in lines:
        for part in str(ln).split("\n"):
            part = sanitize_line(part)
            total += len(part) + 1
            if total > MAX_CHARS:
                out.append("… (reporte recortado; el detalle completo está en el dashboard de SAAF Pro)")
                total = -1
                break
            out.append(part)
        if total < 0:
            break
    out.append(f"Ref: {marker}")
    return out


# ------------------------------------------------------------------
# Perfil, bloqueo y navegador
# ------------------------------------------------------------------
@contextlib.contextmanager
def profile_lock(wait_s: float = None):
    """Un solo proceso a la vez usa el perfil (scheduler y dashboard comparten el mismo)."""
    import fcntl

    PROFILE_DIR.mkdir(parents=True, exist_ok=True)
    try:
        PROFILE_DIR.chmod(0o700)
    except OSError:
        pass
    fh = open(PROFILE_DIR.parent / ".saaf_teams.lock", "w")
    deadline = time.time() + (LOCK_WAIT_S if wait_s is None else wait_s)
    got = False
    try:
        while True:
            try:
                fcntl.flock(fh, fcntl.LOCK_EX | fcntl.LOCK_NB)
                got = True
                break
            except OSError:
                if time.time() >= deadline:
                    break
                time.sleep(1)
        yield got
    finally:
        if got:
            with contextlib.suppress(Exception):
                fcntl.flock(fh, fcntl.LOCK_UN)
        fh.close()


def _clear_stale_chromium_locks():
    """Tras un reinicio o caida, Chromium deja SingletonLock; como ya tenemos el bloqueo propio, es huerfano."""
    for n in ("SingletonLock", "SingletonCookie", "SingletonSocket"):
        p = PROFILE_DIR / n
        with contextlib.suppress(OSError):
            if p.is_symlink() or p.exists():
                p.unlink()


def _import_playwright():
    try:
        from playwright.sync_api import sync_playwright, TimeoutError as PWTimeout, Error as PWError
        return sync_playwright, PWTimeout, PWError
    except Exception:
        return None, None, None


def playwright_ready() -> tuple:
    sp, _, _ = _import_playwright()
    if not sp:
        return False, ("Falta Playwright. Instala: venv/bin/pip install playwright  "
                       "(usa el Chromium del sistema con SAAF_CHROMIUM_PATH o ejecuta: venv/bin/playwright install chromium).")
    return True, ""


def _launch(pw, headless: bool):
    PROFILE_DIR.mkdir(parents=True, exist_ok=True)
    _clear_stale_chromium_locks()
    kw = dict(headless=headless, viewport={"width": 1440, "height": 900}, locale="es-CO",
              timezone_id="America/Bogota", args=["--no-first-run", "--no-default-browser-check", "--disable-dev-shm-usage"])
    if CHROMIUM_PATH:
        kw["executable_path"] = CHROMIUM_PATH
    return pw.chromium.launch_persistent_context(str(PROFILE_DIR), **kw)


def _first(page, key, timeout_ms=0, visible=True):
    """Primer locator de SELECTORS[key] que exista (espera hasta timeout_ms en total)."""
    end = time.time() + timeout_ms / 1000.0
    while True:
        for sel in SELECTORS[key]:
            try:
                loc = page.locator(sel)
                if loc.count() > 0:
                    cand = loc.last
                    if not visible or cand.is_visible():
                        return cand
            except Exception:
                continue
        if time.time() >= end:
            return None
        time.sleep(0.4)


def is_login_page(page) -> bool:
    try:
        host = (urlparse(page.url).hostname or "").lower()
        if any(host == h or host.startswith(h) or host.endswith("." + h) for h in LOGIN_HOSTS):
            return True
        return page.locator('input[name="loginfmt"], input[type="password"], #i0116').count() > 0 \
            and not _first(page, "composer")
    except Exception:
        return False


def _wait_ready(page, timeout_ms):
    """Espera a que Teams cargue (barra de apps o editor) o aparezca el login. -> 'ready' | 'login' | 'timeout'."""
    end = time.time() + timeout_ms / 1000.0
    while time.time() < end:
        if is_login_page(page):
            return "login"
        link = _first(page, "web_app_link")
        if link:
            with contextlib.suppress(Exception):
                link.click(timeout=3000)
        if _first(page, "ready") or _first(page, "composer"):
            return "ready"
        time.sleep(0.7)
    return "login" if is_login_page(page) else "timeout"


# ------------------------------------------------------------------
# Abrir el chat correcto
# ------------------------------------------------------------------
def _title_text(page) -> str:
    t = _first(page, "title")
    parts = []
    if t:
        with contextlib.suppress(Exception):
            parts.append(t.inner_text(timeout=2000))
    with contextlib.suppress(Exception):
        parts.append(page.title())
    return " | ".join(parts)


def _chat_matches(page, name: str) -> bool:
    return _norm(name) in _norm(_title_text(page))


def _norm(s: str) -> str:
    return re.sub(r"\s+", " ", (s or "")).strip().casefold()


def open_target(page, chat_url: str, chat_name: str) -> tuple:
    """(ok, code, mensaje). Abre el destino y comprueba que es el chat esperado."""
    if chat_url:
        page.goto(chat_url, wait_until="domcontentloaded", timeout=NAV_TIMEOUT_MS)
        state = _wait_ready(page, NAV_TIMEOUT_MS)
        if state == "login":
            return False, SESSION_EXPIRED, "Teams pide iniciar sesión de nuevo."
        if state == "timeout":
            return False, NETWORK, "Teams no terminó de cargar."
    else:
        page.goto(TEAMS_URL, wait_until="domcontentloaded", timeout=NAV_TIMEOUT_MS)
        state = _wait_ready(page, NAV_TIMEOUT_MS)
        if state == "login":
            return False, SESSION_EXPIRED, "Teams pide iniciar sesión de nuevo."
        if state == "timeout":
            return False, NETWORK, "Teams no terminó de cargar."

    if chat_name and not _chat_matches(page, chat_name):
        # Buscar el chat por nombre en la lista lateral
        found = False
        for sel in SELECTORS["chat_list_item"]:
            try:
                items = page.locator(sel).filter(has_text=re.compile(re.escape(chat_name), re.I))
                if items.count() > 0:
                    items.first.click(timeout=5000)
                    found = True
                    break
            except Exception:
                continue
        if not found:
            return False, TARGET_NOT_FOUND, f"No se encontró el chat «{chat_name}» en la cuenta de Teams."
        deadline = time.time() + 10
        while time.time() < deadline and not _chat_matches(page, chat_name):
            time.sleep(0.5)
        if not _chat_matches(page, chat_name):
            return False, WRONG_CHAT, f"El chat abierto no es «{chat_name}»; no se envía nada."
    if not _first(page, "composer", timeout_ms=15000):
        return False, COMPOSER_NOT_FOUND, ("No se encontró el cuadro para escribir mensajes (¿la cuenta no tiene permiso "
                                           "para escribir en este chat/canal, o cambió la interfaz de Teams?).")
    return True, OK, ""


# ------------------------------------------------------------------
# Escritura y verificacion
# ------------------------------------------------------------------
def _type_message(page, lines):
    comp = _first(page, "composer", timeout_ms=5000)
    comp.click()
    page.keyboard.press("Control+A")
    page.keyboard.press("Delete")
    for i, ln in enumerate(lines):
        if i:
            page.keyboard.press("Shift+Enter")
        if ln:
            page.keyboard.insert_text(ln)
    return comp


def _composer_text(page) -> str:
    c = _first(page, "composer")
    if not c:
        return ""
    with contextlib.suppress(Exception):
        return c.inner_text(timeout=1500)
    return ""


def _submit(page):
    btn = _first(page, "send", timeout_ms=3000)
    if btn:
        btn.click()
    else:
        page.keyboard.press("Enter")


def _message_state(page, marker: str) -> str:
    """'delivered' | 'failed' | 'absent'. Busca el marcador SOLO en mensajes publicados (no en el editor)."""
    for sel in SELECTORS["messages"]:
        try:
            loc = page.locator(sel).filter(has_text=marker)
            if loc.count() > 0:
                txt = ""
                with contextlib.suppress(Exception):
                    txt = loc.last.locator("xpath=ancestor-or-self::*[self::div or self::li][position()<=4]").last.inner_text(timeout=1500)
                if _FAILED_TEXT.search(txt or "") and marker in (txt or ""):
                    # el texto del propio reporte podria contener «retry»; solo cuenta si hay icono/estado de fallo
                    if page.locator('[data-tid*="send-failed"], [data-tid*="failed"], [aria-label*="Failed" i], [aria-label*="No se pudo" i]').count() > 0:
                        return "failed"
                return "delivered"
        except Exception:
            continue
    return "absent"


def _wait_delivered(page, marker: str, timeout_s: float) -> str:
    end = time.time() + timeout_s
    state = "absent"
    while time.time() < end:
        state = _message_state(page, marker)
        if state != "absent":
            return state
        time.sleep(0.8)
    return state


def _proof(page, marker: str) -> str:
    try:
        PROOF_DIR.mkdir(parents=True, exist_ok=True)
        p = PROOF_DIR / f"{marker}.png"
        page.screenshot(path=str(p))
        return str(p)
    except Exception:
        return ""


def _send_once(pw, chat_url, chat_name, lines, marker, headless) -> dict:
    ctx = _launch(pw, headless)
    page = None
    try:
        page = ctx.pages[0] if ctx.pages else ctx.new_page()
        page.set_default_timeout(20000)
        ok, code, msg = open_target(page, chat_url, chat_name)
        if not ok:
            return {"ok": False, "verified": False, "code": code, "error": msg, "proof": _proof(page, "fail-" + marker)}
        _type_message(page, lines)
        if marker not in _composer_text(page):
            return {"ok": False, "verified": False, "code": ERROR, "error": "El texto no quedó escrito en el cuadro de mensaje.",
                    "proof": _proof(page, "fail-" + marker)}
        _submit(page)
        state = _wait_delivered(page, marker, VERIFY_TIMEOUT_S)
        if state == "delivered":
            # Segunda comprobacion: recargar y confirmar que el mensaje esta en el servidor, no solo en pantalla.
            page.reload(wait_until="domcontentloaded", timeout=NAV_TIMEOUT_MS)
            if _wait_ready(page, NAV_TIMEOUT_MS) == "ready":
                state = _wait_delivered(page, marker, VERIFY_TIMEOUT_S)
        if state == "delivered":
            return {"ok": True, "verified": True, "code": OK, "error": "", "marker": marker, "proof": _proof(page, marker),
                    "chat": _title_text(page)[:120]}
        why = ("Teams mostró el mensaje como no enviado." if state == "failed"
               else "El mensaje no apareció en el chat después de enviarlo.")
        return {"ok": False, "verified": False, "code": NOT_DELIVERED, "error": why, "proof": _proof(page, "fail-" + marker)}
    finally:
        with contextlib.suppress(Exception):
            ctx.close()


def send_message(chat_url: str, chat_name: str, lines, marker: str = None, headless: bool = None) -> dict:
    """
    Envia `lines` al chat/canal y VERIFICA que llegó.
    Devuelve {'ok','verified','code','error','marker','proof','attempts'}. Nunca lanza.
    """
    marker = marker or new_marker()
    headless = HEADLESS if headless is None else headless
    base = {"ok": False, "verified": False, "marker": marker, "proof": "", "attempts": 0}
    if not (chat_url or chat_name):
        return {**base, "code": NO_TARGET, "error": "Falta el enlace o el nombre del chat/canal de Teams."}
    if chat_url and not valid_chat_url(chat_url):
        return {**base, "code": NO_TARGET, "error": "El enlace del chat debe ser https://teams.microsoft.com/… (copiado desde Teams)."}
    ready, why = playwright_ready()
    if not ready:
        return {**base, "code": NO_PLAYWRIGHT, "error": why}
    if not (PROFILE_DIR.exists() and any(PROFILE_DIR.iterdir())):
        return {**base, "code": SESSION_EXPIRED,
                "error": "No hay sesión de Teams guardada. Ejecuta una vez: venv/bin/python scripts/python/teams_login.py"}
    sync_playwright, PWTimeout, PWError = _import_playwright()
    body = prepare_lines(lines, marker)

    with profile_lock() as got:
        if not got:
            return {**base, "code": BUSY, "error": "Otro proceso está usando la sesión de Teams; se reintentará en el próximo envío."}
        last = {**base, "code": ERROR, "error": "sin intentos"}
        for attempt in range(1, MAX_ATTEMPTS + 1):
            try:
                with sync_playwright() as pw:
                    res = _send_once(pw, chat_url, chat_name, body, marker, headless)
            except PWTimeout:
                res = {**base, "code": NETWORK, "error": "Teams tardó demasiado en responder."}
            except PWError as e:
                msg = str(e)
                if "Executable doesn't exist" in msg or "executable" in msg.lower() and "exist" in msg.lower():
                    return {**base, "attempts": attempt, "code": NO_BROWSER,
                            "error": "No se encontró Chromium para Playwright (define SAAF_CHROMIUM_PATH o ejecuta playwright install chromium)."}
                if "ERR_" in msg or "net::" in msg:
                    res = {**base, "code": NETWORK, "error": "Sin conexión con Teams (" + msg.split("net::")[-1][:40] + ")."}
                else:
                    res = {**base, "code": ERROR, "error": f"Error del navegador: {msg.splitlines()[0][:150]}"}
            except Exception as e:  # noqa
                res = {**base, "code": ERROR, "error": f"{e.__class__.__name__}: {str(e)[:120]}"}
            res["attempts"] = attempt
            res.setdefault("marker", marker)
            last = res
            if res["ok"]:
                break
            # Sesion caducada, destino equivocado o sin permiso: reintentar no sirve
            if res["code"] in (SESSION_EXPIRED, TARGET_NOT_FOUND, WRONG_CHAT, COMPOSER_NOT_FOUND, NO_BROWSER):
                break
            time.sleep(min(5 * attempt, 15))
    log.info("Teams: destino=%s ok=%s verificado=%s código=%s intentos=%s ref=%s",
             chat_name or "(enlace)", last["ok"], last["verified"], last["code"], last["attempts"], marker)
    return last


# ------------------------------------------------------------------
# Estado de la sesion (para la interfaz y el aviso de caducidad)
# ------------------------------------------------------------------
def session_status(headless: bool = True) -> dict:
    """{'state': 'ok'|'expired'|'none'|'busy'|'error', 'message'}  (no escribe nada en Teams)."""
    ready, why = playwright_ready()
    if not ready:
        return {"state": "error", "message": why}
    if not (PROFILE_DIR.exists() and any(PROFILE_DIR.iterdir())):
        return {"state": "none", "message": "Aún no hay sesión de Teams guardada."}
    sync_playwright, PWTimeout, PWError = _import_playwright()
    with profile_lock(wait_s=5) as got:
        if not got:
            return {"state": "busy", "message": "La sesión se está usando en este momento."}
        try:
            with sync_playwright() as pw:
                ctx = _launch(pw, headless)
                try:
                    page = ctx.pages[0] if ctx.pages else ctx.new_page()
                    page.goto(TEAMS_URL, wait_until="domcontentloaded", timeout=NAV_TIMEOUT_MS)
                    st = _wait_ready(page, NAV_TIMEOUT_MS)
                finally:
                    with contextlib.suppress(Exception):
                        ctx.close()
        except Exception as e:  # noqa
            return {"state": "error", "message": f"{e.__class__.__name__}: {str(e)[:120]}"}
    if st == "ready":
        return {"state": "ok", "message": "Sesión de Teams activa."}
    if st == "login":
        return {"state": "expired", "message": "La sesión de Teams caducó: inicia sesión de nuevo con teams_login.py."}
    return {"state": "error", "message": "Teams no terminó de cargar."}
