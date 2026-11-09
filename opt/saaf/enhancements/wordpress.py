# =============================================================
# SAAF Pro — enhancements/wordpress.py
# Cliente minimo de la API REST de WordPress para aplicar correcciones
# AUTORIZADAS. Autenticacion: "Contrasena de aplicacion" de un usuario
# dedicado al bot (Usuarios > Perfil > Contrasenas de aplicacion), nunca la
# contrasena de acceso de una persona.
#
# Principios:
#   * Solo acciones reversibles: enviar a la PAPELERA (nunca borrar definitivo)
#     y editar contenido guardando copia para poder revertir.
#   * Solo se actua sobre contenido cuyo enlace permanente coincide EXACTAMENTE
#     con la URL del hallazgo (nunca "el post que mas se parezca").
#   * Nunca se toca la portada ni una URL de otro dominio.
# =============================================================

import os
import re
import time
from collections import Counter
from urllib.parse import urlparse

import requests

from url_utils import split_url
from .items import norm_page

TIMEOUT = 15
UA = "SAAF-Bot/1.0 (+security audit remediation)"
SKIP_TYPES = {"attachment", "nav_menu_item", "wp_block", "wp_template", "wp_template_part",
              "wp_navigation", "wp_global_styles", "wp_font_family", "wp_font_face"}
MAX_CONTENT_BYTES = 400_000


class WPError(Exception):
    def __init__(self, message, status=None):
        super().__init__(message)
        self.status = status


def _same_site(a: str, b: str) -> bool:
    ha, hb = split_url(a)[0], split_url(b)[0]
    return bool(ha) and ha == hb


def _same_page(a: str, b: str) -> bool:
    ha, pa, _ = split_url(a)
    hb, pb, _ = split_url(b)
    return ha == hb and pa.rstrip("/") == pb.rstrip("/")


def is_front_page(site_url: str, page_url: str) -> bool:
    return _same_page(site_url, page_url) or split_url(page_url)[1] in ("", "/")


class WPClient:
    def __init__(self, base_url, username, app_password, timeout=TIMEOUT, session=None):
        base_url = (base_url or "").strip().rstrip("/")
        if not base_url.startswith(("http://", "https://")):
            raise WPError("La URL de WordPress debe comenzar con http:// o https://")
        self.base = base_url
        self.timeout = timeout
        self.s = session or requests.Session()
        self.s.headers.update({"User-Agent": UA, "Accept": "application/json"})
        # Las contrasenas de aplicacion se muestran con espacios; WordPress las acepta con o sin ellos.
        self.s.auth = (username, (app_password or "").replace(" ", ""))
        self._types = None

    # ---------------------------------------------------------- bajo nivel
    def _call(self, method, route, params=None, json=None, auth=True):
        """route = '/wp/v2/pages'. Prueba /wp-json y, si no existe, ?rest_route=."""
        kw = dict(timeout=self.timeout, allow_redirects=False)
        if not auth:
            kw["auth"] = None
        r = None
        for style in ("pretty", "plain"):
            if style == "pretty":
                url, p = f"{self.base}/wp-json{route}", dict(params or {})
            else:
                url, p = f"{self.base}/", {**(params or {}), "rest_route": route}
            try:
                r = self.s.request(method, url, params=p, json=json, **kw)
            except requests.RequestException as e:
                raise WPError(f"No se pudo conectar con WordPress ({e.__class__.__name__})")
            ctype = r.headers.get("content-type", "")
            if r.status_code in (301, 302, 307, 308):
                raise WPError(
                    "WordPress redirige la API (¿http→https o www?). Usa la URL final exacta del sitio.",
                    r.status_code,
                )
            if style == "pretty" and r.status_code == 404 and "json" not in ctype:
                continue  # permalinks planos: probar ?rest_route=
            break
        return r

    @staticmethod
    def _json(r):
        try:
            return r.json()
        except ValueError:
            raise WPError("Respuesta de WordPress no válida (no es JSON)", r.status_code)

    @staticmethod
    def _err(r, default):
        try:
            d = r.json()
            return f"{d.get('code', '')}: {d.get('message', default)}"[:200]
        except ValueError:
            return f"{default} (HTTP {r.status_code})"

    # ---------------------------------------------------------- prueba de conexion
    def test(self) -> dict:
        steps = []
        out = {"ok": False, "steps": steps}
        try:
            r = self._call("GET", "/", auth=False)
            if r.status_code != 200:
                steps.append(("API REST", False, f"HTTP {r.status_code}: no responde /wp-json/"))
                out["message"] = "No se encontró la API REST de WordPress en esa URL."
                return out
            ns = self._json(r).get("namespaces", [])
            if "wp/v2" not in ns:
                steps.append(("API REST", False, "El sitio responde pero no expone wp/v2"))
                out["message"] = "La API REST de WordPress parece deshabilitada."
                return out
            steps.append(("API REST", True, "disponible"))

            r = self._call("GET", "/wp/v2/users/me", params={"context": "edit"})
            if r.status_code in (401, 403):
                steps.append(("Credenciales", False, self._err(r, "rechazadas")))
                out["message"] = ("Credenciales rechazadas. Verifica el usuario y la contraseña de "
                                  "aplicación (y que el sitio use HTTPS).")
                return out
            if r.status_code != 200:
                steps.append(("Credenciales", False, self._err(r, "error")))
                out["message"] = "No se pudo validar el usuario."
                return out
            me = self._json(r)
            caps = me.get("capabilities") or {}
            steps.append(("Credenciales", True, f"usuario «{me.get('name') or me.get('slug')}»"))
            can_edit = bool(caps.get("edit_others_posts") and caps.get("edit_others_pages"))
            can_delete = bool(caps.get("delete_others_posts") and caps.get("delete_others_pages"))
            steps.append(("Permiso para editar contenido de otros", can_edit, "edit_others_posts/pages"))
            steps.append(("Permiso para enviar a la papelera", can_delete, "delete_others_posts/pages"))
            out.update(
                ok=True,
                user=me.get("name") or me.get("slug"),
                roles=me.get("roles") or [],
                can_edit=can_edit,
                can_delete=can_delete,
                is_admin=bool(caps.get("manage_options")),
            )
            msg = "Conexión correcta."
            if not (can_edit and can_delete):
                msg += " ⚠️ El usuario no tiene todos los permisos necesarios para corregir."
            if caps.get("manage_options"):
                msg += " ⚠️ Es administrador: se recomienda un usuario con rol Editor dedicado al bot."
            out["message"] = msg
            return out
        except WPError as e:
            steps.append(("Conexión", False, str(e)))
            out["message"] = str(e)
            return out

    # ---------------------------------------------------------- localizar contenido
    def content_types(self) -> list:
        if self._types is not None:
            return self._types
        bases = ["posts", "pages"]
        try:
            r = self._call("GET", "/wp/v2/types", params={"context": "edit"})
            if r.status_code == 200:
                for slug, t in self._json(r).items():
                    rb = t.get("rest_base")
                    if rb and slug not in SKIP_TYPES and t.get("viewable", True) and rb not in bases:
                        bases.append(rb)
        except WPError:
            pass
        self._types = bases
        return bases

    def resolve(self, url: str, hint_id: int = None):
        """Busca el contenido cuyo enlace permanente ES `url`. dict o None."""
        if not _same_site(self.base, url):
            return None
        fields = "id,link,status,type,slug"
        if hint_id:
            for rb in self.content_types():
                r = self._call("GET", f"/wp/v2/{rb}/{int(hint_id)}",
                               params={"context": "edit", "_fields": fields})
                if r.status_code == 200:
                    d = self._json(r)
                    if _same_page(d.get("link", ""), url):
                        return {**d, "rest_base": rb}
        slug = [s for s in urlparse(url).path.split("/") if s][-1:] or [""]
        slug = slug[0]
        if not slug:
            return None
        for rb in self.content_types():
            r = self._call("GET", f"/wp/v2/{rb}",
                           params={"slug": slug, "status": "any", "context": "edit",
                                   "_fields": fields, "per_page": 20})
            if r.status_code != 200:
                continue
            for d in self._json(r):
                if _same_page(d.get("link", ""), url):
                    return {**d, "rest_base": rb}
        return None

    # ---------------------------------------------------------- acciones
    def trash(self, rest_base: str, post_id: int) -> dict:
        r = self._call("DELETE", f"/wp/v2/{rest_base}/{int(post_id)}")  # sin force => papelera
        if r.status_code == 200:
            d = self._json(r)
            st = d.get("status") or (d.get("previous") or {}).get("status")
            return {"ok": True, "status": st}
        raise WPError(self._err(r, "No se pudo enviar a la papelera"), r.status_code)

    def untrash(self, rest_base: str, post_id: int, status: str = "publish") -> dict:
        r = self._call("POST", f"/wp/v2/{rest_base}/{int(post_id)}", json={"status": status})
        if r.status_code == 200:
            return {"ok": True}
        raise WPError(self._err(r, "No se pudo restaurar"), r.status_code)

    def get_content(self, rest_base: str, post_id: int) -> str:
        r = self._call("GET", f"/wp/v2/{rest_base}/{int(post_id)}",
                       params={"context": "edit", "_fields": "id,content"})
        if r.status_code != 200:
            raise WPError(self._err(r, "No se pudo leer el contenido"), r.status_code)
        raw = (self._json(r).get("content") or {}).get("raw")
        if raw is None:
            raise WPError("WordPress no devolvió el contenido editable (content.raw)")
        return raw

    def set_content(self, rest_base: str, post_id: int, content: str) -> dict:
        r = self._call("POST", f"/wp/v2/{rest_base}/{int(post_id)}", json={"content": content})
        if r.status_code == 200:
            return {"ok": True}
        raise WPError(self._err(r, "No se pudo guardar el contenido"), r.status_code)

    # ---------------------------------------------------------- verificacion en la pagina PUBLICA
    def fetch_public(self, url: str):
        """GET anonimo de la pagina publica saltandose cachés (parametro unico). -> (http_status, html)."""
        sep = "&" if "?" in url else "?"
        try:
            r = requests.get(f"{url}{sep}saaf_verify={int(time.time() * 1000)}", timeout=self.timeout,
                             headers={"User-Agent": UA, "Cache-Control": "no-cache", "Pragma": "no-cache"},
                             allow_redirects=True)
            return r.status_code, r.text or ""
        except requests.RequestException:
            return None, ""

    def verify_public(self, action: str, page_url: str, resource_url: str = "", keep_hrefs=(),
                      tries: int = None, delay: float = None) -> dict:
        """
        Comprueba en la pagina que ve cualquier visitante que la correccion surtio efecto:
          trash_post            -> la URL ya no responde 200 (404/410) o ya no es la misma pagina
          remove_link/code      -> el HTML publico ya no referencia el recurso y conserva los enlaces legitimos
        Devuelve {'ok': True|False|None, 'detail': str}; None = no se pudo comprobar (red).
        """
        tries = int(os.environ.get("SAAF_WP_VERIFY_TRIES", "3")) if tries is None else tries
        delay = float(os.environ.get("SAAF_WP_VERIFY_DELAY", "3")) if delay is None else delay
        last = {"ok": None, "detail": "no se pudo consultar la página pública"}
        for i in range(max(1, tries)):
            if i:
                time.sleep(delay)
            status, html = self.fetch_public(page_url)
            if status is None:
                continue
            if action == "trash_post":
                if status in (404, 410):
                    return {"ok": True, "detail": f"la página pública responde HTTP {status}"}
                last = {"ok": False, "detail": f"la página pública sigue respondiendo HTTP {status} (¿caché del sitio?)"}
                continue
            if status >= 400:
                last = {"ok": None, "detail": f"la página pública respondió HTTP {status}"}
                continue
            if public_references(html, resource_url):
                last = {"ok": False, "detail": "el recurso sigue apareciendo en el HTML público (¿caché, tema, widget o plugin?)"}
                continue
            missing = [h for h in keep_hrefs if h and h not in html]
            if missing:
                return {"ok": False, "detail": "tras la corrección faltan enlaces legítimos en la página pública: "
                                               + ", ".join(missing[:3])}
            return {"ok": True, "detail": "el recurso ya no aparece en el HTML público y el contenido legítimo sigue ahí"}
        return last


# =============================================================
# Edicion segura de contenido (funciones puras)
# =============================================================
_A_RE = re.compile(r"<a\b[^>]*?\bhref\s*=\s*(?P<q>[\"'])(?P<href>.*?)(?P=q)[^>]*>.*?</a\s*>", re.I | re.S)
_SCRIPT_RE = re.compile(r"<script\b[^>]*?\bsrc\s*=\s*(?P<q>[\"'])(?P<href>.*?)(?P=q)[^>]*>.*?</script\s*>", re.I | re.S)
_IFRAME_RE = re.compile(r"<iframe\b[^>]*?\bsrc\s*=\s*(?P<q>[\"'])(?P<href>.*?)(?P=q)[^>]*>.*?</iframe\s*>", re.I | re.S)
_HIDDEN_WRAP_OPEN = re.compile(
    r"<(?P<tag>div|span|p|li|ul)\b[^>]*(?:display\s*:\s*none|visibility\s*:\s*hidden|left\s*:\s*-\d{3,}|"
    r"font-size\s*:\s*0|height\s*:\s*0|hidden)[^>]*>\s*$", re.I)


def _res_matches(href: str, resource_url: str) -> bool:
    h, p, _ = split_url(href)
    rh, rp, _ = split_url(resource_url)
    if not h or h != rh:
        return False
    rp, p = rp.rstrip("/"), p.rstrip("/")
    return (not rp) or p == rp or p.startswith(rp + "/")


def _remove(raw: str, rx, resource_url: str):
    removed, out, last = 0, [], 0
    for m in rx.finditer(raw):
        if _res_matches(m.group("href"), resource_url):
            out.append(raw[last:m.start()])
            last = m.end()
            removed += 1
    out.append(raw[last:])
    new = "".join(out)
    # Si el elemento estaba dentro de un contenedor oculto que quedo vacio, se retira tambien.
    if removed:
        for _ in range(removed):
            m = None
            for cand in re.finditer(r"<(?P<tag>div|span|p|li|ul)\b[^>]*>\s*</(?P=tag)>", new, re.I):
                if _HIDDEN_WRAP_OPEN.search(new[cand.start():cand.end()].split(">", 1)[0] + ">"):
                    m = cand
                    break
            if not m:
                break
            new = new[:m.start()] + new[m.end():]
    return new, removed


def strip_links(raw: str, resource_url: str):
    """Quita los <a href> hacia `resource_url`. (nuevo_contenido, n_quitados)."""
    return _remove(raw, _A_RE, resource_url)


def strip_code(raw: str, resource_url: str):
    """Quita <script src> e <iframe src> hacia `resource_url`."""
    new, n1 = _remove(raw, _SCRIPT_RE, resource_url)
    new, n2 = _remove(new, _IFRAME_RE, resource_url)
    return new, n1 + n2


def extract_post_id(html: str):
    """ID de WordPress desde el HTML (shortlink ?p=ID o clases postid-/page-id-)."""
    if not html:
        return None
    m = re.search(r"<link[^>]+rel=[\"']shortlink[\"'][^>]+href=[\"'][^\"']*[?&]p=(\d+)", html, re.I) or \
        re.search(r"<link[^>]+href=[\"'][^\"']*[?&]p=(\d+)[\"'][^>]+rel=[\"']shortlink", html, re.I) or \
        re.search(r"<body[^>]+class=[\"'][^\"']*\b(?:postid|page-id)-(\d+)", html, re.I)
    return int(m.group(1)) if m else None


def public_references(html: str, resource_url: str) -> bool:
    """True si el HTML publico enlaza/carga `resource_url` (a, script o iframe)."""
    if not resource_url:
        return False
    for rx in (_A_RE, _SCRIPT_RE, _IFRAME_RE):
        for m in rx.finditer(html or ""):
            if _res_matches(m.group("href"), resource_url):
                return True
    # etiquetas <link>/<img> o enlaces fuera de patron
    for m in re.finditer(r"(?:href|src)\s*=\s*([\"'])(.*?)\1", html or "", re.I | re.S):
        if _res_matches(m.group(2), resource_url):
            return True
    return False


def kept_hrefs(raw: str, resource_url: str) -> list:
    """href/src de a, script e iframe que NO apuntan a `resource_url` (lo legitimo que debe sobrevivir)."""
    out = []
    for rx in (_A_RE, _SCRIPT_RE, _IFRAME_RE):
        out += [m.group("href") for m in rx.finditer(raw or "") if not _res_matches(m.group("href"), resource_url)]
    return out


def legit_preserved(before: str, after: str, resource_url: str) -> tuple:
    """(ok, faltantes): todo enlace/script/iframe que no es el retirado sigue en `after`."""
    need, have = Counter(kept_hrefs(before, resource_url)), Counter(kept_hrefs(after, resource_url))
    missing = [h for h, n in need.items() if have.get(h, 0) < n]
    return (not missing), missing
