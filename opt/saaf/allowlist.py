#!/home/admin_ubuntu/Desktop/proyecto_saaf/opt/saaf/venv/bin/python
# =============================================================
# SAAF Pro — allowlist.py
# Lista de exclusiones ("lista permitida") para recursos legitimos.
# Logica PURA: validacion de reglas y coincidencia. La persistencia
# (tabla allowlist_rules) vive en database.py.
#
# Una regla dice: "este recurso (URL / dominio / fragmento / patron) ya
# fue aprobado; no lo presentes como riesgo".
#   - Alcance GLOBAL : aplica a todos los sitios/campañas.
#   - Alcance SITE   : aplica solo a una campaña (un sitio).
#
# IMPORTANTE (ver Mejoras_auditoria_y_alertas, punto 1): una exclusion NO
# hace que el auditor deje de DETECTAR el recurso. El auditor lo detecta,
# lo reconoce como aprobado, lo cuenta (hit_count) y solo entonces no lo
# presenta como alerta.
# =============================================================

import re

from url_utils import split_url, url_matches, is_public_suffix

SCOPE_GLOBAL = "global"
SCOPE_SITE = "site"
SCOPES = (SCOPE_GLOBAL, SCOPE_SITE)

MATCH_URL = "url"
MATCH_CONTAINS = "contains"
MATCH_REGEX = "regex"
MATCH_TYPES = {
    MATCH_URL: "URL / dominio / dominio + ruta",
    MATCH_CONTAINS: "Fragmento (la URL contiene…)",
    MATCH_REGEX: "Patrón (expresión regular)",
}

MAX_PATTERN_LEN = 500
MAX_REGEX_LEN = 300

# URLs "de prueba" para detectar regex demasiado amplias
_PROBES = (
    "http://a.test/",
    "https://b.invalid/x.js",
    "https://zzz.example.net/path/file.php?q=1",
)
# Fragmentos tan genericos que permitirian practicamente cualquier recurso
_GENERIC_FRAGMENTS = {
    "http", "https", "html", "script", "javascript", "static", "assets",
    "image", "images", "media", "files", "embed", "cdn", "api", "widget",
}
_NESTED_QUANT_RE = re.compile(r"\([^)]*[+*][^)]*\)[+*{]")  # (a+)+  -> riesgo ReDoS


def validate_rule(scope, pattern, match_type=MATCH_URL, site_id=None):
    """
    Valida y normaliza los datos de una regla.

    Returns:
        (pattern_limpio, match_type, site_id_normalizado)

    Raises:
        ValueError con un mensaje en español apto para mostrar al usuario.
    """
    if scope not in SCOPES:
        raise ValueError("El alcance debe ser 'global' o 'site' (una campaña).")
    if match_type not in MATCH_TYPES:
        raise ValueError(f"Tipo de coincidencia inválido: {match_type!r}.")

    if scope == SCOPE_SITE:
        try:
            site_id = int(site_id)
        except (TypeError, ValueError):
            raise ValueError("Una exclusión por campaña requiere elegir la campaña (sitio).")
    else:
        site_id = None
        
    p = (pattern or "").strip()
    if not p:
        raise ValueError("Indica la URL, dominio, fragmento o patrón a permitir.")
    if len(p) > MAX_PATTERN_LEN:
        raise ValueError(f"El patrón es demasiado largo (máximo {MAX_PATTERN_LEN} caracteres).")
    if any(ord(c) < 32 for c in p):
        raise ValueError("El patrón contiene caracteres de control no permitidos.")
    
    if match_type == MATCH_URL:
        if re.search(r"\s", p):
            raise ValueError("Una URL o dominio no puede contener espacios.")
        host, _path, _q = split_url(p)
        if not host or "." not in host:
            raise ValueError(
                "Indica un dominio completo (por ejemplo 'google.com' o "
                "'google.com/recaptcha/'), no solo una palabra."
            )
        if is_public_suffix(host):
            raise ValueError(
                "Ese patrón es un sufijo público (permitiría dominios ajenos). "
                "Indica un dominio concreto."
            )
    
    elif match_type == MATCH_CONTAINS:
        core = re.sub(r"^(https?:)?//", "", p.lower()).replace("www.", "").strip("/. ")
        frag = p.lower()
        if (
            len(core) < 4
            or core in _GENERIC_FRAGMENTS
            or sum(frag in probe for probe in _PROBES) >= 2
        ):
            raise ValueError(
                "El fragmento es demasiado corto/genérico: permitiría demasiadas "
                "URLs. Usa un dominio (por ejemplo 'google.com/recaptcha/') o un "
                "fragmento más específico."
            )
    
    else:  # MATCH_REGEX
        if len(p) > MAX_REGEX_LEN:
            raise ValueError(f"La expresión regular es demasiado larga (máximo {MAX_REGEX_LEN}).")
        if _NESTED_QUANT_RE.search(p):
            raise ValueError("La expresión regular tiene cuantificadores anidados (riesgo de bloqueo). Simplifícala.")
        try:
            rx = re.compile(p, re.IGNORECASE)
        except re.error as e:
            raise ValueError(f"Expresión regular inválida: {e}")
        if rx.search(""):
            raise ValueError("La expresión regular coincide con textos vacíos: permitiría todo.")
        if all(rx.search(probe) for probe in _PROBES):
            raise ValueError("La expresión regular es demasiado amplia: coincide con casi cualquier URL.")

    return p, match_type, site_id


def _get(rule, key, default=None):
    """Acceso uniforme a dict o sqlite3.Row."""
    try:
        v = rule[key]
    except (KeyError, IndexError):
        return default
    return default if v is None else v


def rule_matches(rule, resource_url, threat_type=None, site_id=None, _rx_cache=None) -> bool:
    """
    ¿La regla (dict/Row) permite este recurso para este sitio/tipo de amenaza?
    No valida el patron: asume que se creo con validate_rule().
    """
    if not resource_url:
        return False
    if not _get(rule, "active", 1):
        return False

    scope = _get(rule, "scope", SCOPE_GLOBAL)
    if scope == SCOPE_SITE and _get(rule, "site_id") != site_id:
        return False

    rule_type = _get(rule, "threat_type")
    if rule_type and threat_type and rule_type != threat_type:
        return False

    pattern = _get(rule, "pattern", "")
    mtype = _get(rule, "match_type", MATCH_URL)
    if mtype == MATCH_URL:
        return url_matches(resource_url, pattern)
    if mtype == MATCH_CONTAINS:
        return pattern.lower() in str(resource_url).lower()
    if mtype == MATCH_REGEX:
        try:
            rx = (_rx_cache or {}).get(pattern) or re.compile(pattern, re.IGNORECASE)
            return bool(rx.search(str(resource_url)))
        except re.error:
            return False
    return False


class AllowlistMatcher:
    """
    Evalua un conjunto de reglas contra recursos. Se construye una vez por
    auditoria (con las reglas vigentes: globales + las del sitio) y cuenta
    cuantas veces coincidio cada regla.
    """
    
    def __init__(self, rules=None):
        self.rules = [r for r in (rules or []) if _get(r, "active", 1)]
        # Las reglas por campaña tienen prioridad sobre las globales al atribuir el acierto
        self.rules.sort(key=lambda r: 0 if _get(r, "scope") == SCOPE_SITE else 1)
        self._rx = {}
        for r in self.rules:
            if _get(r, "match_type") == MATCH_REGEX:
                try:
                    self._rx[_get(r, "pattern")] = re.compile(_get(r, "pattern"), re.IGNORECASE)
                except re.error:
                    pass
        self.hits = {}  # rule_id -> numero de coincidencias
    
    def match(self, resource_url, site_id=None, threat_type=None):
        """Devuelve la primera regla que permite el recurso, o None. Registra el acierto."""
        for r in self.rules:
            if rule_matches(r, resource_url, threat_type, site_id, self._rx):
                rid = _get(r, "id")
                if rid is not None:
                    self.hits[rid] = self.hits.get(rid, 0) + 1
                return r
        return None


# =============================================================
# Recuperar el recurso de amenazas ANTIGUAS (sin columna resource_url)
# =============================================================

_SRC_HREF_DESC_RE = re.compile(r"(?:src|href)='([^']+)'")
_ATTR_HTML_RE = re.compile(r"""(?:src|href)\s*=\s*["']([^"']+)["']""", re.IGNORECASE)
_DOMAIN_DESC_RE = re.compile(r"dominio='([^']+)'")


def extract_resource_url(threat_type, description, code_snippet=None, url_found=None):
    """
    Reconstruye el recurso sospechoso (src/href) de una amenaza guardada ANTES
    de existir la columna resource_url, leyendo su descripcion/snippet.
    Aviso: las descripciones antiguas recortaban la URL a 100 caracteres.
    """
    if threat_type == "casino_pharma_adult":
        return url_found or None
    m = _SRC_HREF_DESC_RE.search(description or "")
    if m:
        return m.group(1)
    m = _ATTR_HTML_RE.search(code_snippet or "")
    if m:
        return m.group(1)
    if threat_type == "broken_internal_link":
        m = _DOMAIN_DESC_RE.search(description or "")
        if m:
            return f"https://{m.group(1)}/"
    return None