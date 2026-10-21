#!/home/admin_ubuntu/Desktop/proyecto_saaf/opt/saaf/venv/bin/python
# =============================================================
# SAAF Pro — url_utils.py
# Utilidades PURAS (sin BD, sin red) para normalizar URLs/hosts y
# comparar un recurso contra un patron de dominio/ruta.
#
# Las usan allowlist.py (lista de exclusiones) y risk_signals.py
# (clasificacion de severidad). Se centralizan aqui para que ambos
# modulos entiendan "esta URL coincide con ese patron" EXACTAMENTE igual.
#
# Reglas de coincidencia (importantes para la seguridad de la lista
# permitida — una regla demasiado laxa abriria un hueco):
#   - El dominio coincide si es IGUAL o es un SUBDOMINIO del patron,
#     en limite de etiqueta:  google.com  ~  www.google.com
#                             google.com  !~ google.com.evil.tk
#                             google.com  !~ notgoogle.com
#   - La ruta coincide por PREFIJO en limite de segmento:
#                             /recaptcha/ ~  /recaptcha/api2/aframe
#                             /lopezy     !~ /lopezy-evil
#   - Esquema, puerto, 'www.', query y fragmento se ignoran.
#   - Se compara en minusculas.
# =============================================================

import re
from urllib.parse import urlsplit

_SCHEME_RE = re.compile(r"^[a-zA-Z][a-zA-Z0-9+.\-]*://")

# Sufijos publicos de 2 niveles frecuentes (aprox. de eTLD+1 sin depender
# de la lista publica de sufijos). Incluye los de Colombia/LatAm.
_TWO_LEVEL_SUFFIXES = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk",
    "com.au", "net.au", "org.au", "co.nz", "co.za",
    "com.br", "com.ar", "com.mx", "com.pe", "com.ve", "com.ec",
    "com.uy", "com.py", "com.bo", "com.pa", "com.gt", "com.do",
    "com.co", "org.co", "net.co", "edu.co", "gov.co", "mil.co", "nom.co",
    "co.jp", "co.in", "co.kr", "com.tr", "com.cn", "com.hk", "com.sg",
}

_IPV4_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")


def strip_www(host: str) -> str:
    """Quita UN prefijo 'www.' (NO usa lstrip('www.'), que borraba letras)."""
    return host[4:] if host.startswith("www.") else host


def split_url(url) -> tuple:
    """
     Devuelve (host, path, query) normalizados: minusculas, sin puerto,
    sin 'www.', path con '/' inicial y sin '/' duplicados.
    Acepta URLs completas, protocolo-relativas ('//host/x') y patrones sin
    esquema ('google.com/recaptcha/'). Si no se puede interpretar: ('','','').
    """
    if url is None:
        return("", "", "")
    u = str(url).strip().strip("'\"")
    if not u:
        return("", "", "")
    if u.startswith("//"):
        u = "https:" + u
    elif not _SCHEME_RE.match(u):
        u = "http://" + u
    try:
        parts = urlsplit(u)
        host = (parts.hostname or "").lower().rstrip(".")
    except ValueError:
        return("", "", "")
    host = strip_www(host)
    path = re.sub(r"/{2,}", "/", parts.path or "/").lower()
    if not path.startswith("/"):
        path = "/" + path
    return (host, path, parts.query or "")


def get_host(url) -> str:
    """Host normalizado de una URL ('' si no se puede interpretar)."""
    return split_url(url)[0]


def tld_of(host: str) -> str:
    """Ultima etiqueta del host ('' si es IP o vacio)."""
    if not host or _IPV4_RE.match(host):
        return ""
    return host.rsplit(".", 1)[-1]


def registrable_domain(host: str) -> str:
    """Aproximacion de eTLD+1:  cdn.sub.ejemplo.com.co -> ejemplo.com.co"""
    if not host or _IPV4_RE.match(host):
        return host or ""
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    if ".".join(labels[-2:]) in _TWO_LEVEL_SUFFIXES:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def is_public_suffix(host: str) -> bool:
    """
    True si `host` es un sufijo publico (TLD o 'co.uk', 'com.co'...) y por tanto
    NO identifica a un dueño concreto. Permitirlo en una lista de exclusiones
    dejaria pasar dominios ajenos.
    """
    if not host or "." not in host:
        return True # TLD suelto (com, bet...)
    if host in _TWO_LEVEL_SUFFIXES:
        return True
    labels = host.split(".")
    return (
        len(labels) == 2
        and labels[0] in {"co", "com", "org", "net", "edu", "gov", "ac", "mil", "nom"}
        and len(labels[1]) == 2
    )
    

def host_matches(host: str, pattern_host: str) -> bool:
    """host == pattern_host  o  host es subdominio de pattern_host (limite de etiqueta)."""
    if not host or not pattern_host:
        return False
    return host == pattern_host or host.endswith("." + pattern_host)


def path_prefix_matches(path: str, pattern_path : str) -> bool:
    """Prefijo de ruta en limite de segmento. Patron '/' o '' = cualquier ruta."""
    pat = (pattern_path or "").rstrip("/")
    if pat == "":
        return True
    path = (path or "/").rstrip("/") or "/"
    return path == pat or path.startswith(pat + "/")


def url_matches(url, pattern) -> bool:
    """
    True si `url` pertenece al dominio (y ruta, si el patron la incluye) de `pattern`.
        url_matches('https://www.google.com/recaptcha/api2/aframe', 'google.com/recaptcha/') -> True
        url_matches('https://google.com.evil.tk/recaptcha/',        'google.com/recaptcha/') -> False
        url_matches('https://m.me/lopezylopezabogado',              'https://m.me/lopezylopezabogado') -> True
        url_matches('https://m.me/lopezylopezabogado-evil',         'https://m.me/lopezylopezabogado') -> False
    """
    host, path, _ = split_url(url)
    p_host, p_path, _ = split_url(pattern)
    if not host or not p_host:
        return False
    return host_matches(host, p_host) and path_prefix_matches(path, p_path)

def is_third_party(host: str, base_domain: str) -> bool:
    """True si `host` NO es el dominio del sitio auditado ni un subdominio suyo."""
    if not host:
        return False
    base = strip_www((base_domain or "").lower())
    return not host_matches(host, base)