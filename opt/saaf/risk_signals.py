#!/home/admin_ubuntu/Desktop/proyecto_saaf/opt/saaf/venv/bin/python
# =============================================================
# SAAF Pro — risk_signals.py
# Evalua las SEÑALES de riesgo de un recurso externo (script, iframe
# o enlace) a partir de su URL y contexto. Es logica PURA (sin BD ni
# red) para que sea facil de probar y razonar.
#
# severity.py suma los puntos de las señales y decide el nivel final.
# Asi la severidad ya NO depende solo de "es un script externo": se
# evalua la COMBINACION de indicadores (ver Mejoras_auditoria_y_alertas,
# punto 2).
#
# Cada Signal tiene:
#   points : suma (positivo = mas riesgo) o resta (negativo = confianza)
#   strong : True si es un indicador fuerte por si solo de inyeccion /
#            malware. 3 o mas señales fuertes => CRITICAL (ver severity.py)
# =============================================================

import re
from dataclasses import dataclass, asdict

from url_utils import (
    split_url,
    tld_of,
    registrable_domain,
    host_matches,
    url_matches
)

# Kinds de recurso
SCRIPT = "script"
IFRAME = "iframe"
LINK = "link"


@dataclass(frozen=True)
class Signal:
    code: str
    points: int
    label: str
    strong: bool = False
    
    def to_dict(self) -> dict:
        return asdict(self)
    

# =============================================================
# Listas de referencia
# =============================================================

# TLD asociados a apuestas / contenido adulto: muy raros como origen de
# scripts legitimos de un sitio corporativo => señal fuerte.
HIGH_RISK_TLDS = {
    "bet", "casino", "poker", "bingo", "lotto", "porn", "xxx", "adult",
    "sex", "sexy", "webcam",
}

# TLD baratos con alta tasa de abuso. Señal debil (puntua poco).
ABUSED_TLDS = {
    "xyz", "top", "click", "link", "icu", "buzz", "cyou", "cfd", "sbs",
    "rest", "monster", "loan", "win", "stream", "download", "zip", "mov",
    "tk", "ml", "ga", "cf", "gq", "work", "party", "review", "bid", "kim",
    "men", "trade", "accountant", "date", "racing", "science", "faith",
    "cricket", "pw",
}

# Extensiones de lenguaje de servidor: un <script src> que apunta a ellas
# desde un dominio de terceros suele ser un cargador dinamico (inyeccion).
SERVER_SIDE_EXTENSIONS = {
    "php", "php3", "php4", "php5", "php7", "php8", "phtml", "asp", "aspx",
    "jsp", "jspx", "cgi", "pl", "py", "rb", "cfm",
}

# Doble extension: algo.js.php, imagen.jpg.js, doc.pdf.exe ...
_DOUBLE_EXT_RE = re.compile(
    r"\.(js|css|jpe?g|png|gif|svg|ico|webp|txt|json|map|pdf|docx?|html?)"
    r"\.(php\d?|phtml|asp|aspx|jsp|cgi|js|exe|zip|bat|sh|scr)$",
    re.IGNORECASE,
)

# Carpetas de CONTENIDO/proyecto: no es donde un proveedor legitimo
# publica su JS (que vive en /dist, /js, /sdk, /v1, /widget...).
_CONTENT_DIRS = {
    "projects", "project", "uploads", "upload", "images", "img", "tmp",
    "temp", "cache", "files", "file", "users", "user", "members", "member",
    "backup", "backups", "old", "test", "demo", "dev",
}

# Hosts de contenido generado por usuarios / alojamiento temporal, muy
# usados para servir payloads. Un sitio legitimo casi nunca carga SCRIPTS
# de aqui. (Señal debil.)
UGC_OR_TEMP_HOSTS = (
    "gist.githubusercontent.com", "raw.githubusercontent.com", "pastebin.com",
    "paste.ee", "hastebin.com", "ghostbin.com", "transfer.sh", "anonfiles.com",
    "dl.dropboxusercontent.com", "workers.dev", "pages.dev", "vercel.app",
    "netlify.app", "herokuapp.com", "glitch.me", "repl.co", "ngrok.io",
    "ngrok-free.app", "trycloudflare.com", "ipfs.io", "web.app",
    "firebaseapp.com", "000webhostapp.com", "infinityfreeapp.com",
)

# Librerias conocidas cuyo nombre suelen imitar los scripts maliciosos
# (p. ej. id="asahi-jquery-min-bundle-js" cargando desde un dominio ajeno).
_KNOWN_LIBS = (
    "jquery", "bootstrap", "recaptcha", "analytics", "gtag", "fontawesome",
    "lodash", "popper", "swiper", "slick", "moment", "axios", "wp-embed",
    "elementor", "woocommerce",
)

# Marcas que suelen imitarse: token -> dominios registrables OFICIALES.
# (token minusculas y sin guiones). Deliberadamente acotada a objetivos
# de alto valor para evitar falsos positivos.
BRANDS = {
    "draftkings": {"draftkings.com"},
    "fanduel": {"fanduel.com"},
    "betmgm": {"betmgm.com"},
    "bet365": {"bet365.com"},
    "pokerstars": {"pokerstars.com", "pokerstars.eu"},
    "caesars": {"caesars.com", "caesarscasino.com"},
    "paypal": {"paypal.com", "paypalobjects.com", "paypal.me"},
    "stripe": {"stripe.com", "stripe.network"},
    "binance": {"binance.com"},
    "coinbase": {"coinbase.com"},
    "metamask": {"metamask.io"},
    "google": {
        "google.com", "gstatic.com", "googleapis.com", "googleusercontent.com",
        "googletagmanager.com", "google-analytics.com", "googlesyndication.com",
        "googleadservices.com", "googletagservices.com", "doubleclick.net",
        "youtube.com", "youtu.be", "ytimg.com", "withgoogle.com", "recaptcha.net",
    },
    "facebook": {"facebook.com", "facebook.net", "fbcdn.net", "fb.com", "fb.me"},
    "instagram": {"instagram.com", "cdninstagram.com"},
    "whatsapp": {"whatsapp.com", "whatsapp.net", "wa.me"},
    "microsoft": {
        "microsoft.com", "microsoftonline.com", "msn.com", "live.com",
        "office.com", "windows.net", "azureedge.net", "bing.com",
    },
    "apple": {"apple.com", "icloud.com", "mzstatic.com"},
    "amazon": {
        "amazon.com", "amazonaws.com", "amazon-adsystem.com",
        "media-amazon.com", "ssl-images-amazon.com",
    },
    "netflix": {"netflix.com", "nflxext.com", "nflximg.net"},
    "jquery": {"jquery.com", "jquerycdn.com"},
    "cloudflare": {"cloudflare.com", "cloudflare.net", "cloudflareinsights.com"},
}

# Servicios LEGITIMOS conocidos, con ruta (consciente del path: google.com
# en general NO es de confianza — sites.google.com se usa para spam —, pero
# google.com/recaptcha/ si). Reducen la severidad; no ocultan la deteccion.
TRUSTED_RESOURCE_PREFIXES = (
    "google.com/recaptcha/",
    "gstatic.com/recaptcha/",
    "recaptcha.net/",
    "google.com/maps/embed",
    "youtube.com/embed/",
    "youtube-nocookie.com/embed/",
    "player.vimeo.com/video/",
    "facebook.com/plugins/",
    "connect.facebook.net/",
    "platform.twitter.com/",
    # Infraestructura publicitaria / de consentimiento de Google (iframes ocultos
    # habituales en sitios con anuncios). Solo dominios de Google: nadie mas
    # puede servir contenido desde ellos.
    "doubleclick.net/",
    "fundingchoicesmessages.google.com/",
    "adtrafficquality.google/",
)

# Leet-speak basico para detectar paypa1, g00gle, etc.
_LEET = str.maketrans({"0": "o", "1": "l", "3": "e", "4": "a", "5": "s", "7": "t"})

# Puntos por señal (centralizado para ajustar el criterio en un solo sitio)
POINTS = {
    "known_spam_domain": 3,
    "high_risk_tld": 3,
    "abused_tld": 1,
    "server_side_ext": 2,
    "double_extension": 3,
    "brand_impersonation": 3,
    "anomalous_path": 1,
    "library_masquerade": 1,
    "ugc_or_temp_host": 2,
    "spam_keywords": 2,
    "hidden_script": 2,
    "new_domain": 1,
    "trusted_provider": -6,
}


def _sig(code: str, label: str, strong: bool = False) -> Signal:
    return Signal(code=code, points=POINTS[code], label=label, strong=strong)


# =============================================================
# Detectores individuales (funciones puras)
# =============================================================


def trusted_prefix(url: str):
    """Devuelve el prefijo de TRUSTED_RESOURCE_PREFIXES que cubre `url`, o None."""
    for prefix in TRUSTED_RESOURCE_PREFIXES:
        if url_matches(url, prefix):
            return prefix
    return None


def _filename(path: str) -> str:
    return path.rstrip("/").rsplit("/", 1)[-1] if path else ""


def _extension(filename: str) -> str:
    return filename.rsplit(".", 1)[-1].lower() if "." in filename else ""


def brand_impersonated(host: str):
    """
    Devuelve (token_marca, motivo) si el host imita a una marca conocida sin
    ser su dominio oficial; None si no. Reglas (alta precision):
      a) SLD sin guiones == marca, pero SLD con guiones != marca   (draft-kings)
      b) algun segmento del SLD separado por guion == marca        (paypal-login)
      c) leet-speak: paypa1, g00gle
      d) SLD == marca pero con un TLD de riesgo                    (paypal.xyz, draftkings.bet)
      e) la marca aparece como SUBDOMINIO de un dominio ajeno      (paypal.com.evil.tk)
    Un dominio oficial (BRANDS[token]) nunca se marca.
    """
    reg = registrable_domain(host)
    if not reg or "." not in reg:
        return None
    sld = reg.split(".")[0]
    tld = tld_of(host)
    risky_tld = tld in HIGH_RISK_TLDS or tld in ABUSED_TLDS
    sld_joined = sld.replace("-", "")
    segments = [s for s in sld.split("-") if s]
    sub_labels = host[: -len(reg)].rstrip(".").split(".") if host != reg else []

    for token, official in BRANDS.items():
        if reg in official:
            continue
        # (d) y variantes: el SLD coincide exactamente con la marca
        if sld == token:
            if risky_tld:
                return token, f"usa el nombre de la marca '{token}' con un TLD sospechoso (.{tld})"
            continue  # p. ej. amazon.de / google.com.co: regional legitimo
        # (a) guiones intercalados: draft-kings
        if sld_joined == token and sld != token:
            return token, f"imita a la marca '{token}' mediante guiones ({sld})"
        # (c) leet-speak
        if sld_joined.translate(_LEET) == token and sld_joined != token:
            return token, f"imita a la marca '{token}' con caracteres sustituidos ({sld})"
        # (b) segmento exacto: paypal-login, secure-google
        if len(segments) > 1 and token in segments:
            return token, f"incluye el nombre de la marca '{token}' en un dominio ajeno ({sld})"
        # (e) marca como subdominio de otro dominio
        if any(token == lbl.replace("-", "") for lbl in sub_labels):
            return token, f"usa '{token}' como subdominio de un dominio ajeno ({reg})"
    return None


def anomalous_path(path: str):
    """Descripcion de la anomalia de ruta, o None."""
    segs = [s for s in (path or "").lower().split("/") if s]
    # El ultimo segmento es el archivo; las carpetas son los anteriores
    folders = segs[:-1] if segs and "." in segs[-1] else segs
    hit = [s for s in folders if s in _CONTENT_DIRS]
    if hit:
        return f"ruta poco convencional para un script de terceros (/{hit[0]}/)"
    # NOTA: se probo detectar "identificadores aleatorios" en la ruta, pero
    # marcaba IDs legitimos (p. ej. youtube.com/embed/dQw4w9WgXcQ) — se
    # descarto a proposito: mas ruido que señal.
    return None


# =============================================================
# Evaluacion completa de un recurso
# =============================================================


def evaluate_resource(
    url: str,
    kind: str,
    base_domain: str = "",
    tag_id: str = "",
    is_spam_domain: bool = False,
    new_domain: bool = False,
    hidden: bool = False,
    spam_pattern=None,
) -> list:
    """
    Devuelve la lista de Signal que aplican a `url`.

    Args:
        url:            URL completa del recurso (src / href).
        kind:           SCRIPT | IFRAME | LINK.
        base_domain:    dominio del sitio auditado (informativo).
        tag_id:         atributo id del <script> (para detectar imitacion de librerias).
        is_spam_domain: el dominio esta en la tabla spam_domains.
        new_domain:     el sitio nunca habia cargado recursos de este dominio.
        hidden:         el elemento esta oculto con CSS (solo relevante para scripts).
        spam_pattern:   regex compilada de palabras casino/pharma/adult (de analyzer).
    """
    signals = []
    host, path, _ = split_url(url)
    if not host:
        return signals
    
    # --- Confianza: servicio legitimo conocido (reduce) ---
    prefix = trusted_prefix(url)
    if prefix:
        signals.append(_sig("trusted_provider", f"Servicio legítimo conocido ({prefix})"))

    # --- Reputacion del dominio ---
    if is_spam_domain:
        signals.append(_sig("known_spam_domain", f"Dominio en la lista de spam conocidos ({host})", strong=True))

    tld = tld_of(host)
    if tld in HIGH_RISK_TLDS:
        signals.append(_sig("high_risk_tld", f"TLD de alto riesgo (.{tld}) asociado a apuestas/contenido adulto", strong=True))
    elif tld in ABUSED_TLDS:
        signals.append(_sig("abused_tld", f"TLD con alta tasa de abuso (.{tld})"))

    imp = brand_impersonated(host)
    if imp:
        signals.append(_sig("brand_impersonation", f"Dominio aparenta relación con una marca conocida: {imp[1]}", strong=True))

    if any(host_matches(host, h) for h in UGC_OR_TEMP_HOSTS) and kind in (SCRIPT, IFRAME):
        signals.append(_sig("ugc_or_temp_host", f"Alojamiento de contenido de usuario/temporal ({registrable_domain(host)})"))

    # --- Naturaleza del archivo ---
    fname = _filename(path)
    ext = _extension(fname)
    if _DOUBLE_EXT_RE.search(fname):
        signals.append(_sig("double_extension", f"Doble extensión sospechosa ({fname})", strong=True))
    if kind == SCRIPT and ext in SERVER_SIDE_EXTENSIONS:
        signals.append(_sig("server_side_ext", f"Archivo de servidor (.{ext}) cargado como script externo", strong=True))

    if kind in (SCRIPT, IFRAME):
        why = anomalous_path(path)
        if why:
            signals.append(_sig("anomalous_path", why.capitalize()))
    
    if kind == SCRIPT:
        hay = f"{(tag_id or '').lower()} {fname.lower()}"
        lib = next((l for l in _KNOWN_LIBS if l in hay), None)
        if lib:
            signals.append(_sig("library_masquerade", f"Aparenta ser '{lib}' pero se carga desde un dominio ajeno ({host})"))

    # --- Palabras spam (excluye el TLD para no duplicar con high_risk_tld) ---
    if spam_pattern is not None:
        host_no_tld = host.rsplit(".", 1)[0] if "." in host else host
        if spam_pattern.search(f"{host_no_tld}{path}"):
            signals.append(_sig("spam_keywords", "Palabras de casino/farmacia/adultos en el dominio o la ruta"))

    # --- Contexto ---
    if hidden and kind == SCRIPT:
        signals.append(_sig("hidden_script", "Script cargado dentro de un elemento oculto"))
    if new_domain:
        signals.append(_sig("new_domain", "Dominio nuevo: el sitio no había cargado recursos de aquí antes"))

    return signals


def signals_to_json(signals: list) -> str:
    import json

    return json.dumps([s.to_dict() for s in signals], ensure_ascii=False)


def signals_from_json(raw) -> list:
    """Lista de dicts desde el JSON guardado en BD (tolerante a None/invalido)."""
    import json

    if not raw:
        return []
    try:
        data = json.loads(raw)
        return data if isinstance(data, list) else []
    except (ValueError, TypeError):
        return []


def describe_signals(signals) -> str:
    """Texto corto legible: 'a; b; c' (acepta Signal o dict)."""
    out = []
    for s in signals or []:
        out.append(s.label if isinstance(s, Signal) else s.get("label", ""))
    return "; ".join(x for x in out if x)