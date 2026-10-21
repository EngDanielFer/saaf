#!/home/admin_ubuntu/Desktop/proyecto_saaf/opt/saaf/venv/bin/python
# =============================================================
# SAAF Pro — analyzer.py
# Analiza HTML buscando amenazas por patrones fijos:
#   - Spam links ocultos con CSS
#   - Scripts externos de dominios desconocidos
#   - iframes ocultos
#   - JavaScript ofuscado (eval, base64, document.write)
#   - URLs con patrones casino / pharma / adult
# Ruta: /home/admin_ubuntu/Desktop/proyecto_saaf/opt/saaf/analyzer.py
# =============================================================

import re
import logging
from pathlib import Path
from urllib.parse import urlparse, urljoin

from url_utils import strip_www

from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

# =============================================================
# Patrones de deteccion
# =============================================================

# Palabras clave en URLs que indican casino / pharma / adult
URL_SPAM_PATTERNS = re.compile(
    r"\b(casino|poker|slots?|bet(ting)?|gambling|jackpot|"
    r"viagra|cialis|levitra|pharmacy|pharma|pills?|"
    r"porn|xxx|adult|nude|naked|escort|"
    r"payday[\s\-]?loans?|cheap[\s\-]?meds?|buy[\s\-]?pills?)\b",
    re.IGNORECASE,
)

# JavaScript ofuscado — patrones que indican codigo malicioso
OBFUSCATION_PATTERNS = [
    re.compile(r"\beval\s*\(", re.IGNORECASE),
    re.compile(r"document\.write\s*\(", re.IGNORECASE),
    re.compile(r"unescape\s*\(", re.IGNORECASE),
    re.compile(r"String\.fromCharCode\s*\(", re.IGNORECASE),
    # Patron base64 solitario eliminado — genera falsos positivos
    # (imagenes inline, fuentes, configuraciones legitimas son base64 largo)
    # Solo se detecta base64 cuando va acompanado de atob() o eval()
    # atob() — decodificador base64 nativo de JS
    re.compile(r"\batob\s*\(", re.IGNORECASE),
]

# Atributos CSS que ocultan elementos
HIDDEN_CSS_PATTERNS = re.compile(
    r"display\s*:\s*none|visibility\s*:\s*hidden|"
    r"opacity\s*:\s*0|font-size\s*:\s*0|"
    r"height\s*:\s*0|width\s*:\s*0|"
    r"position\s*:\s*absolute.*left\s*:\s*-[0-9]",
    re.IGNORECASE,
)

# Máximo de caracteres del code_snippet guardado en BD
MAX_SNIPPET_LEN = 500


# =============================================================
# Resultado de análisis
# =============================================================


class Threat:
    """Representa una amenaza detectada en una página."""

    VALID_TYPES = {
        "casino_pharma_adult",
        "hidden_spam_link",
        "external_script",
        "hidden_iframe",
        "obfuscated_js",
        "claude_anomaly",
        "broken_internal_link",
    }

    def __init__(
        self,
        threat_type: str,
        description: str,
        code_snippet: str = None,
        url_found: str = None,
        extra_context: dict = None,
        resource_url: str = None,
    ):
        assert threat_type in self.VALID_TYPES, f"Tipo invalido: {threat_type}"
        self.threat_type = threat_type
        self.description = description
        self.code_snippet = (code_snippet or "")[:MAX_SNIPPET_LEN]
        # url_found = PAGINA donde se detecto ; resource_url = recurso sospechoso
        # (src/href completo), que es lo que se compara con la lista permitida.
        self.url_found = url_found
        self.extra_context = dict(extra_context) if isinstance(extra_context, dict) else {}
        self.resource_url = resource_url or self.extra_context.get("resource_url")
        if self.resource_url:
            self.extra_context.setdefault("resource_url", self.resource_url)
        # severity, score y signals los asigna severity.py — aqui son None/[]
        self.severity = None
        self.score = None
        self.signals = []

    def __repr__(self):
        return f"Threat({self.threat_type!r}, url={self.url_found!r})"

    def to_dict(self) -> dict:
        return {
            "threat_type": self.threat_type,
            "description": self.description,
            "code_snippet": self.code_snippet,
            "url_found": self.url_found,
            "severity": self.severity,
            "resource_url": self.resource_url,
            "extra_context": self.extra_context,
        }


# =============================================================
# Utilidades
# =============================================================


def _get_domain(url: str) -> str:
    """Extrae el dominio de una URL (sin www)."""
    try:
        # strip_www quita UN prefijo 'www.'. (lstrip("www.") borraba letras
        # sueltas: 'wordpress.com' -> 'ordpress.com')
        return strip_www(urlparse(url).netloc.lower())
    except Exception:
        return ""


def _is_hidden(tag) -> bool:
    """
    Determina si un tag HTML está visualmente oculto.
    Chequea: atributo style, clase CSS con patrones de ocultacion,
    y atributo hidden nativo de HTML5.
    """
    # Atributo style inline
    style = tag.get("style", "")
    if HIDDEN_CSS_PATTERNS.search(style):
        return True
    # Atributo hidden de HTML5
    if tag.has_attr("hidden"):
        return True
    # Clase con nombres tipicos de ocultacion
    classes = " ".join(tag.get("class", []))
    if re.search(
        r"\bhidden\b|\binvisible\b|\boff-screen\b|\bsr-only\b|\bvisually-hidden\b",
        classes,
        re.IGNORECASE,
    ):
        return True
    return False


def _is_hidden_or_ancestor_hidden(tag, max_depth: int = 6) -> bool:
    """
    Verifica si el tag o alguno de sus ancestros está visualmente oculto.
    Sube hasta max_depth niveles en el árbol DOM.
    """
    current = tag
    for _ in range(max_depth):
        if current is None:
            break
        if _is_hidden(current):
            return True
        current = getattr(current, "parent", None)
    return False


def _truncate(text: str, max_len: int = MAX_SNIPPET_LEN) -> str:
    if len(text) <= max_len:
        return text
    return text[:max_len] + "...[truncado]"


# =============================================================
# Detectores individuales
# =============================================================}


def detect_hidden_span_links(soup: BeautifulSoup, page_url: str) -> list:
    """
    Busca links (<a>) ocultos con CSS que apunten a dominios EXTERNOS con
    patrones casino/pharma/adult.
    Solo se alerta si el link apunta a un dominio distinto al del sitio —
    esto evita falsos positivos en articulos legitimos sobre estos temas.
    """
    base_domain = _get_domain(page_url)
    threats = []
    seen_hrefs = set()

    for tag in soup.find_all("a", href=True):
        href = tag.get("href", "").strip()
        text = tag.get_text(strip=True)

        # Ignorar links relativos o del mismo dominio
        if not href.startswith(("http://", "https://")):
            continue
        link_domain = _get_domain(href)
        if not link_domain:
            continue
        if link_domain == base_domain or link_domain.endswith("." + base_domain):
            continue

        # Deduplicar por href
        if href in seen_hrefs:
            continue
        seen_hrefs.add(href)

        # Solo alertar si el link externo tiene patrones spam en href O en texto
        is_spam_href = bool(URL_SPAM_PATTERNS.search(href))
        is_spam_text = bool(URL_SPAM_PATTERNS.search(text))
        is_hidden = _is_hidden_or_ancestor_hidden(tag)

        if is_hidden:
            # Capturar el contenedor oculto mas cercano para el snippet
            container = tag
            for _ in range(6):
                parent = getattr(container, "parent", None)
                if parent is None:
                    break
                if _is_hidden(parent):
                    container = parent
                    break

            snippet = _truncate(
                f"Elemento oculto:\n{str(container)[:300]}\n\nLink:\n{str(tag)}"
            )
            threats.append(
                Threat(
                    threat_type="hidden_spam_link",
                    description=(
                        f"Link externo oculto (display:none/hidden): "
                        f"dominio='{link_domain}' "
                        f"href='{href[:100]}' "
                        f"texto='{text[:60]}'"
                    ),
                    code_snippet=snippet,
                    url_found=page_url,
                    resource_url=href,
                    extra_context={"hidden": True},
                )
            )
            logger.debug("hidden_spam_link (oculto) en %s: %s", page_url, href[:80])

        elif is_spam_href or is_spam_text:
            # Link visible pero con palabras spam en href o texto
            snippet = _truncate(str(tag))
            threats.append(
                Threat(
                    threat_type="hidden_spam_link",
                    description=(
                        f"Link externo con patron spam: "
                        f"dominio='{link_domain}' "
                        f"href='{href[:100]}' "
                        f"texto='{text[:60]}'"
                    ),
                    code_snippet=snippet,
                    url_found=page_url,
                    resource_url=href,
                    extra_context={"hidden": False},
                )
            )
            logger.debug(
                "hidden_spam_link (spam visible) en %s: %s", page_url, href[:80]
            )

        # if not (is_spam_href or is_spam_text):
        #     continue

        # # Verificar si está oculto
        # if _is_hidden(tag):
        #     snippet = _truncate(str(tag))
        #     threats.append(
        #         Threat(
        #             threat_type="hidden_spam_link",
        #             description=f"Link externo spam oculto: dominio='{link_domain}' href='{href[:80]}'",
        #             code_snippet=snippet,
        #             url_found=page_url,
        #         )
        #     )
        #     logger.debug("hidden_spam_link en %s: %s", page_url, href[:80])

    return threats


def detect_external_scripts(
    soup: BeautifulSoup, page_url: str, spam_domains: set, base_domain: str
) -> list:
    """
    Busca scripts externos cargados desde dominios no reconocidos.
    spam_domains: conjunto de dominios maliciosos conocidos (de la tabla spam_domains en BD).
    Scripts de estos dominios se marcan como spam; otros externos como unknown.
    """
    threats = []

    # CDNs y dominios de scripts legitimos conocidos
    SAFE_SCRIPT_DOMAINS = {
        "googleapis.com",
        "gstatic.com",
        "googletagmanager.com",
        "google-analytics.com",
        "googlesyndication.com",
        "cloudflare.com",
        "cdnjs.cloudflare.com",
        "jquery.com",
        "jsdelivr.net",
        "unpkg.com",
        "bootstrapcdn.com",
        "fontawesome.com",
        "facebook.net",
        "facebook.com",
        "twitter.com",
        "twimg.com",
        "linkedin.com",
        "amazon-adsystem.com",
        "doubleclick.net",
        "adsense.google.com",
        "connect.facebook.net",
        "platform.twitter.com",
        "disqus.com",
        "disquscdn.com",
        "addthis.com",
        "sharethis.com",
        "hotjar.com",
        "clarity.ms",
        "segment.com",
        "segment.io",
        "stripe.com",
        "js.stripe.com",
        "paypal.com",
        "paypalobjects.com",
    }

    for tag in soup.find_all("script", src=True):
        src = tag.get("src", "").strip()
        if not src or not src.startswith(("http://", "https://", "//")):
            continue

        # Normalizar //domain a https://domain
        if src.startswith("//"):
            src = "https:" + src

        script_domain = _get_domain(src)
        if not script_domain:
            continue

        # Es del mismo dominio o subdominio
        if script_domain == base_domain or script_domain.endswith("." + base_domain):
            continue

        # Es un dominio seguro conocido
        is_safe = any(
            script_domain == safe or script_domain.endswith("." + safe)
            for safe in SAFE_SCRIPT_DOMAINS
        )
        if is_safe:
            continue

        # Es un dominio spam conocido
        is_spam = any(
            script_domain == spam or script_domain.endswith("." + spam)
            for spam in spam_domains
        )

        snippet = _truncate(str(tag))
        severity_hint = "spam" if is_spam else "unknown"
        threats.append(
            Threat(
                threat_type="external_script",
                description=f"Script externo de dominio {severity_hint}: {script_domain} (src='{src[:100]}')",
                code_snippet=snippet,
                url_found=page_url,
                resource_url=src,
                extra_context={
                    "is_spam_domain": is_spam,
                    "tag_id": tag.get("id", "") or "",
                    "hidden": _is_hidden_or_ancestor_hidden(tag),
                },
            )
        )
        logger.debug(
            "external_script en %s: %s (%s)", page_url, script_domain, severity_hint
        )

    return threats


def detect_hidden_iframes(soup: BeautifulSoup, page_url: str) -> list:
    """
    Busca iframes ocultos (por CSS, dimensiones 0 o sandboxed sin display).
    Un iframe visible y con src conocido es normal; uno oculto es sospechoso.
    """
    threats = []
    for tag in soup.find_all("iframe"):
        src = tag.get("src", "").strip()

        # iframe sin src o con about:blank no es amenaza
        if not src or src in ("about:blank", "javascript:void(0)"):
            continue

        is_hidden_css = _is_hidden_or_ancestor_hidden(tag)
        width = tag.get("width", "").strip()
        height = tag.get("height", "").strip()
        is_zero_size = width in ("0", "0px", "1", "1px") or height in (
            "0",
            "0px",
            "1",
            "1px",
        )

        if is_hidden_css or is_zero_size:
            snippet = _truncate(str(tag))
            # src puede ser relativo o protocolo-relativo: se resuelve para
            # poder compararlo contra la lista permitida
            abs_src = urljoin(page_url, src) if not src.startswith(("javascript:", "data:")) else src
            threats.append(
                Threat(
                    threat_type="hidden_iframe",
                    description=f"Iframe oculto detectado: src='{src[:100]}'",
                    code_snippet=snippet,
                    url_found=page_url,
                    resource_url=abs_src,
                )
            )
            logger.debug("hidden_iframe en %s: %s", page_url, src[:80])

    return threats


def detect_obfuscated_js(soup: BeautifulSoup, page_url: str) -> list:
    """
    Busca codigo JavaScript ofuscado en scripts inline.
    Patrones: eval(), document.write(), atob(), String.fromCharCode(),
    unescape(), y strings base64 largos (payload probable).
    """
    threats = []
    for tag in soup.find_all("script"):
        # Solo scripts inline (sin atributo src)
        if tag.get("src"):
            continue
        code_text = tag.get_text()
        if not code_text.strip():
            continue

        matched_patterns = []
        for pattern in OBFUSCATION_PATTERNS:
            match = pattern.search(code_text)
            if match:
                matched_patterns.append(match.group(0)[:40])

        if matched_patterns:
            snippet = _truncate(code_text.strip())
            threats.append(
                Threat(
                    threat_type="obfuscated_js",
                    description=f"JavaScript ofuscado: patrones detectados: {', '.join(matched_patterns[:3])}",
                    code_snippet=snippet,
                    url_found=page_url,
                )
            )
            logger.debug("obfuscated_js en %s: %s", page_url, matched_patterns[:3])

    return threats


def detect_broken_internal_links(
    soup: BeautifulSoup, page_url: str, base_domain: str, known_old_domains: list = None
) -> list:
    """
    Detecta enlaces internos rotos que apuntan a un dominio antiguo del sitio.

    Esto ocurre cuando un sitio cambia de dominio (ej: de alexas-enterprise.com
    a rrlandconstruction.com) pero los links del footer/header no se actualizaron,
    o cuando un hack inyecta links a un dominio previo del cliente para manipular
    el anchor text y el historial de backlinks.

    Estrategia de detección:
      1. Si se proveen known_old_domains: detectar links a esos dominios específicos.
      2. Si NO se proveen: buscar links "internos" que en realidad apuntan a un
         dominio distinto al actual pero que comparte palabras del nombre del sitio
         (heurística para detectar dominios alternativos del mismo negocio).
      3. Agrupar por dominio destino para reportar "N links rotos al mismo dominio".

    Args:
        soup:             HTML parseado de la página.
        page_url:         URL de la página que se está analizando.
        base_domain:      Dominio actual del sitio (ej: rrlandconstruction.com).
        known_old_domains: Lista de dominios antiguos conocidos del sitio (opcional).
                           Si se pasa vacío, se usa detección heurística.

    Returns:
        Lista de objetos Threat con tipo 'broken_internal_link'.
    """

    threats = []
    old_domains = [d.lower().strip() for d in (known_old_domains or [])]

    # Acumular links por dominio destino para agruparlos en un solo Threat
    # { dominio_antiguo: [lista de (href, anchor_text, tag_html)] }
    broken_by_domain: dict = {}

    for tag in soup.find_all("a", href=True):
        href = tag.get("href", "").strip()
        if not href.startswith(("http://", "https://")):
            continue

        link_domain = _get_domain(href)
        if not link_domain or link_domain == base_domain:
            continue
        if link_domain.endswith("." + base_domain):
            continue

        is_broken = False

        # Caso 1: dominio antiguo conocido explícitamente
        if old_domains:
            if any(
                link_domain == old or link_domain.endswith("." + old)
                for old in old_domains
            ):
                is_broken = True

        # Caso 2: heurística — el dominio destino comparte términos clave
        # con el dominio actual, sugiriendo que es un dominio anterior del mismo sitio.
        # Ejemplo: base=rrlandconstruction.com, link=alexas-enterprise.com
        # Esta heurística es deliberadamente conservadora para evitar falsos positivos.
        # Solo activa si el link está en footer/header (ubicaciones típicas de nav).
        if not is_broken and not old_domains:
            parent_tag = getattr(tag, "parent", None)
            in_nav_area = False
            current = parent_tag
            for _ in range(8):
                if current is None:
                    break
                tag_name = getattr(current, "name", "")
                tag_id = (current.get("id", "") or "").lower()
                tag_cls = " ".join(current.get("class", [])).lower()
                if tag_name in ("footer", "header", "nav") or any(
                    w in tag_id + tag_cls
                    for w in ("footer", "header", "nav", "menu", "bottom")
                ):
                    in_nav_area = True
                    break
                current = getattr(current, "parent", None)

            if in_nav_area:
                # Verificar que comparte términos con el dominio base
                base_words = set(re.split("[.\\-_]", base_domain)) - {
                    "com",
                    "net",
                    "org",
                    "www",
                    "",
                }
                link_words = set(re.split("[.\\-_]", link_domain)) - {
                    "com",
                    "net",
                    "org",
                    "www",
                    "",
                }
                shared = base_words & link_words
                # Solo alertar si comparten al menos UNA palabra significativa (>3 chars)
                if any(len(w) > 3 for w in shared):
                    is_broken = True

        if is_broken:
            anchor = tag.get_text(strip=True)[:80]
            if link_domain not in broken_by_domain:
                broken_by_domain[link_domain] = []
            broken_by_domain[link_domain].append((href[:200], anchor, str(tag)[:200]))

    # Crear una Threat por dominio antiguo encontrado
    for old_domain, occurrences in broken_by_domain.items():
        count = len(occurrences)
        # Muestra hasta 3 ejemplos en el snippet
        examples = "\n".join(
            f"  [{i+1}] href={href} | texto='{anchor}'"
            for i, (href, anchor, _) in enumerate(occurrences[:3])
        )
        if count > 3:
            examples += f"\n  ... y {count - 3} más"

        code_examples = "\n".join(tag_html for _, _, tag_html in occurrences[:3])

        threats.append(
            Threat(
                threat_type="broken_internal_link",
                description=(
                    f"{count} enlace(s) internos apuntan al dominio antiguo "
                    f"dominio='{old_domain}' en lugar de '{base_domain}'"
                ),
                code_snippet=_truncate(
                    f"{count} links rotos al dominio anterior '{old_domain}':\n"
                    f"{examples}\n\nEjemplos de HTML:\n{code_examples}"
                ),
                url_found=page_url,
                resource_url=occurrences[0][0],
                extra_context={"old_domain": old_domain, "count": count},
            )
        )
        logger.info(
            "broken_internal_link en %s: %d links a '%s'", page_url, count, old_domain
        )

    return threats


def detect_spam_urls(urls: list, site_url: str) -> list:
    """
    Analiza la lista de URLs del sitio buscando patrones
    casino / pharma / adult en las propias URLs del sitemap/crawl.
    """
    threats = []
    seen = set()
    for url in urls:
        if url in seen:
            continue
        seen.add(url)
        match = URL_SPAM_PATTERNS.search(url)
        if match:
            pattern_found = match.group(0)
            threats.append(
                Threat(
                    threat_type="casino_pharma_adult",
                    description=f"URL del sitemap con patron spam '{pattern_found}': {url[:200]}",
                    code_snippet=(
                        f"URL del sitemap:\n{url}\n\n"
                        f"Patron detectado: '{pattern_found}'\n"
                        f"Categoria: {_classify_spam_pattern(pattern_found)}"
                    ),
                    url_found=url,
                    resource_url=url,
                )
            )
            logger.debug(
                "casino_pharma_adult URL: %s (patron: %s)", url[:100], pattern_found
            )
    return threats


def _classify_spam_pattern(pattern: str) -> str:
    """Clasifica el patron spam en una categoria legible."""
    p = pattern.lower()
    if any(w in p for w in ["casino", "poker", "slots", "bet", "gambling", "jackpot"]):
        return "casino/apuestas"
    if any(
        w in p
        for w in ["viagra", "cialis", "levitra", "pharmacy", "pharma", "pills", "meds"]
    ):
        return "pharma/medicamentos"
    if any(w in p for w in ["porn", "xxx", "adult", "sex", "nude", "naked", "escort"]):
        return "contenido adulto"
    if any(w in p for w in ["payday", "loan", "cheap", "buy"]):
        return "prestamos/spam"
    return "spam generico"


# =============================================================
# Función principal
# =============================================================


def analyze_html(
    html_results: list, site: dict, spam_domains: list = None, progress_cb=None
) -> list:
    """
    Analiza el HTML de todas las páginas del sitio buscando amenazas.

    Args:
        html_results: Lista de dicts devueltos por scraper.js
                      (campos: html, url, status_code, error, response_time_ms)
        site:         Dict del sitio (url, name, niche)
        spam_domains: Lista de dominios spam conocidos (de la BD)
        progress_cb:  callable(i, total) opcional, invocado por cada pagina
                      analizada (latido de la auditoria; puede lanzar para abortar)

    Returns:
        Lista de objetos Threat con todas las amenazas encontradas.
        La severidad (threat.severity) se asigna en severity.py.
    """
    all_threats = []
    spam_set = set(spam_domains or [])
    base_domain = _get_domain(site["url"])

    # 1. Analizar URLs del sitio buscando patrones spam
    all_urls = [
        r.get("url") or r.get("redirect_url") or ""
        for r in html_results
        if r.get("url")
    ]
    spam_url_threats = detect_spam_urls(all_urls, site["url"])
    all_threats.extend(spam_url_threats)
    if spam_url_threats:
        logger.info("[%s] %d URLs con patron spam", site["name"], len(spam_url_threats))

    # 2. Analizar el HTML de cada página
    for i, result in enumerate(html_results, 1):
        if progress_cb:
            progress_cb(i, len(html_results))
        html = result.get("html")
        url = result.get("url") or site["url"]
        error = result.get("error")

        if error or not html:
            logger.debug("Sin HTML para analizar en %s: %s", url, error)
            continue

        try:
            soup = BeautifulSoup(html, "html.parser")
        except Exception as e:
            logger.warning("Error parseando HTML de %s: %s", url, e)
            continue

        page_threats = []
        page_threats.extend(detect_hidden_span_links(soup, url))
        page_threats.extend(detect_external_scripts(soup, url, spam_set, base_domain))
        page_threats.extend(detect_hidden_iframes(soup, url))
        page_threats.extend(detect_obfuscated_js(soup, url))
        old_domains = site.get("old_domains") or []
        page_threats.extend(
            detect_broken_internal_links(soup, url, base_domain, old_domains)
        )

        if page_threats:
            logger.info("[%s] %d amenazas en %s", site["name"], len(page_threats), url)

        all_threats.extend(page_threats)

    logger.info(
        "[%s] Analisis completo: %d amenazas en %d paginas",
        site["name"],
        len(all_threats),
        len(html_results),
    )
    return all_threats


# =============================================================
# Entrypoint
# =============================================================

if __name__ == "__main__":
    import sys

    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s"
    )

    print("\n=== SAAF Pro — Analyzer (test completo) ===\n")

    # Test 1: link oculto que NO contiene palabras spam (el caso Boxmark real)
    test_html_boxmark = """
    <html><body>
    <div style="display:none">
      <a href="https://gist.github.com/OriolrOMM/abc123">GitHub</a>
      <a href="https://sites.google.com/view/some-site">Google Site</a>
    </div>
    <a href="https://casino-slots.com/poker" style="display:none">free slots</a>
    <a href="https://normal.com">Normal link</a>
    <script src="https://evil-tracker.xyz/track.js"></script>
    <script>eval(atob('YWxlcnQoJ2hhY2tlZCcp'))</script>
    <iframe src="https://malware.com" width="1" height="1"></iframe>
    </body></html>
    """

    test_result = [
        {
            "html": test_html_boxmark,
            "url": "https://boxmarkdigital.com/tips-for-a-succesful-social-media-strategy/",
            "error": None,
            "status_code": 200,
            "response_time_ms": 200,
        }
    ]
    test_site = {
        "name": "Boxmark Digital",
        "url": "https://boxmarkdigital.com",
        "niche": "digital-marketing",
    }
    spam_list = ["evil-tracker.xyz"]

    threats = analyze_html(test_result, test_site, spam_list)

    print(f"Amenazas detectadas: {len(threats)} (esperado: 5+)\n")
    for t in threats:
        print(f"  [{t.threat_type}] {t.description[:100]}")
        if t.code_snippet:
            print(f"    snippet: {t.code_snippet[:80]}...")
    print()

    # Verificar que se detectaron los links de gist.github.com y sites.google.com
    hidden_links = [t for t in threats if t.threat_type == "hidden_spam_link"]
    hrefs_detected = [t.description for t in hidden_links]
    gist_detected = any("gist.github.com" in d for d in hrefs_detected)
    google_detected = any("sites.google.com" in d for d in hrefs_detected)
    print(f"  gist.github.com detectado: {'SI ✓' if gist_detected else 'NO ✗ (BUG)'}")
    print(
        f"  sites.google.com detectado: {'SI ✓' if google_detected else 'NO ✗ (BUG)'}"
    )

    # Test 2: URL spam en sitemap — verificar code_snippet tiene el patron
    urls_test = [
        "https://boxmarkdigital.com/tips-for-a-succesful-social-media-strategy/",
        "https://site.com/casino-best-poker-2024/",
        "https://site.com/normal-page/",
    ]
    spam_threats = detect_spam_urls(urls_test, "https://site.com")
    print(f"\n  URLs spam detectadas: {len(spam_threats)} (esperado: 1)")
    for t in spam_threats:
        print(
            f"    snippet contiene 'Patron': {'SI ✓' if 'Patron' in t.code_snippet else 'NO ✗'}"
        )
        print(f"    {t.code_snippet[:120]}")

    # Test 3: enlaces internos rotos a dominio antiguo
    print("\n  --- Test broken_internal_link ---")
    test_html_broken = """
    <html><body>
    <footer>
      <a href="https://alexas-enterprise.com/contact">Contact us</a>
      <a href="https://alexas-enterprise.com/about">About</a>
      <a href="https://alexas-enterprise.com/services">Services</a>
      <a href="https://alexas-enterprise.com/portfolio">Portfolio</a>
    </footer>
    <a href="https://rrlandconstruction.com/about">About (correct)</a>
    </body></html>
    """
    test_broken_result = [
        {
            "html": test_html_broken,
            "url": "https://rrlandconstruction.com/",
            "error": None,
            "status_code": 200,
            "response_time_ms": 100,
        }
    ]
    test_broken_site = {
        "name": "RR Land Construction",
        "url": "https://rrlandconstruction.com",
        "niche": "construction",
        "old_domains": ["alexas-enterprise.com"],
    }
    broken_threats = analyze_html(test_broken_result, test_broken_site, [])
    broken = [t for t in broken_threats if t.threat_type == "broken_internal_link"]
    print(f"  broken_internal_link detectados: {len(broken)} (esperado: 1)")
    for t in broken:
        print(f"  ✓ {t.description}")
        print(f"    snippet: {t.code_snippet[:150]}")
