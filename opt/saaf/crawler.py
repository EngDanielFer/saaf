#!/home/admin_ubuntu/Desktop/proyecto_saaf/opt/saaf/venv/bin/python
# =============================================================
# SAAF Pro — crawler.py
# Extrae URLs de un sitio: primero intenta sitemap.xml,
# si no existe hace crawl de la homepage hasta MAX_CRAWL_PAGES.
# Ruta: /home/admin_ubuntu/Desktop/proyecto_saaf/opt/saaf/crawler.py
# =============================================================

import logging
import os
import re
import time
from pathlib import Path
from urllib.parse import urljoin, urlparse
from xml.etree import ElementTree

import requests
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

# ------------------------------------------------------------------
# Configuración
# ------------------------------------------------------------------

MAX_CRAWL_PAGES = int(os.environ.get("SAAF_MAX_CRAWL_PAGES", "200"))
MAX_SITEMAP_URLS = int(os.environ.get("SAAF_MAX_SITEMAP_URLS", "500"))
CRAWL_DELAY = float(os.environ.get("SAAF_CRAWL_DELAY", "0.5"))
REQUEST_TIMEOUT = int(os.environ.get("SAAF_REQUEST_TIMEOUT", "15"))
USER_AGENT = "SAAF-Crawler/2.0 (security audit bot)"

HEADERS = {"User-Agent": USER_AGENT}

# Namespaces XML usados en sitemaps estándar
SITEMAP_NS = {
    "sm": "http://www.sitemaps.org/schemas/sitemap/0.9",
    "xhtml": "http://www.w3.org/1999/xhtml",
}

# =============================================================
# Resultado estandarizado
# =============================================================


class CrawlResult:
    """Resultado de la extracción de URLs de un sitio."""

    def __init__(self, urls: list, method: str, error: str = None):
        self.urls = urls  # Lista de URLs encontradas (strings)
        self.method = method  # 'sitemap' | 'crawl' | 'none'
        self.error = error  # Mensaje de error si falló todo

    def __repr__(self):
        return (
            f"CrawlResult(method={self.method!r}, "
            f"urls={len(self.urls)}, error={self.error!r})"
        )


# =============================================================
# Utilidades
# =============================================================


def _make_session() -> requests.Session:
    """Crea una sesión con headers y timeouts consistentes."""
    s = requests.Session()
    s.headers.update(HEADERS)
    return s


def _is_same_domain(url: str, base_url: str) -> bool:
    """Comprueba que url pertenezca al mismo dominio que base_url."""
    try:
        base_host = urlparse(base_url).netloc.lower().lstrip("www.")
        url_host = urlparse(url).netloc.lower().lstrip("www.")
        return url_host == base_host or url_host.endswith("." + base_host)
    except Exception:
        return False


def _normalize_url(url: str) -> str:
    """Elimina fragmentos y normaliza la URL"""
    try:
        p = urlparse(url)
        return p._replace(fragment="").geturl().rstrip("/")
    except Exception:
        return url


def _is_valid_http_url(url: str) -> bool:
    try:
        p = urlparse(url)
        return p.scheme in ("http", "https") and bool(p.netloc)
    except Exception:
        return False


# =============================================================
# SITEMAP — fetcher y parser
# =============================================================


def _fetch_sitemap_urls(
    sitemap_url: str, session: requests.Session, visited: set = None, depth: int = 0
) -> list:
    """
    Descarga y parsea un sitemap.xml o sitemap index.
    Sigue recursivamente los sitemaps hijos (sitemap index).
    Retorna lista de URLs de páginas.
    """
    if visited is None:
        visited = set()
    if sitemap_url in visited or depth > 3:
        return []
    visited.add(sitemap_url)
    try:
        resp = session.get(sitemap_url, timeout=REQUEST_TIMEOUT, allow_redirects=True)
        resp.raise_for_status()
    except requests.RequestException as e:
        logger.warning("Error descargando sitemap %s: %s", sitemap_url, e)
        return []

    content_type = resp.headers.get("Content-Type", "")
    raw = resp.text.strip()

    # Detectar si es XML o texto plano
    if not raw.startswith("<") and "xml" not in content_type:
        # Puede ser un sitemap de texto plano (una URL por línea)
        urls = [
            line.strip()
            for line in raw.splitlines()
            if line.strip() and _is_valid_http_url(line.strip())
        ]
        logger.info("Sitemap texto plano: %d URLs en %s", len(urls), sitemap_url)
        return urls[:MAX_SITEMAP_URLS]

    # Parsear XML
    try:
        root = ElementTree.fromstring(raw.encode("utf-8"))
    except ElementTree.ParseError as e:
        logger.warning("Error parseando XML del sitemap %s: %s", sitemap_url, e)
        return []

    # Eliminar namespace para simplificar la búsqued
    tag = root.tag
    ns = ""
    if tag.startswith("{"):
        ns = tag.split("}")[0] + "}"

    urls = []

    # Sitemap index — contiene referencias a otros sitemaps
    if root.tag in (f"{ns}sitemapindex", "sitemapindex"):
        child_sitemaps = [
            loc.text.strip()
            for sm in root.findall(f"{ns}sitemap")
            for loc in sm.findall(f"{ns}loc")
            if loc.text and loc.text.strip()
        ]
        logger.info(
            "Sitemap index: %d sitemaps hijos en %s", len(child_sitemaps), sitemap_url
        )
        for child_url in child_sitemaps:
            if len(urls) >= MAX_SITEMAP_URLS:
                break
            child_urls = _fetch_sitemap_urls(child_url, session, visited, depth + 1)
            remaining = MAX_SITEMAP_URLS - len(urls)
            urls.extend(child_urls[:remaining])

    # Sitemap normal — contiene URLs de páginas
    elif root.tag in (f"{ns}urlset", "urlset"):
        for url_el in root.findall(f"{ns}url"):
            if len(urls) >= MAX_SITEMAP_URLS:
                # Cortar durante el loop — no iterar millones de elementos innecesariamente
                break
            loc = url_el.find(f"{ns}loc")
            if loc is not None and loc.text and loc.text.strip():
                url = _normalize_url(loc.text.strip())
                if _is_valid_http_url(url):
                    urls.append(url)
        logger.info("Sitemap normal: %d URLs en %s", len(urls), sitemap_url)

    # Truncar por si acaso (sitemap index puede haber excedido via extend)
    return urls[:MAX_SITEMAP_URLS]


def fetch_from_sitemap(
    site: dict, session: requests.Session = None, on_progress=None
) -> CrawlResult:
    """
    Intenta obtener URLs desde el sitemap del sitio.
    Prueba: sitemap_url configurado → /sitemap.xml → /sitemap_index.xml

    Returns:
        CrawlResult con method='sitemap' si tuvo éxito, o method='none' si falló.
    """
    s = session or _make_session()
    base_url = site["url"]
    sitemap_url = site.get("sitemap_url")

    # Candidatos a probar en orden
    candidates = []
    if sitemap_url:
        candidates.append(sitemap_url)
    candidates += [
        urljoin(base_url + "/", "sitemap.xml"),
        urljoin(base_url + "/", "sitemap_index.xml"),
        urljoin(base_url + "/", "sitemap-index.xml"),
    ]
    # Eliminar duplicados preservando orden
    seen = set()
    candidates = [c for c in candidates if not (c in seen or seen.add(c))]

    for candidate in candidates:
        if on_progress:
            on_progress(f"Buscando sitemap ({candidate})")
        logger.info("Probando sitemap: %s", candidate)
        urls = _fetch_sitemap_urls(candidate, s)
        if urls:
            # Filtrar solo URLs del mismo dominio
            same_domain = [u for u in urls if _is_same_domain(u, base_url)]
            logger.info(
                "Sitemap OK: %d URLs totales, %d del mismo dominio en %s",
                len(urls),
                len(same_domain),
                candidate,
            )
            # Siempre incluir la homepage
            homepage = _normalize_url(base_url)
            if homepage not in same_domain:
                same_domain.insert(0, homepage)
            return CrawlResult(urls=same_domain, method="sitemap")

    logger.info("No se encontró sitemap válido para %s", base_url)
    return CrawlResult(urls=[], method="none")


# =============================================================
# CRAWL — seguimiento de links internos
# =============================================================


def crawl_homepage(
    site: dict,
    session: requests.Session = None,
    max_pages: int = MAX_CRAWL_PAGES,
    on_progress=None,
) -> CrawlResult:
    """
    Crawlea la homepage siguiendo links internos hasta max_pages páginas.
    Solo sigue links del mismo dominio y con esquema http/https.

    Returns:
        CrawlResult con method='crawl'.
    """
    s = session or _make_session()
    base_url = site["url"]
    homepage = _normalize_url(base_url)

    # Límite de cola: max_pages * 5 como máximo en memoria.
    # Sin este límite, un sitio con miles de links en la homepage
    # llenaría la cola entera antes de procesar ninguna página.
    MAX_QUEUE_SIZE = max_pages * 5

    visited = set()
    queue = [homepage]
    found = []

    logger.info(
        "Iniciando crawl desde %s (max %d páginas, cola max %d)",
        homepage,
        max_pages,
        MAX_QUEUE_SIZE,
    )

    while queue and len(found) < max_pages:
        url = queue.pop(0)
        if url in visited:
            continue
        visited.add(url)
        if on_progress:
            # latido: un crawl de 200 paginas puede tardar varios minutos
            on_progress(f"Rastreando enlaces ({len(found)}/{max_pages} páginas)")

        try:
            resp = s.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=True)
            # Solo procesar HTML
            ct = resp.headers.get("Content-Type", "")
            if resp.status_code != 200 or "html" not in ct:
                continue
        except requests.RequestException as e:
            logger.debug("Error fetcheando %s: %s", url, e)
            continue

        found.append(url)
        logger.debug("Crawleada (%d/%d): %s", len(found), max_pages, url)

        # Extraer links internos — no agregar a la cola si ya está llena
        if len(queue) >= MAX_QUEUE_SIZE:
            logger.debug("Cola llena (%d), omitiendo links de %s", MAX_QUEUE_SIZE, url)
            continue

        try:
            soup = BeautifulSoup(resp.text, "html.parser")
            for tag in soup.find_all("a", href=True):
                if len(queue) >= MAX_QUEUE_SIZE:
                    break
                href = tag["href"].strip()
                if not href or href.startswith(("#", "mailto:", "tel:", "javascript:")):
                    continue
                abs_url = _normalize_url(urljoin(url, href))
                if (
                    _is_valid_http_url(abs_url)
                    and _is_same_domain(abs_url, base_url)
                    and abs_url not in visited
                    and abs_url not in queue
                ):
                    queue.append(abs_url)
        except Exception as e:
            logger.debug("Error extrayendo links de %s: %s", url, e)

    logger.info(
        "Crawl completado: %d páginas encontradas para %s", len(found), base_url
    )
    return CrawlResult(urls=found, method="crawl")


# =============================================================
# FUNCIÓN PRINCIPAL — decide sitemap o crawl
# =============================================================


def get_urls(site: dict, max_pages: int = None, on_progress=None) -> CrawlResult:
    """
    Obtiene las URLs a auditar para un sitio.
    Estrategia:
      1. Intenta el sitemap (configurado o auto-detectado).
      2. Si no hay sitemap, hace crawl automático desde la homepage.
      3. Limita el resultado a max_pages URLs.

    Args:
        site:      Dict con claves 'url', 'sitemap_url', 'name'.
        max_pages: Máximo de URLs a devolver.
        on_progress: callable(texto) opcional, invocado durante el rastreo
                     (latido de la auditoría; puede lanzar para abortar).

    Returns:
        CrawlResult con urls, method y error.
    """
    # Prioridad: argumento explícito > campo en el dict del sitio > variable de entorno
    if max_pages is None:
        max_pages = int(site.get("max_pages") or MAX_CRAWL_PAGES)
    session = _make_session()

    # Paso 1: intentar sitemap
    result = fetch_from_sitemap(site, session, on_progress=on_progress)
    if result.urls:
        result.urls = result.urls[:MAX_SITEMAP_URLS]
        logger.info(
            "[%s] Sitemap: %d URLs (limitado a %d)",
            site["name"],
            len(result.urls),
            MAX_SITEMAP_URLS,
        )
        return result

    # Paso 2: crawl automático
    logger.info("[%s] Sin sitemap — iniciando crawl automático", site["name"])
    result = crawl_homepage(site, session, max_pages=max_pages, on_progress=on_progress)

    if not result.urls:
        # Incluir al menos la homepage
        homepage = _normalize_url(site["url"])
        logger.warning("[%s] Crawl sin resultados — usando solo homepage", site["name"])
        return CrawlResult(
            urls=[homepage],
            method="crawl",
            error="Crawl sin resultados, usando solo homepage",
        )

    logger.info("[%s] Crawl: %d URLs encontradas", site["name"], len(result.urls))
    return result


# =============================================================
# ENTRYPOINT
# =============================================================

if __name__ == "__main__":
    import sys

    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s"
    )

    url = sys.argv[1] if len(sys.argv) > 1 else "https://example.com"
    site = {
        "name": url,
        "url": url,
        "sitemap_url": sys.argv[2] if len(sys.argv) > 2 else None,
    }

    print(f"\n=== SAAF Pro — Crawler ===")
    print(f"Sitio: {url}\n")

    result = get_urls(site)

    print(f"Método: {result.method}")
    print(f"URLs: {len(result.urls)}")
    if result.error:
        print(f"Aviso: {result.error}")
    print()
    for i, u in enumerate(result.urls, 1):
        print(f"  {i:>3}. {u}")
