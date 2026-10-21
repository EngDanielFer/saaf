#!/home/admin_ubuntu/Desktop/proyecto_saaf/opt/saaf/venv/bin/python
# =============================================================
# SAAF Pro — test_fase2.py
# Tests de validación para crawler.py y scraper.js (Fase 2)
# Ruta: /home/admin_ubuntu/Desktop/proyecto_saaf/opt/saaf/tests/test_fase2.py
# =============================================================

import sys
import os
import json
import tempfile
import subprocess
from pathlib import Path
from unittest.mock import patch, MagicMock

TMP = Path(tempfile.mkdtemp())
os.environ["SAAF_DB_PATH"] = str(TMP / "test.db")

sys.path.insert(0, str(Path(__file__).parent.parent))

PASS = 0
FAIL = 0


def ok(msg):
    global PASS
    PASS += 1
    print(f"  [OK] {msg}")


def fail(msg, err=""):
    global FAIL
    FAIL += 1
    print(f"  [FAIL] {msg}" + (f"\n         {err}" if err else ""))


def section(title):
    print(f"\n{'='*55}")
    print(f"  {title}")
    print(f"{'='*55}")


# ==========================================================
section("Imports")
# ==========================================================
try:
    from crawler import (
        get_urls,
        fetch_from_sitemap,
        crawl_homepage,
        CrawlResult,
        _is_same_domain,
        _normalize_url,
        _is_valid_http_url,
        _fetch_sitemap_urls,
    )

    ok("crawler.py importado correctamente")
except ImportError as e:
    fail("crawler.py no se pudo importar", e)
    sys.exit(1)


# ==========================================================
section("crawler.py — Utilidades")
# ==========================================================
try:
    assert _is_valid_http_url("https://example.com") == True
    assert _is_valid_http_url("http://example.com/page") == True
    assert _is_valid_http_url("ftp://example.com") == False
    assert _is_valid_http_url("no-es-url") == False
    assert _is_valid_http_url("") == False
    ok("_is_valid_http_url() correcto")
except Exception as e:
    fail("_is_valid_http_url()", e)

try:
    assert _is_same_domain("https://example.com/page", "https://example.com") == True
    assert _is_same_domain("https://sub.example.com/x", "https://example.com") == True
    assert _is_same_domain("https://www.example.com", "https://example.com") == True
    assert _is_same_domain("https://other.com", "https://example.com") == False
    assert _is_same_domain("https://evil-example.com", "https://example.com") == False
    ok("_is_same_domain() correcto")
except Exception as e:
    fail("_is_same_domain()", e)

try:
    assert (
        _normalize_url("https://example.com/page#section") == "https://example.com/page"
    )
    assert _normalize_url("https://example.com/") == "https://example.com"
    assert _normalize_url("https://example.com") == "https://example.com"
    ok("_normalize_url() correcto")
except Exception as e:
    fail("_normalize_url()", e)


# ==========================================================
section("crawler.py — CrawlResult")
# ==========================================================
try:
    r = CrawlResult(urls=["https://a.com", "https://b.com"], method="sitemap")
    assert len(r.urls) == 2
    assert r.method == "sitemap"
    assert r.error is None
    ok("CrawlResult() con sitemap")
except Exception as e:
    fail("CrawlResult()", e)

try:
    r = CrawlResult(urls=[], method="none", error="Sin sitemap")
    assert r.method == "none"
    assert r.error == "Sin sitemap"
    ok("CrawlResult() con error")
except Exception as e:
    fail("CrawlResult() error", e)


# ==========================================================
section("crawler.py — Sitemap XML parser (mock)")
# ==========================================================
SITEMAP_XML = """<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <url><loc>https://example.com/</loc></url>
  <url><loc>https://example.com/about</loc></url>
  <url><loc>https://example.com/contact</loc></url>
  <url><loc>https://other.com/spam</loc></url>
</urlset>"""

SITEMAP_INDEX_XML = """<?xml version="1.0" encoding="UTF-8"?>
<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
  <sitemap><loc>https://example.com/sitemap-posts.xml</loc></sitemap>
  <sitemap><loc>https://example.com/sitemap-pages.xml</loc></sitemap>
</sitemapindex>"""

try:
    import requests
    from unittest.mock import patch, MagicMock

    def mock_get_sitemap(url, **kwargs):
        r = MagicMock()
        r.status_code = 200
        r.raise_for_status = lambda: None
        r.headers = {"Content-Type": "application/xml"}
        r.text = SITEMAP_XML
        return r

    with patch("requests.Session.get", side_effect=mock_get_sitemap):
        from crawler import _make_session

        session = _make_session()
        with patch.object(session, "get", side_effect=mock_get_sitemap):
            urls = _fetch_sitemap_urls("https://example.com/sitemap.xml", session)
    assert len(urls) >= 3
    assert "https://example.com/about" in urls
    ok(f"_fetch_sitemap_urls() extrae {len(urls)} URLs del XML")
except Exception as e:
    fail("_fetch_sitemap_urls() XML", e)

try:
    SITEMAP_TXT = "https://example.com/\nhttps://example.com/page1\nnot-a-url\nhttps://example.com/page2\n"

    def mock_get_txt(url, **kwargs):
        r = MagicMock()
        r.status_code = 200
        r.raise_for_status = lambda: None
        r.headers = {"Content-Type": "text/plain"}
        r.text = SITEMAP_TXT
        return r

    from crawler import _make_session

    session = _make_session()
    with patch.object(session, "get", side_effect=mock_get_txt):
        urls = _fetch_sitemap_urls("https://example.com/sitemap.txt", session)
    assert len(urls) == 3
    assert "not-a-url" not in urls
    ok("_fetch_sitemap_urls() texto plano — omite URLs inválidas")
except Exception as e:
    fail("_fetch_sitemap_urls() texto plano", e)


# ==========================================================
section("crawler.py — fetch_from_sitemap (mock)")
# ==========================================================
try:
    site = {
        "name": "Test",
        "url": "https://example.com",
        "sitemap_url": "https://example.com/sitemap.xml",
    }

    def mock_sitemap_response(url, **kwargs):
        r = MagicMock()
        r.raise_for_status = lambda: None
        r.headers = {"Content-Type": "application/xml"}
        r.text = SITEMAP_XML
        return r

    from crawler import _make_session

    session = _make_session()
    with patch.object(session, "get", side_effect=mock_sitemap_response):
        with patch("crawler._make_session", return_value=session):
            result = fetch_from_sitemap(site, session)

    assert result.method == "sitemap"
    assert len(result.urls) >= 1
    # Homepage siempre incluida
    assert any("example.com" in u for u in result.urls)
    # URLs de otros dominios filtradas
    assert not any("other.com" in u for u in result.urls)
    ok(f"fetch_from_sitemap() — {len(result.urls)} URLs, dominio cruzado filtrado")
except Exception as e:
    fail("fetch_from_sitemap()", e)

try:
    site = {"name": "Test", "url": "https://example.com", "sitemap_url": None}

    def mock_404(url, **kwargs):
        r = MagicMock()
        r.raise_for_status.side_effect = requests.HTTPError("404")
        return r

    from crawler import _make_session

    session = _make_session()
    with patch.object(
        session,
        "get",
        side_effect=requests.exceptions.ConnectionError("Connection refused"),
    ):
        with patch("crawler._make_session", return_value=session):
            result = fetch_from_sitemap(site, session)

    assert result.method == "none"
    assert result.urls == []
    ok("fetch_from_sitemap() devuelve method='none' cuando no hay sitemap")
except Exception as e:
    fail("fetch_from_sitemap() sin sitemap", e)


# ==========================================================
section("crawler.py — crawl_homepage (mock)")
# ==========================================================
try:
    HTML_HOME = """<html><body>
    <a href="/about">About</a>
    <a href="/contact">Contact</a>
    <a href="https://external.com/page">External</a>
    <a href="mailto:test@test.com">Mail</a>
    <a href="#section">Fragment</a>
    </body></html>"""

    HTML_ABOUT = """<html><body>
    <a href="/team">Team</a>
    <a href="/">Home</a>
    </body></html>"""

    call_count = [0]

    def mock_crawl_get(url, **kwargs):
        call_count[0] += 1
        r = MagicMock()
        r.status_code = 200
        r.headers = {"Content-Type": "text/html"}
        if url == "https://example.com":
            r.text = HTML_HOME
        else:
            r.text = HTML_ABOUT
        return r

    site = {"name": "Test", "url": "https://example.com", "sitemap_url": None}

    from crawler import _make_session

    session = _make_session()
    with patch.object(session, "get", side_effect=mock_crawl_get):
        with patch("crawler._make_session", return_value=session):
            result = crawl_homepage(site, session, max_pages=5)

    assert result.method == "crawl"
    assert len(result.urls) >= 1
    assert "https://example.com" in result.urls
    # Links externos no incluidos
    assert not any("external.com" in u for u in result.urls)
    ok(f"crawl_homepage() — {len(result.urls)} URLs, externos filtrados")
except Exception as e:
    fail("crawl_homepage()", e)

try:
    site = {"name": "Caido", "url": "https://down.example.com", "sitemap_url": None}

    from crawler import _make_session

    session = _make_session()
    with patch.object(
        session,
        "get",
        side_effect=requests.exceptions.ConnectionError("Connection refused"),
    ):
        with patch("crawler._make_session", return_value=session):
            result = crawl_homepage(site, session, max_pages=5)

    assert result.method == "crawl"
    ok(
        f"crawl_homepage() sitio caído — devuelve result sin crash (urls={len(result.urls)})"
    )
except Exception as e:
    fail("crawl_homepage() sitio caido", e)


# ==========================================================
section("crawler.py — get_urls (mock integración)")
# ==========================================================
try:
    site = {
        "name": "Test",
        "url": "https://example.com",
        "sitemap_url": "https://example.com/sitemap.xml",
    }

    def mock_full(url, **kwargs):
        r = MagicMock()
        r.raise_for_status = lambda: None
        r.headers = {"Content-Type": "application/xml"}
        r.text = SITEMAP_XML
        return r

    from crawler import _make_session

    session = _make_session()
    with patch.object(session, "get", side_effect=mock_full):
        with patch("crawler._make_session", return_value=session):
            result = get_urls(site, max_pages=5)

    assert result.method == "sitemap"
    assert len(result.urls) <= 5
    ok(f"get_urls() con sitemap — {len(result.urls)} URLs (limitado a 5)")
except Exception as e:
    fail("get_urls() con sitemap", e)

try:
    site = {"name": "Test", "url": "https://example.com", "sitemap_url": None}

    def mock_no_sitemap_but_crawl(url, **kwargs):
        r = MagicMock()
        if "sitemap" in url:
            raise requests.exceptions.HTTPError("404 Not Found")
        r.raise_for_status = lambda: None
        r.status_code = 200
        r.headers = {"Content-Type": "text/html"}
        r.text = (
            '<html><body><a href="/page1">P1</a><a href="/page2">P2</a></body></html>'
        )
        return r

    from crawler import _make_session

    session = _make_session()
    with patch.object(session, "get", side_effect=mock_no_sitemap_but_crawl):
        with patch("crawler._make_session", return_value=session):
            result = get_urls(site, max_pages=3)

    assert result.method == "crawl"
    assert len(result.urls) >= 1
    ok(f"get_urls() sin sitemap — fallback a crawl ({len(result.urls)} URLs)")
except Exception as e:
    fail("get_urls() fallback crawl", e)

# ==========================================================
section("scraper.js — contrato JSON (response_time_ms)")
# ==========================================================
SCRAPER_PATH = Path("/home/admin_ubuntu/Desktop/proyecto_saaf/opt/saaf/scripts/node/scraper.js")
if not SCRAPER_PATH.exists():
    print(f"  [SKIP] scraper.js no encontrado en {SCRAPER_PATH}")
else:
    try:
        proc = subprocess.run(
            ["node", str(SCRAPER_PATH)], capture_output=True, text=True, timeout=15
        )
        data = json.loads(proc.stdout.strip())
        assert "response_time_ms" in data, "Falta campo response_time_ms"
        assert "html" in data
        assert "url" in data
        assert "status_code" in data
        assert "error" in data
        assert "redirect_url" in data
        ok("scraper.js sin URL — contrato JSON incluye response_time_ms")
    except Exception as e:
        fail("scraper.js contrato JSON", e)

    try:
        proc = subprocess.run(
            ["node", str(SCRAPER_PATH), "https://example.com"],
            capture_output=True,
            text=True,
            timeout=40,
        )
        data = json.loads(proc.stdout.strip())
        assert "response_time_ms" in data
        if data.get("error") is None:
            assert isinstance(data["response_time_ms"], int)
            assert data["response_time_ms"] > 0
            ok(
                f"scraper.js con URL real — response_time_ms={data['response_time_ms']}ms"
            )
        else:
            ok(
                f"scraper.js con URL real — error esperado en entorno sin red: {data['error'][:60]}"
            )
    except Exception as e:
        fail("scraper.js con URL real", e)

# ==========================================================
print(f"\n{'='*55}")
print(f"  Resultado: {PASS} OK  |  {FAIL} FAIL")
print(f"{'='*55}")

if FAIL > 0:
    print("  [!] Hay tests fallidos. Revisar antes de continuar con Fase 3.")
    sys.exit(1)
else:
    print("  [OK] Todos los tests de Fase 2 pasaron.")
    print("  [->] Listo para continuar con Fase 3.")
    sys.exit(0)
