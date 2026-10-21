#!/home/admin_ubuntu/Desktop/proyecto_saaf/opt/saaf/venv/bin/python
# =============================================================
# SAAF Pro — claude_analyzer.py
# Analisis inteligente de HTML con Claude API (Anthropic).
# Se activa solo si analyzer.py detecto amenazas previas,
# o si force=True. Falla de forma controlada sin crashear el ciclo.
# Ruta: /home/admin_ubuntu/Desktop/proyecto_saaf/opt/saaf/claude_analyzer.py
# =============================================================

import os
import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

_ENV_PATH = Path("/home/admin_ubuntu/Desktop/proyecto_saaf/opt/saaf/config/saaf.env")

def _load_api_key() -> str:
    """
    Obtiene ANTHROPIC_API_KEY de forma robusta contra CRLF de Windows:
      1. Del entorno (os.environ), limpiando \r, \n, comillas y espacios.
      2. Si está vacía, lee saaf.env directamente y lo limpia.
    Inmune a archivos .env editados en Windows (terminaciones CRLF).
    """
    key = os.environ.get("ANTHROPIC_API_KEY", "")
    key = key.strip().strip("\r").strip("\n").strip().strip('"').strip("'")
    if key:
        return key

    if _ENV_PATH.exists():
        try:
            for raw_line in _ENV_PATH.read_text(encoding="utf-8").splitlines():
                line = raw_line.strip()
                if line.startswith("export "):
                    line = line[len("export "):].strip()
                if line.startswith("ANTHROPIC_API_KEY="):
                    val = line.split("=", 1)[1]
                    val = val.strip().strip('"').strip("'").strip("\r").strip()
                    if val:
                        logger.info("API key cargada desde saaf.env (%d chars)", len(val))
                        return val
        except Exception as e:
            logger.warning("No se pudo leer saaf.env: %s", e)
    return ""

# Maximo de caracteres de HTML enviados a Claude (controla tokens/costo)
MAX_HTML_CHARS = 15_000
# Maximo de tokens en la respuesta de Claude
CLAUDE_MAX_TOKENS = 1_000
# Modelo a usar
CLAUDE_MODEL = "claude-sonnet-4-6"

# Timeout por solicitud y reintentos. SIN esto el SDK espera hasta 10 min por
# intento: una API colgada dejaba la auditoria "RUNNING" durante media hora o
# mas. Peor caso ahora: (1 + CLAUDE_MAX_RETRIES) x CLAUDE_TIMEOUT_S segundos.
CLAUDE_TIMEOUT_S = float(os.environ.get("SAAF_CLAUDE_TIMEOUT", "60"))
CLAUDE_MAX_RETRIES = int(os.environ.get("SAAF_CLAUDE_MAX_RETRIES", "1"))

# TTL del cache de prompt. Se usa "1h" (en vez del default de 5 min) porque
# un ciclo completo (run_cycle) puede tardar 10-40 minutos recorriendo
# todos los sitios activos, y Claude solo se invoca para los sitios que
# ya tienen amenazas detectadas por patrones — el tiempo entre una llamada
# y la siguiente puede superar facilmente los 5 minutos del cache default.
CACHE_TTL = "1h"

# =============================================================
# System prompt ESTATICO — se envia identico en cada llamada y se marca
# con cache_control para que Claude lo cachee del lado del servidor.
#
# IMPORTANTE sobre cache_control (prompt caching de Anthropic):
#   - NO es un parametro top-level de client.messages.create(). Va dentro
#     de un bloque de contenido, tipicamente en la lista `system=[...]`.
#   - Solo se cachea si el bloque marcado supera el minimo de tokens del
#     modelo (1024 tokens para la familia Claude Sonnet 4.x). Un texto mas
#     corto se procesa normalmente sin error, pero SIN ahorro de costo.
#     Por eso este prompt se escribio de forma extensa (taxonomia completa
#     + ejemplos), no como relleno artificial sino como contexto que ademas
#     mejora la consistencia de las respuestas.
#   - La parte variable de cada sitio (nombre, URL, HTML) va en `messages`,
#     NUNCA en este bloque — si se mezclara aqui, el prefijo cambiaria en
#     cada llamada y nunca habria un cache hit.
#
# Efecto esperado: dentro de un mismo ciclo (run_cycle recorre los sitios
# activos uno por uno), la 1ra llamada a Claude paga el "cache write"
# (1.25x-2x el costo de esos tokens) y CADA llamada siguiente dentro de la
# ventana del TTL paga solo 0.1x por ese bloque en vez del precio completo.
# Con varios sitios por ciclo, el ahorro neto es real desde el 2do sitio.
# =============================================================

CLAUDE_SYSTEM_PROMPT = """Eres un analista de seguridad web experto, integrado como segunda capa de \
analisis dentro de SAAF Pro, un sistema automatizado de monitoreo de sitios web. Tu trabajo es revisar \
el HTML de una pagina y decidir si contiene anomalias de seguridad reales, actuando como confirmacion \
o complemento de un analizador de patrones que ya corrio antes que tu.
 
## Contexto de la arquitectura
 
En cada auditoria, un analizador de patrones (regex y heuristicas) revisa primero el HTML y detecta \
amenazas conocidas. Tu analisis se activa solo cuando ese analizador ya encontro algo sospechoso (o, en \
modo forzado, aunque no haya encontrado nada). Tu valor agregado es detectar cosas que un regex no puede: \
intencion, ofuscacion sofisticada, combinaciones de senales debiles que juntas son sospechosas, y \
confirmar o descartar lo que el analizador de patrones ya marco.
 
## Taxonomia de amenazas que debes reconocer
 
Usa exactamente estos valores en el campo "threat_type" cuando apliquen. Si una anomalia no encaja en \
ninguno, usa "claude_anomaly".
 
1. **hidden_spam_link** — Enlaces ocultos (display:none, visibility:hidden, posicionados fuera de \
   pantalla, con texto en color igual al fondo, o con tamano de fuente casi cero) que apuntan a dominios \
   de casino, apuestas, farmacia no regulada, contenido para adultos o prestamos predatorios. Suelen \
   inyectarse en el footer o al final del <body> tras una intrusion.
2. **external_script** — Etiquetas <script src="..."> que cargan codigo desde dominios externos \
   desconocidos o previamente identificados como maliciosos, especialmente si no corresponden a \
   proveedores legitimos conocidos (CDNs, analitica, fuentes, pasarelas de pago, chat en vivo).
3. **hidden_iframe** — <iframe> con dimensiones de 0/1 pixel, position:absolute fuera del viewport, o \
   display:none, usados tipicamente para cargar contenido malicioso o hacer clickjacking sin que el \
   visitante lo note.
4. **obfuscated_js** — JavaScript deliberadamente ofuscado: eval(atob(...)), cadenas codificadas en \
   base64 que se decodifican y ejecutan, nombres de variable ilegibles generados automaticamente, \
   fragmentacion de strings para evadir deteccion, o codigo empaquetado (packer) sin razon aparente.
5. **broken_internal_link** — Enlaces internos que aun apuntan a un dominio antiguo del sitio (indicando \
   una migracion incompleta) o a rutas que ya no existen, lo cual puede ser aprovechado para secuestro \
   de subdominio o para minar la confianza/SEO del sitio.
6. **casino_pharma_adult** — URLs indexadas (en sitemap o enlazadas) cuyo path o parametros contienen \
   patrones de spam de casino, apuestas, farmacia, contenido adulto o similares, sugiriendo que el sitio \
   fue comprometido para alojar paginas doorway de SEO spam.
7. **claude_anomaly** — Cualquier otra anomalia de seguridad real que detectes y que no encaje en las \
   categorias anteriores: codigo malicioso generico, redirects sospechosos (window.location a dominios \
   desconocidos condicionado a user-agent de buscador), señales de exfiltracion de datos (formularios \
   que envian datos a un dominio distinto al del sitio sin razon legitima), o senales de phishing \
   (formularios de login duplicados/falsos, imitacion de otra marca).
 
## Que NO debes reportar (evita falsos positivos)
 
No marques como amenaza: scripts de analitica conocidos (Google Analytics, Google Tag Manager, Meta \
Pixel, Hotjar), CDNs de librerias legitimas (jQuery, Bootstrap, Cloudflare, jsDelivr, unpkg), widgets de \
chat en vivo o soporte (Intercom, Tawk.to, WhatsApp Business), fuentes web (Google Fonts, Adobe Fonts), \
pasarelas de pago reconocidas (Stripe, PayPal, MercadoPago), pixeles de remarketing de plataformas de \
publicidad legitimas, ni minificacion/empaquetado estandar de JS moderno (webpack, vite, terser) que solo \
comprime codigo sin ocultar intencion maliciosa. La minificacion NO es lo mismo que ofuscacion: el codigo \
minificado es ilegible por compresion, el ofuscado esta deliberadamente disenado para esconder que hace.
 
## Metodologia
 
1. Lee el HTML completo prestando atencion a: el <head>, scripts inline y externos, iframes, comentarios \
   HTML sospechosos, atributos style con display:none/visibility:hidden/posicionamiento fuera de pantalla, \
   y el pie de pagina (donde suele inyectarse spam).
2. Contrasta con los tipos de amenaza que el analizador de patrones ya reporto (se te indicaran) — \
   confirma si el contexto en el HTML respalda esa deteccion, la descartas (falso positivo del regex), o \
   encuentras anomalias adicionales relacionadas.
3. Se conservador: reporta solo cuando tengas evidencia razonable en el propio HTML, no especules sobre \
   intenciones sin señales concretas.
 
## Formato de salida — OBLIGATORIO
 
Responde UNICAMENTE con un objeto JSON valido, sin bloques de markdown (sin ```), sin texto antes ni \
despues. La estructura exacta es:
 
{
  "has_anomalies": true,
  "reasoning": "Explicacion breve en espanol de lo encontrado (1-2 frases)",
  "anomalies": [
    {
      "threat_type": "uno_de_los_7_valores_de_la_taxonomia",
      "description": "Descripcion especifica y concreta de la anomalia encontrada",
      "code_snippet": "Fragmento literal del HTML/JS sospechoso, recortado si es muy largo",
      "url_found": "URL de la pagina donde se encontro, si se puede determinar"
    }
  ]
}
 
Si no encuentras anomalias adicionales a las ya reportadas por el analizador de patrones, responde \
exactamente:
 
{"has_anomalies": false, "reasoning": "Sin anomalias adicionales detectadas", "anomalies": []}
 
## Ejemplos de referencia
 
Ejemplo 1 — entrada relevante: un <div style="position:absolute;left:-9999px"> conteniendo varios <a> \
hacia dominios de apuestas. Salida esperada:
{"has_anomalies": true, "reasoning": "Se confirma spam de casino oculto fuera de pantalla en el footer.", \
"anomalies": [{"threat_type": "hidden_spam_link", "description": "Bloque posicionado fuera de pantalla \
(left:-9999px) con 6 enlaces a dominios de apuestas online", "code_snippet": "<div style=\\"position:\
absolute;left:-9999px\\">...</div>", "url_found": "https://ejemplo.com/"}]}
 
Ejemplo 2 — entrada relevante: HTML normal de un blog corporativo, con Google Analytics, Google Fonts y \
un formulario de contacto que envia por POST al mismo dominio. Salida esperada:
{"has_anomalies": false, "reasoning": "Sin anomalias adicionales detectadas", "anomalies": []}"""


# =============================================================
# Resultado del analisis de Claude
# =============================================================


class ClaudeResult:
    """
    Resultado del analisis de Claude API.

    Atributos:
        triggered:    True si Claude fue invocado (habia HTML y amenazas previas).
        has_anomalies: True si Claude encontro anomalias nuevas.
        anomalies:    Lista de dicts con threat_type, description, code_snippet.
        reasoning:    Explicacion de Claude.
        error:        Mensaje tecnico del error si fallo la llamada (None si OK).
        error_code:   Codigo estable (credits, auth, rate_limit, timeout,
                      connection, provider, invalid_response, internal) o
                      'not_configured' si no hay API key (NO es una falla).
        error_human:  Mensaje claro en español para mostrar al usuario.
    """

    def __init__(
        self, triggered=False, anomalies=None, reasoning="", error=None,
        error_code=None, error_human=None,
    ):
        self.triggered = triggered
        self.anomalies = anomalies or []
        self.reasoning = reasoning
        self.error = error
        self.error_code = error_code
        self.error_human = error_human
        
    @property
    def failed(self) -> bool:
        """True si Claude se invoco y FALLO (no cuenta 'sin API key')."""
        return bool(self.error) and self.error_code != "not_configured"

    def has_anomalies(self) -> bool:
        return bool(self.anomalies)

    def __repr__(self):
        return (
            f"ClaudeResult(triggered={self.triggered}, "
            f"anomalies={len(self.anomalies)}, error={self.error!r})"
        )


# =============================================================
# Funcion principal
# =============================================================


def analyze(
    html_results: list, site: dict, pattern_threats: list = None, force: bool = False
) -> ClaudeResult:
    """
    Envia el HTML del sitio a Claude API para analisis contextual.

    Args:
        html_results:    Lista de dicts {html, url, error, ...} del scraper.
        site:            Dict del sitio (name, url, niche).
        pattern_threats: Lista de objetos Threat de analyzer.py (puede estar vacia).
        force:           Si True, analiza aunque no haya amenazas previas.

    Returns:
        ClaudeResult con anomalias encontradas por Claude.
        Si falla (sin API key, error de red, JSON invalido),
        retorna ClaudeResult(triggered=False, error=mensaje).
    """
    # --- Condiciones de activacion ---
    has_html = any(r.get("html") for r in html_results if not r.get("error"))
    has_threats = bool(pattern_threats)

    if not has_html:
        logger.debug("[%s] Claude: sin HTML disponible, omitiendo", site.get("name"))
        return ClaudeResult(triggered=False)

    if not has_threats and not force:
        logger.debug(
            "[%s] Claude: sin amenazas previas y force=False, omitiendo",
            site.get("name"),
        )
        return ClaudeResult(triggered=False)

    # --- Verificar API key ---
    api_key = _load_api_key()
    if not api_key:
        logger.warning(
            "[%s] Claude: ANTHROPIC_API_KEY no configurada", site.get("name")
        )
        return ClaudeResult(
            triggered=False,
            error="ANTHROPIC_API_KEY no configurada",
            error_code="not_configured",
            error_human="Análisis con IA omitido: ANTHROPIC_API_KEY no configurada.",
        )
    if not api_key.startswith("sk-ant-"):
        logger.warning("[%s] Claude: API key con formato raro — revisar caracteres invisibles", site.get("name"))

    # --- Preparar HTML concatenado (limitado a MAX_HTML_CHARS) ---
    html_chunks = []
    total_chars = 0
    for r in html_results:
        if r.get("error") or not r.get("html"):
            continue
        chunk = r["html"][: MAX_HTML_CHARS - total_chars]
        html_chunks.append(f"<!-- URL: {r.get('url', 'desconocida')} -->\n{chunk}")
        total_chars += len(chunk)
        if total_chars <= MAX_HTML_CHARS:
            break

    html_combined = "\n\n".join(html_chunks)

    # --- Preparar lista de amenazas ya detectadas ---
    threat_types_found = list({t.threat_type for t in (pattern_threats or [])})

    # --- Construir la parte VARIABLE del prompt (nunca se cachea) ---
    # Solo va aqui lo que cambia sitio a sitio / ciclo a ciclo: datos del
    # sitio, amenazas ya detectadas por patrones y el HTML. El resto de
    # las instrucciones (fijas) viven en CLAUDE_SYSTEM_PROMPT — ver nota
    # de cache_control mas arriba en el modulo.
    user_prompt = f"""Sitio: {site.get('name', '')}
URL: {site.get('url', '')}
Nicho: {site.get('niche', 'general')}
 
El analizador de patrones ya detecto estos tipos de amenazas: {threat_types_found if threat_types_found else 'ninguna'}
 
HTML a analizar:
{html_combined}
 
Responde con el JSON segun el formato y la taxonomia indicados en las instrucciones."""

    # --- Llamar a Claude API ---
    try:
        import anthropic

        client = anthropic.Anthropic(
            api_key=api_key, timeout=CLAUDE_TIMEOUT_S, max_retries=CLAUDE_MAX_RETRIES
        )
        message = client.messages.create(
            model=CLAUDE_MODEL,
            max_tokens=CLAUDE_MAX_TOKENS,
            # El bloque de sistema es el UNICO marcado con cache_control.
            # cache_control va en el bloque de contenido, no como parametro
            # top-level de .create() (asi documentado por Anthropic).
            system=[
                {
                    "type": "text",
                    "text": CLAUDE_SYSTEM_PROMPT,
                    "cache_control": {"type": "ephemeral", "ttl": CACHE_TTL},
                }
            ],
            messages=[{"role": "user", "content": user_prompt}],
        )
        response_text = message.content[0].text.strip()
        logger.debug(
            "[%s] Claude respuesta: %s...", site.get("name"), response_text[:100]
        )
        
        # --- Log de uso de cache — util para verificar el ahorro real ---
        # cache_read_input_tokens > 0  => este llamado reutilizo el cache (barato)
        # cache_creation_input_tokens > 0 => este llamado escribio el cache (mas caro que un input normal, pero se paga una sola vez por ventana de TTL)
        usage = getattr(message, "usage", None)
        if usage is not None:
            cache_read = getattr(usage, "cache_read_input_tokens", 0) or 0
            cache_write = getattr(usage, "cache_creation_input_tokens", 0) or 0
            fresh_input = getattr(usage, "input_tokens", 0) or 0
            logger.info(
                "[%s] Claude tokens — cache_read=%d, cache_write=%d, sin_cache=%d, output=%d",
                site.get("name"),
                cache_read,
                cache_write,
                fresh_input,
                getattr(usage, "output_tokens", 0) or 0,
            )
            if cache_read == 0 and cache_write == 0:
                logger.debug(
                    "[%s] Sin actividad de cache — normal en la 1ra llamada de la ventana, "
                    "o si el bloque de sistema no alcanza el minimo cacheable del modelo.",
                    site.get("name"),
                )

    except ImportError:
        logger.error("anthropic SDK no instalado — ejecutar: pip install anthropic")
        return ClaudeResult(
            triggered=True,
            error="anthropic SDK no instalado",
            error_code="internal",
            error_human="El SDK de anthropic no está instalado en el servidor.",
        )

    except Exception as e:
        from audit_state import classify_exception

        code, human = classify_exception(e, "el proveedor de IA")
        logger.error("[%s] Claude API error (%s): %s", site.get("name"), code, e)
        return ClaudeResult(triggered=True, error=str(e), error_code=code, error_human=human)

    # --- Parsear respuesta JSON ---
    try:
        # Limpiar posibles backticks de markdown si Claude los incluye
        clean = response_text.strip()
        if clean.startswith("```"):
            clean = "\n".join(clean.split("\n")[1:])
        if clean.endswith("```"):
            clean = "\n".join(clean.split("\n")[:-1])
        clean = clean.strip()

        data = json.loads(clean)
        anomalies = data.get("anomalies", [])
        reasoning = data.get("reasoning", "")
        has_anom = data.get("has_anomalies", False)

        logger.info(
            "[%s] Claude: %d anomalias — %s",
            site.get("name"),
            len(anomalies),
            reasoning[:80],
        )

        return ClaudeResult(
            triggered=True, anomalies=anomalies if has_anom else [], reasoning=reasoning
        )

    except (json.JSONDecodeError, KeyError, TypeError) as e:
        logger.error("[%s] Claude: respuesta JSON invalida: %s", site.get("name"), e)
        return ClaudeResult(
            triggered=True,
            error=f"JSON invalido en respuesta de Claude: {e}",
            error_code="invalid_response",
            error_human="Respuesta inválida del proveedor de IA (no es JSON).",
        )


# =============================================================
# Entrypoint
# =============================================================

if __name__ == "__main__":
    import sys

    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s"
    )

    print("\n=== SAAF Pro — Claude Analyzer (test) ===\n")

    api_key = os.environ.get("ANTHROPIC_API_KEY", "")
    if not api_key:
        print("[INFO] ANTHROPIC_API_KEY no configurada — se simulara una respuesta.")
        print("       Para test real: export ANTHROPIC_API_KEY='sk-ant-...'")
        print()
        # Simular respuesta sin API key
        result = ClaudeResult(triggered=False, error="ANTHROPIC_API_KEY no configurada")
        print(f"Resultado: {result}")
        print("[OK] claude_analyzer.py importable y funcional (sin API key)")
        sys.exit(0)

    # Test real con HTML sintetico
    test_html = [
        {
            "html": '<html><body><script>eval(atob("dGVzdA=="))</script></body></html>',
            "url": "https://test.com",
            "error": None,
        }
    ]
    test_site = {"name": "Test", "url": "https://test.com", "niche": "blog"}

    # Simular una amenaza previa para activar Claude
    class FakeThreat:
        threat_type = "obfuscated_js"

    result = analyze(test_html, test_site, pattern_threats=[FakeThreat()], force=False)

    print(f"triggered: {result.triggered}")
    print(f"has_anomalies: {result.has_anomalies()}")
    print(f"reasoning: {result.reasoning}")
    print(f"anomalies: {len(result.anomalies)}")
    print(f"error: {result.error}")
    if result.has_anomalies():
        for a in result.anomalies:
            print(f"  [{a.get('threat_type')}] {a.get('description', '')[:80]}")
