# =============================================================
# SAAF Pro — enhancements/items.py
# "Elementos" (alertas) que analizan las mejoras: se construyen a partir de
# las amenazas ya clasificadas por el orquestador (sin modificarlas) mas los
# hallazgos propios (paginas en idioma inesperado, enlaces por revisar).
# Incluye la huella (fingerprint) para el historial y la clasificacion
# heuristica con porcentaje de confianza.
# =============================================================

import hashlib
import re
from urllib.parse import urlparse, parse_qs, urlencode

from url_utils import split_url, get_host

from . import taxonomy as tx

_TRACKING = {
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content",
    "fbclid", "gclid", "msclkid", "ref", "source",
}

SEV_PRIOR = {"CRITICAL": 0.85, "HIGH": 0.70, "MEDIUM": 0.50, "LOW": 0.30, "INFO": 0.15}
NON_TOPIC_CATEGORY = {
    "external_script": "scripts",
    "obfuscated_js": "scripts",
    "hidden_iframe": "scripts",
    "hidden_spam_link": "injected_links",
    "casino_pharma_adult": "injected_links",
    "broken_internal_link": "other",
    "claude_anomaly": "other",
    "unexpected_language": "language",
    "external_link_review": "external_review",
}
# Huellas tipicas de cargadores de malware en JavaScript. Ninguna basta por si sola
# (hay librerias legitimas con base64 o eval); sumadas indican un cargador malicioso.
CODE_INDICATORS = (
    ("evita_admin", re.compile(r"getElementById\(\s*['\"]wpadminbar['\"]\s*\)", re.I), 0.35,
     "no se ejecuta si hay un administrador de WordPress conectado"),
    ("anti_analisis", re.compile(r"\(\s*\+\s*new\s+Date\(\)\s*\)\s*-\s*\w+\s*>\s*\d+|Date\.now\(\)\s*-\s*\w+\s*>\s*\d+", re.I), 0.35,
     "mide tiempos para evadir el análisis automático"),
    ("cookie_control", re.compile(r"document\.cookie(\s*\|\|\s*(''|\"\"))?\s*\)?\.indexOf\(\s*['\"][A-Za-z0-9_\-]{4,}=['\"]\s*\)\s*!==?\s*-1\s*\)\s*return", re.I), 0.30,
     "usa una cookie de control para ejecutarse una sola vez"),
    ("decodificador_propio", re.compile(r"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789\+/="), 0.30,
     "incluye un decodificador base64 propio"),
    ("ejecucion_dinamica", re.compile(r"\beval\s*\(|new\s+Function\s*\(|\bFunction\s*\(\s*['\"]", re.I), 0.25,
     "ejecuta código construido dinámicamente"),
    ("cadenas_codificadas", re.compile(r"(\\x[0-9a-fA-F]{2}){6,}|(\\u[0-9a-fA-F]{4}){6,}"), 0.30,
     "contiene cadenas codificadas en hexadecimal/unicode"),
)


def code_indicators(*texts) -> list:
    """[(nombre, probabilidad, descripcion)] de las huellas de cargador malicioso halladas en los textos."""
    blob = "\n".join(t for t in texts if t)
    return [(n, p, d) for n, rx, p, d in CODE_INDICATORS if rx.search(blob)]


# Tipos que la IA puede considerar LEGITIMOS (un script de un proveedor conocido
# o un enlace externo coherente). El resto de tipos nunca se descarta por IA.
LEGIT_ELIGIBLE_TYPES = {"external_script", "external_link_review"}


# ------------------------------------------------------------------
# Normalizacion
# ------------------------------------------------------------------
def norm_page(url) -> str:
    """Misma idea que orchestrator._normalize_url_for_dedup (copiada para no importar el orquestador)."""
    if not url:
        return ""
    try:
        p = urlparse(str(url).strip())
        q = ""
        if p.query:
            params = parse_qs(p.query, keep_blank_values=True)
            q = urlencode({k: v for k, v in params.items() if k.lower() not in _TRACKING}, doseq=True)
        path = p.path
        if path != "/" and path.endswith("/"):
            path = path.rstrip("/")
        return p._replace(path=path, query=q, fragment="").geturl().lower()
    except Exception:
        return str(url).lower()


def page_path(url) -> str:
    """Ruta relativa legible (/pagina-1/) de una URL del propio sitio."""
    if not url:
        return ""
    try:
        p = urlparse(str(url))
        path = p.path or "/"
        return path + (("?" + p.query) if p.query else "")
    except Exception:
        return str(url)


def res_key(url) -> str:
    """host+ruta del recurso, sin esquema/www/query (clave estable)."""
    host, path, _ = split_url(url)
    if not host:
        return ""
    return host + (path.rstrip("/") if path and path != "/" else "")


def _snip_hash(snippet) -> str:
    return hashlib.sha1((snippet or "").strip().encode("utf-8", "ignore")).hexdigest()[:10]


def fingerprint(item: dict) -> str:
    t = item.get("threat_type") or item.get("source") or "x"
    page = norm_page(item.get("page_url"))
    res = res_key(item.get("resource_url"))
    if item.get("source") == "language":
        return f"lang|{page}"
    if item.get("source") == "link_review":
        return f"link|{res or get_host(item.get('resource_url') or '')}"
    if res:
        return f"{t}|{page}|{res}"
    return f"{t}|{page}|{_snip_hash(item.get('snippet'))}"


# ------------------------------------------------------------------
# Construccion de elementos
# ------------------------------------------------------------------
def _signals_list(signals) -> list:
    out = []
    for s in signals or []:
        out.append(s.to_dict() if hasattr(s, "to_dict") else dict(s))
    return out


def from_threats(threats: list) -> list:
    """Threat (ya con severidad) -> elementos. Se omiten INFO y las ya omitidas (falso positivo)."""
    items = []
    for t in threats or []:
        if getattr(t, "ignored", False):
            continue
        sev = getattr(t, "severity", None)
        if sev == "INFO":
            continue
        ctx = getattr(t, "extra_context", None) or {}
        items.append(
            {
                "source": "threat",
                "threat_id": None,
                "threat_type": t.threat_type,
                "severity": sev or "LOW",
                "page_url": t.url_found or "",
                "resource_url": getattr(t, "resource_url", None) or "",
                "description": t.description or "",
                "snippet": (t.code_snippet or "")[:500],
                "signals": _signals_list(getattr(t, "signals", None)),
                "hidden": bool(ctx.get("hidden")),
                "is_new_original": bool(getattr(t, "is_new", False)),
            }
        )
    return items


def language_item(page_url, lang, expected, excerpt, conf) -> dict:
    return {
        "source": "language",
        "threat_id": None,
        "threat_type": "unexpected_language",
        "severity": "MEDIUM",
        "page_url": page_url,
        "resource_url": "",
        "description": f"Página en idioma inesperado: {lang} (esperado: {', '.join(expected) or 'n/d'})",
        "snippet": (excerpt or "")[:300],
        "signals": [],
        "hidden": False,
        "lang": lang,
        "lang_conf": conf,
    }


def link_review_item(host, sample_url, pages, anchors, reason, conf) -> dict:
    return {
        "source": "link_review",
        "threat_id": None,
        "threat_type": "external_link_review",
        "severity": "LOW",
        "page_url": pages[0] if pages else "",
        "resource_url": sample_url,
        "description": f"Enlace externo por revisar: {host} — {reason}",
        "snippet": "; ".join(anchors[:3])[:300],
        "signals": [],
        "hidden": False,
        "pages": pages[:10],
        "link_conf": conf,
    }


# ------------------------------------------------------------------
# Clasificacion heuristica
# ------------------------------------------------------------------
def classify_item(item: dict, niche: str = "", spam_domains=None, page_text_terms=None) -> dict:
    """
    Rellena en `item`: category, confidence (0-100), indicators, has_indicator,
    h_confidence, h_category, reason. Heuristica pura (la IA la ajusta despues).
    """
    ttype = item["threat_type"]
    texts = {
        "url_res": (item.get("resource_url") or "") and f"{res_key(item['resource_url'])}",
        "url_page": page_path(item.get("page_url")),
        "text": " ".join(x for x in (item.get("snippet"), item.get("description")) if x),
    }
    found = tx.find_terms(texts, niche)
    if page_text_terms:  # terminos hallados en el texto de la pagina (paginas en idioma raro)
        for cat, terms in page_text_terms.items():
            found.setdefault(cat, {}).update(terms)
    cat, topic_p, terms = tx.best_topic(found)

    strong_signals = [s for s in item.get("signals", []) if s.get("strong")]
    spam_domain_hit = any(s.get("code") == "known_spam_domain" for s in item.get("signals", []))
    if not spam_domain_hit and spam_domains and item.get("resource_url"):
        host = get_host(item["resource_url"])
        if host and any(host == d or host.endswith("." + d) for d in spam_domains):
            spam_domain_hit = True

    sev_p = SEV_PRIOR.get(item.get("severity"), 0.3)
    ps = [topic_p] + [0.5] * len(strong_signals)
    if spam_domain_hit:
        ps.append(0.9)

    # Huellas de codigo malicioso (solo en elementos que son codigo)
    code_hits = []
    if ttype in ("obfuscated_js", "external_script", "hidden_iframe") and item.get("source") != "language":
        code_hits = code_indicators(item.get("snippet"), item.get("description"))
        ps += [p for _, p, _ in code_hits]

    # El motor original marco la URL de la PROPIA pagina por un patron, pero no hay terminos de spam:
    # casi siempre es un articulo legitimo. Se informa con confianza baja, sin proponer acciones.
    self_ref = False
    if ttype == "casino_pharma_adult" and not terms and not strong_signals and not spam_domain_hit and item.get("resource_url"):
        try:
            self_ref = bool(get_host(item["resource_url"])) and get_host(item["resource_url"]) == get_host(item.get("page_url") or "")
        except Exception:
            self_ref = False

    if item.get("source") == "language":
        ps.append(0.45)  # idioma distinto al esperado: indicio, no prueba
    elif item.get("source") == "link_review":
        ps = [item.get("link_conf", 0.5) / 100.0, topic_p]
    elif self_ref:
        ps = [0.12]
    else:
        ps.append(0.6 * sev_p)  # la severidad que ya calculo el sistema pesa, pero no manda

    if cat is None:
        cat = "other" if self_ref else NON_TOPIC_CATEGORY.get(ttype, "other")
    p = tx.combine_prob(*ps)

    # Recurso externo sin ninguna evidencia de riesgo (solo la severidad base): no es un «script sospechoso»,
    # es un recurso de terceros por revisar. Se separa para no diluir el porcentaje de los scripts realmente sospechosos.
    if (cat == "scripts" and ttype in ("external_script", "hidden_iframe") and not terms and not strong_signals
            and not spam_domain_hit and len(code_hits) < 2 and tx.pct(p) < 50):
        cat = "external_review"

    indicators = [t for t in terms] + [n for n, _, _ in code_hits]
    reason_bits = []
    if code_hits:
        reason_bits.append("el código " + "; ".join(d for _, _, d in code_hits[:3]))
    if self_ref:
        reason_bits.append("la URL de la propia página coincidió con un patrón pero no contiene términos de spam (posible falso positivo)")
    if terms:
        reason_bits.append("indicadores: " + ", ".join(sorted(terms)[:5]))
    if strong_signals:
        reason_bits.append("señales: " + "; ".join(s.get("label", "") for s in strong_signals[:2]))
    if spam_domain_hit:
        reason_bits.append("dominio en la lista de spam")
    if item.get("source") == "language":
        reason_bits.append(item["description"])

    item.update(
        category=cat,
        h_category=cat,
        h_confidence=tx.pct(p),
        confidence=tx.pct(p),
        indicators=indicators,
        # separados para poder redactarlos: los terminos se citan tal cual
        # ("casino, bet, slot") y las huellas de codigo con su descripcion.
        terms=sorted(terms),
        code_notes=[d for _, _, d in code_hits],
        has_indicator=bool(
            terms or strong_signals or spam_domain_hit or len(code_hits) >= 2
            or (item.get("severity") in ("CRITICAL", "HIGH") and not self_ref)
            or item.get("source") == "language"
        ),
        # corroboracion deterministica fuerte (la IA sola no basta para corregir solo)
        corroborated=bool(terms or strong_signals or spam_domain_hit or len(code_hits) >= 2
                          or item.get("source") == "language"),
        reason="; ".join(reason_bits),
    )
    return item


def combine_with_ai(item: dict, ai_cat, ai_conf, ai_legit: bool = False):
    """
    Mezcla heuristica + IA para un elemento:
      - coinciden en categoria      -> promedio + 5 puntos de acuerdo.
      - discrepan                   -> prevalece la heuristica si tiene indicadores,
                                       con confianza min(h, ia) - 10.
      - la heuristica es generica   -> se toma la categoria de la IA (promedio).
      - sin corroboracion fuerte    -> tope 60 (la IA sola no corrige automaticamente).
    """
    h, h_cat = item["h_confidence"], item["h_category"]
    generic = h_cat in ("injected_links", "scripts", "other", "external_review")
    if ai_cat in (None, ""):
        return
    ai_conf = max(0, min(100, int(ai_conf)))
    if ai_cat == h_cat:
        conf, cat = min(98, round((h + ai_conf) / 2) + 5), h_cat
    elif generic and ai_cat in tx.CATEGORY_LABELS:
        conf, cat = round((h + ai_conf) / 2), ai_cat
    else:
        conf, cat = max(0, min(h, ai_conf) - 10), h_cat
    if not item.get("corroborated"):
        conf = min(conf, 60)
    item["category"], item["confidence"] = cat, conf
    item["ai_category"], item["ai_confidence"] = ai_cat, ai_conf
