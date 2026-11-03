# =============================================================
# SAAF Pro — enhancements/links.py
# Inventario de ENLACES EXTERNOS del sitio y veredicto de coherencia.
#
# Un enlace externo NO es una alerta por si mismo (ej.: una empresa de
# cercas cita municipios, permisos, asociaciones, fabricantes). Aqui se
# agrupan los enlaces por dominio y se decide cuales son coherentes (quedan
# registrados como "recurso analizado y valido") y cuales requieren revision.
#
# Este modulo da el veredicto HEURISTICO. La IA (ai_context.py) puede
# confirmarlo o escalarlo a "revisar", pero NUNCA puede marcar como legitimo
# un dominio que la heuristica considera de riesgo (hard_bad): un texto
# inyectado en la pagina no debe poder convencer a la IA de que un enlace
# spam es bueno.
# =============================================================

import re

from bs4 import BeautifulSoup

from url_utils import split_url, registrable_domain, get_host

from . import taxonomy as tx
from .items import res_key

MAX_DOMAINS = 150

# Dominios registrables generalmente legitimos para citar desde un sitio de empresa.
TRUSTED_DOMAINS = {
    "facebook.com", "instagram.com", "youtube.com", "youtu.be", "linkedin.com", "twitter.com",
    "x.com", "tiktok.com", "pinterest.com", "wa.me", "whatsapp.com", "t.me", "telegram.org",
    "google.com", "goo.gl", "g.page", "maps.app.goo.gl", "apple.com", "microsoft.com",
    "wikipedia.org", "github.com", "wordpress.org", "wordpress.com", "gravatar.com",
    "yelp.com", "bbb.org", "trustpilot.com", "angi.com", "houzz.com", "nextdoor.com",
    "schema.org", "w3.org", "mozilla.org", "creativecommons.org",
}
_GOV_EDU_RE = re.compile(r"(^|\.)(gov|edu|mil|gob|gouv|int)(\.[a-z]{2})?$")


def _is_trusted(reg: str) -> bool:
    return reg in TRUSTED_DOMAINS or bool(_GOV_EDU_RE.search(reg))


def extract_external_links(html_results: list, site_url: str, old_domains=None) -> dict:
    """
    {dominio_registrable: info} con los enlaces <a href> a dominios ajenos al sitio.
    No toma en cuenta los dominios antiguos del sitio (los cubre otro detector).
    """
    from analyzer import _is_hidden_or_ancestor_hidden  # import perezoso

    site_reg = registrable_domain(get_host(site_url))
    old = {registrable_domain(d.strip().lower()) for d in (old_domains or []) if d and d.strip()}
    out = {}
    for res in html_results or []:
        html, page = res.get("html"), res.get("url") or site_url
        if res.get("error") or not html:
            continue
        try:
            soup = BeautifulSoup(html, "html.parser")
        except Exception:
            continue
        for a in soup.find_all("a", href=True):
            href = (a.get("href") or "").strip()
            if not href.startswith(("http://", "https://", "//")):
                continue
            if href.startswith("//"):
                href = "https:" + href
            host = get_host(href)
            if not host:
                continue
            reg = registrable_domain(host)
            if not reg or reg == site_reg or reg in old:
                continue
            info = out.setdefault(
                reg,
                {"host": reg, "sample_url": href, "sample_urls": [], "links_count": 0, "pages": [],
                 "anchors": [], "hidden_count": 0},
            )
            info["links_count"] += 1
            if page not in info["pages"]:
                info["pages"].append(page)
            if href not in info["sample_urls"] and len(info["sample_urls"]) < 5:
                info["sample_urls"].append(href)
            text = a.get_text(" ", strip=True)[:80]
            if text and text not in info["anchors"] and len(info["anchors"]) < 8:
                info["anchors"].append(text)
            try:
                if _is_hidden_or_ancestor_hidden(a):
                    info["hidden_count"] += 1
            except Exception:
                pass
    return out


def heuristic_verdicts(domains: dict, niche: str = "", spam_domains=None, site_url: str = "") -> list:
    """Lista de dicts (uno por dominio) con verdict/confidence/reason, ordenada por n.o de enlaces."""
    from risk_signals import evaluate_resource, LINK

    spam_domains = set(spam_domains or [])
    spam_regex = re.compile(
        r"\b(" + "|".join(sorted({t for cat in tx.TOPIC_CATEGORIES for t, s, _ in tx._T[cat] if s == "S"},
                                  key=len, reverse=True)).replace(" ", r"\s") + r")\b", re.I
    )
    base = get_host(site_url)
    rows = []
    for reg, info in sorted(domains.items(), key=lambda kv: -kv[1]["links_count"])[:MAX_DOMAINS]:
        found = tx.find_terms(
            {"url": res_key(info["sample_url"]), "text": " ".join(info["anchors"])}, niche
        )
        topic_cat, topic_p, terms = tx.best_topic(found)
        is_spam_dom = any(reg == d or reg.endswith("." + d) or d.endswith("." + reg) for d in spam_domains)
        try:
            signals = evaluate_resource(
                info["sample_url"], LINK, base_domain=base, is_spam_domain=is_spam_dom,
                spam_pattern=spam_regex,
            )
        except Exception:
            signals = []
        strong = [s for s in signals if s.strong]
        trusted = _is_trusted(reg)
        hard_bad = bool(is_spam_dom or strong or (topic_p >= 0.6 and not trusted))

        verdict, reason = "legit", ""
        p = 0.0
        if hard_bad:
            verdict = "review"
            p = tx.combine_prob(topic_p, *([0.5] * len(strong)), 0.9 if is_spam_dom else 0.0)
            bits = []
            if is_spam_dom:
                bits.append("dominio en la lista de spam")
            if terms:
                bits.append("indicadores: " + ", ".join(sorted(terms)[:4]))
            bits += [s.label for s in strong[:2]]
            reason = "; ".join(bits) or "señales de riesgo"
        elif info["hidden_count"] and not trusted:
            verdict, p = "review", 0.6
            reason = f"{info['hidden_count']} enlace(s) oculto(s) con CSS hacia un dominio no reconocido"
        elif trusted:
            p = 0.9
            reason = "dominio institucional o plataforma conocida"
        else:
            p = 0.6
            reason = "sin indicios de riesgo, pero su coherencia con el negocio no se ha verificado"
        rows.append(
            {
                "host": reg,
                "sample_url": info["sample_url"],
                "sample_urls": info["sample_urls"],
                "links_count": info["links_count"],
                "pages_count": len(info["pages"]),
                "sample_pages": info["pages"][:5],
                "all_pages": info["pages"],
                "anchors": info["anchors"],
                "hidden_count": info["hidden_count"],
                "verdict": verdict,
                "confidence": tx.pct(p),
                "reason": reason,
                "source": "heuristic",
                "hard_bad": hard_bad,
                "trusted": trusted,
                "category": topic_cat,
            }
        )
    return rows


def apply_ai_verdicts(rows: list, ai_links: list) -> int:
    """Aplica los veredictos de la IA sobre las filas heuristicas. Devuelve cuantas cambiaron."""
    by_host = {r["host"]: r for r in rows}
    changed = 0
    for v in ai_links or []:
        host = str(v.get("domain") or v.get("host") or "").strip().lower()
        row = by_host.get(host)
        if not row:
            continue
        verdict = str(v.get("verdict") or "").lower()
        if verdict not in ("legit", "review"):
            continue
        conf = max(0, min(100, int(v.get("confidence") or 0)))
        reason = str(v.get("reason") or "")[:240]
        if verdict == "legit" and row["hard_bad"]:
            continue  # la IA no puede absolver lo que la heuristica considera de riesgo
        if verdict != row["verdict"]:
            changed += 1
        row["verdict"] = verdict
        row["confidence"] = conf if conf else row["confidence"]
        if reason:
            row["reason"] = reason
        row["source"] = "ia"
    return changed


def is_confirmed(row: dict) -> bool:
    """
    Un dominio "legit" puede serlo por dos motivos muy distintos:
      * CONFIRMADO: es institucional (.gov/.edu) o una plataforma conocida, lo
        declaro la campania como servicio de terceros, o la IA lo juzgo coherente.
      * NO VERIFICADO: simplemente no muestra indicios de riesgo. No es alerta,
        pero decir que "es coherente con la actividad del sitio" seria inexacto.
    """
    return row["verdict"] == "legit" and (bool(row.get("trusted")) or row.get("source") in ("ia", "campaña"))


def summarize(rows: list) -> dict:
    legit = [r for r in rows if r["verdict"] == "legit"]
    review = [r for r in rows if r["verdict"] == "review"]
    confirmed = [r for r in legit if is_confirmed(r)]
    unverified = [r for r in legit if not is_confirmed(r)]
    return {
        "domains": len(rows),
        "links": sum(r["links_count"] for r in rows),
        "legit": len(legit),          # total que NO es alerta (confirmados + no verificados)
        "review": len(review),
        "confirmed": len(confirmed),  # coherencia respaldada (institucional, declarado o IA)
        "unverified": len(unverified),
        "legit_hosts": [r["host"] for r in legit],
        "review_hosts": [r["host"] for r in review],
        "confirmed_hosts": [r["host"] for r in confirmed],
        "unverified_hosts": [r["host"] for r in unverified],
    }
