# =============================================================
# SAAF Pro — enhancements/taxonomy.py
# Categorias de problemas e indicadores tipicos (tabla del punto 1 del
# documento de mejoras) y calculo de la confianza HEURISTICA de una
# clasificacion. Funciones puras: sin BD, sin red.
#
# Reglas aprendidas del proyecto (learnings):
#   - Las palabras se buscan con LIMITE DE PALABRA: "cialis" no debe
#     coincidir dentro de "especialistas".
#   - Solo los terminos largos y sin ambiguedad (marcados sub=True) se
#     aceptan como subcadena DENTRO de URLs/dominios (mostbetindia.com).
# =============================================================

import re
import unicodedata

# Categorias (clave -> etiqueta). El orden es el de presentacion.
CATEGORY_LABELS = {
    "casino": "Casino y apuestas",
    "pharmacy": "Farmacia",
    "adult": "Contenido adulto",
    "loans_crypto": "Préstamos, cripto y forex",
    "replicas": "Réplicas y falsificaciones",
    "services": "Servicios sospechosos",
    "language": "Páginas en idiomas inesperados",
    "scripts": "Scripts o código sospechoso",
    "injected_links": "Enlaces inyectados o páginas spam",
    "external_review": "Enlaces externos por revisar",
    "other": "Otros hallazgos",
}
CATEGORY_ORDER = list(CATEGORY_LABELS)

# Categorias que son spam/abuso por naturaleza (candidatas a correccion)
SPAM_CATEGORIES = {"casino", "pharmacy", "adult", "loans_crypto", "replicas", "services"}
TOPIC_CATEGORIES = tuple(c for c in CATEGORY_ORDER if c in SPAM_CATEGORIES)

P_STRONG = 0.75
P_WEAK = 0.30

# (termino, fuerza 'S'|'W', sub: acepta subcadena dentro de URL/dominio)
_T = {
    "casino": [
        ("casino", "S", True), ("kazino", "S", True), ("gacor", "S", True), ("togel", "S", True),
        ("mostbet", "S", True), ("1win", "S", True), ("sbobet", "S", True), ("1xbet", "S", True),
        ("melbet", "S", True), ("parimatch", "S", True), ("sportsbook", "S", True),
        ("betsson", "S", True), ("bet365", "S", True), ("bwin", "S", True), ("unibet", "S", True),
        ("pokerstars", "S", True), ("draftkings", "S", True), ("fanduel", "S", True), ("betway", "S", True),
        ("baccarat", "S", True), ("roulette", "S", True), ("blackjack", "S", True),
        ("nongamstop", "S", True), ("non gamstop", "S", False), ("slot gacor", "S", False),
        ("slot online", "S", False), ("situs slot", "S", False), ("judi online", "S", False),
        ("judi bola", "S", False), ("poker online", "S", False), ("maxwin", "S", True),
        ("gambling", "S", False), ("online betting", "S", False), ("betting site", "S", False),
        ("apuestas online", "S", False), ("casino online", "S", False), ("bandar", "S", False),
        ("bet", "W", False), ("bets", "W", False), ("betting", "W", False), ("slot", "W", False),
        ("slots", "W", False), ("poker", "W", False), ("jackpot", "W", False),
        ("apuestas", "W", False), ("apuesta", "W", False), ("free spins", "W", False),
        ("wager", "W", False), ("lottery", "W", False),
    ],
    "pharmacy": [
        ("viagra", "S", True), ("kamagra", "S", True), ("levitra", "S", True),
        ("tadalafil", "S", True), ("sildenafil", "S", True), ("cialis", "S", False),
        ("no prescription", "S", False), ("without prescription", "S", False),
        ("online pharmacy", "S", False), ("canadian pharmacy", "S", False),
        ("cheap meds", "S", False), ("buy viagra", "S", False), ("buy cialis", "S", False),
        ("pharmacy", "W", False), ("pharma", "W", False), ("buy online", "W", False),
        ("pills", "W", False), ("tramadol", "W", False), ("xanax", "W", False),
        ("drugstore", "W", False), ("farmacia online", "W", False),
    ],
    "adult": [
        ("porn", "S", True), ("pornhub", "S", True), ("xvideos", "S", True), ("xnxx", "S", True),
        ("hentai", "S", True), ("xxx", "S", False), ("escort", "S", False), ("escorts", "S", False),
        ("sex cam", "S", False), ("live sex", "S", False), ("adult cam", "S", False),
        ("nudes", "S", False), ("milf", "S", False), ("erotic", "W", False),
        ("dating", "W", False), ("cam", "W", False), ("cams", "W", False), ("adult", "W", False),
        ("hookup", "W", False), ("onlyfans", "W", False), ("sex", "W", False),
    ],
    "loans_crypto": [
        ("payday loan", "S", False), ("payday loans", "S", False), ("instant loan", "S", False),
        ("bad credit loan", "S", False), ("loan approval", "S", False), ("cash buyers", "S", False),
        ("we buy houses", "S", False), ("sell your house fast", "S", False),
        ("forex signals", "S", False), ("binary options", "S", False), ("crypto casino", "S", False),
        ("bitcoin doubler", "S", False), ("crypto investment", "S", False), ("airdrop", "S", True),
        ("forex trading", "S", False),
        ("crypto", "W", False), ("bitcoin", "W", False), ("btc", "W", False), ("forex", "W", False),
        ("loan", "W", False), ("loans", "W", False), ("cash advance", "W", False),
        ("quick cash", "W", False), ("easy money", "W", False), ("ethereum", "W", False),
        ("prestamos rapidos", "W", False),
    ],
    "replicas": [
        ("replica watches", "S", False), ("replica handbags", "S", False), ("fake rolex", "S", False),
        ("rolex replica", "S", False), ("cheap jerseys", "S", False), ("cheap nfl jerseys", "S", False),
        ("louis vuitton outlet", "S", False), ("ugg outlet", "S", False), ("knockoff", "S", False),
        ("fake watches", "S", False), ("designer replica", "S", False),
        ("replica", "W", False), ("replicas", "W", False), ("rolex", "W", False),
        ("louis vuitton", "W", False), ("ugg", "W", False), ("uggs", "W", False),
        ("jerseys", "W", False), ("moncler", "W", False), ("canada goose", "W", False),
        ("ray ban", "W", False),
    ],
    "services": [
        ("essay writing", "S", False), ("write my essay", "S", False), ("cheap essay", "S", False),
        ("buy followers", "S", False), ("buy likes", "S", False), ("buy instagram followers", "S", False),
        ("seo backlinks", "S", False), ("buy backlinks", "S", False), ("hire hacker", "S", False),
        ("hire a hacker", "S", False), ("phone hacker", "S", False), ("hack instagram", "S", False),
        ("pbn links", "S", False),
        ("backlinks", "W", False), ("seo services", "W", False), ("guest post", "W", False),
        ("assignment help", "W", False), ("dissertation help", "W", False), ("paper writing", "W", False),
        ("hacker", "W", False),
    ],
}

# Si el nicho del sitio contiene alguna de estas palabras, esa categoria NO se
# considera sospechosa (un casino puede hablar de casino).
NICHE_EXEMPT = {
    "casino": ("casino", "gaming", "apuesta", "bet", "juego", "gambl", "lotter", "loteria"),
    "pharmacy": ("farmacia", "pharma", "salud", "health", "medic", "drog", "clinic", "hospital"),
    "adult": ("adult", "erotic"),
    "loans_crypto": ("financ", "fintech", "crypto", "cripto", "bank", "banco", "prestam", "loan",
                     "forex", "invers", "invest", "inmobil", "real estate", "realestate"),
    "replicas": ("moda", "fashion", "ropa", "retail", "joyer", "jewel", "reloj", "watch", "outlet"),
    "services": ("seo", "marketing", "agenc", "academ", "educa", "universi", "colegio"),
}


def strip_accents(s: str) -> str:
    return "".join(c for c in unicodedata.normalize("NFKD", s) if not unicodedata.combining(c))


_NON_ALNUM = re.compile(r"[^a-z0-9]+")


def normalize(s) -> str:
    """minusculas, sin acentos, todo lo no alfanumerico -> espacio."""
    if not s:
        return ""
    return _NON_ALNUM.sub(" ", strip_accents(str(s)).lower()).strip()


def _compile():
    out = {}
    for cat, terms in _T.items():
        items = []
        for term, strength, sub in terms:
            nt = normalize(term)
            items.append((term, nt, strength, sub, nt.replace(" ", "")))
        out[cat] = items
    return out


_COMPILED = _compile()


def niche_exempt(niche: str, category: str) -> bool:
    n = normalize(niche)
    return any(w in n for w in NICHE_EXEMPT.get(category, ()))


def find_terms(texts: dict, niche: str = "") -> dict:
    """
    Busca indicadores en `texts` ({"url": ..., "text": ...}).
      - claves que empiezan por "url": host+ruta de un recurso o pagina. Ademas
               del limite de palabra, aceptan subcadena para los terminos sub=True.
      - "text": texto libre (ancla, descripcion, fragmento): solo limite de palabra.
    Devuelve {categoria: {termino: 'S'|'W'}} (solo categorias no exentas por nicho).
    """
    norm = {k: " " + normalize(v) + " " for k, v in (texts or {}).items() if v}
    squashed = {k: normalize(v).replace(" ", "") for k, v in (texts or {}).items() if v}
    found = {}
    for cat, items in _COMPILED.items():
        if niche_exempt(niche, cat):
            continue
        for term, nt, strength, sub, flat in items:
            hit = False
            for k, n in norm.items():
                if f" {nt} " in n:
                    hit = True
                    break
                if sub and k.startswith("url") and len(flat) >= 4 and flat in squashed.get(k, ""):
                    hit = True
                    break
            if hit:
                found.setdefault(cat, {})[term] = strength
    return found


def topic_probability(terms: dict) -> float:
    """1 - prod(1 - p_i) sobre los terminos distintos encontrados."""
    q = 1.0
    for strength in terms.values():
        q *= 1.0 - (P_STRONG if strength == "S" else P_WEAK)
    return 1.0 - q


def best_topic(found: dict):
    """(categoria, probabilidad, terminos) de la categoria con mayor probabilidad, o (None, 0, {})."""
    best, best_p, best_terms = None, 0.0, {}
    for cat in TOPIC_CATEGORIES:
        terms = found.get(cat)
        if not terms:
            continue
        p = topic_probability(terms)
        if p > best_p + 1e-9:
            best, best_p, best_terms = cat, p, terms
    return best, best_p, best_terms


def combine_prob(*ps: float) -> float:
    q = 1.0
    for p in ps:
        q *= 1.0 - max(0.0, min(0.99, p))
    return 1.0 - q


def pct(p: float, cap: int = 98) -> int:
    return max(0, min(cap, int(round(p * 100))))


def label(cat: str) -> str:
    return CATEGORY_LABELS.get(cat, cat)
