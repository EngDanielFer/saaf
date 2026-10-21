# =============================================================
# SAAF Pro — enhancements/language.py
# Deteccion ligera de idioma (sin dependencias) para encontrar paginas en
# idiomas inesperados (tipico del spam SEO inyectado: indonesio, ruso, chino...).
#
# Estrategia:
#   1. Por escritura (cirilico, CJK, arabe, tailandes...) -> idioma aproximado.
#   2. Para escritura latina: puntaje por palabras funcionales (stopwords).
#   3. Si no hay texto suficiente se usa el atributo <html lang>, o 'unknown'.
# No pretende ser perfecto: solo senala paginas CLARAMENTE distintas al
# idioma esperado; la decision final pasa por la confianza y la autorizacion.
# =============================================================

import re
from collections import Counter

from .taxonomy import normalize

MIN_TOKENS = 25

_STOP = {
    "es": "de la que el en y a los se del las un por con no una su para es al lo como mas pero sus le ya o este si porque esta entre cuando muy sin sobre tambien me hasta hay donde quien desde todo nos durante todos uno les ni contra otros ese eso ante ellos e esto mi antes algunos que unos yo otro otras otra el tanto esa estos mucho quienes nada muchos cual poco ella estar estas algunas algo nosotros servicios nuestro contacto".split(),
    "en": "the of and to in is you that it he was for on are as with his they i at be this have from or one had by word but not what all were we when your can said there use an each which she do how their if will up other about out many then them these so some her would make like him into time has look two more write go see number no way could people my than first water been call who oil its now find long down day did get come made may part our services contact buy best free order cheap shipping worldwide".split(),
    "pt": "de a o que e do da em um para e com nao uma os no se na por mais as dos como mas foi ao ele das tem seu sua ou ser quando muito ha nos ja esta eu tambem so pelo pela ate isso ela entre era depois sem mesmo aos ter seus quem nas me esse eles estao voce tinha foram essa num nem suas meu as minha tem numa pelos elas havia seja qual sera nos tenho lhe deles essas esses pelas este fosse dele servicos contato".split(),
    "fr": "de la le et les des en un du une que est pour qui dans a par plus pas au sur ne se ce il sont les ou avec son mais comme on nous vous leur ses elle etre cette aux fait tout ete ont deux sans sous entre aussi tres bien services contactez".split(),
    "de": "der die und in den von zu das mit sich des auf fur ist im dem nicht ein eine als auch es an werden aus er hat dass sie nach wird bei einer um am sind noch wie einem uber einen so zum war haben nur oder aber vor zur bis mehr durch man sein wurde sei".split(),
    "it": "di e il la che in a per un del le un con non una i si da come lo al ma sono dei piu ha anche nel della gli alla suo questo sua nella tra era loro essere stato fra molto ogni servizi contatto".split(),
    "id": "yang dan di ke dari ini itu dengan untuk tidak akan pada juga saya ada adalah atau mereka kami kita anda oleh sudah bisa dalam lebih karena sebagai telah seperti hanya dapat harus semua jika setelah banyak situs daftar resmi terpercaya permainan".split(),
    "nl": "de van het een en in is dat op te zijn voor met niet aan er maar om ook als dan bij of uit nog wel naar door over ze zich hebben heeft wordt".split(),
    "tr": "ve bir bu da de icin ile mi ne ama gibi daha cok en olarak ben sen biz siz var yok olan kadar sonra ancak veya her".split(),
}
_STOP_SETS = {k: set(v) for k, v in _STOP.items()}

_SCRIPTS = (
    ("ru", re.compile(r"[Ѐ-ӿ]")),
    ("ar", re.compile(r"[؀-ۿݐ-ݿ]")),
    ("th", re.compile(r"[฀-๿]")),
    ("hi", re.compile(r"[ऀ-ॿ]")),
    ("he", re.compile(r"[֐-׿]")),
    ("el", re.compile(r"[Ͱ-Ͽ]")),
    ("ko", re.compile(r"[가-힯]")),
    ("ja", re.compile(r"[぀-ヿ]")),
    ("zh", re.compile(r"[一-鿿]")),
)

LANG_NAMES = {
    "es": "español", "en": "inglés", "pt": "portugués", "fr": "francés", "de": "alemán",
    "it": "italiano", "id": "indonesio", "nl": "neerlandés", "tr": "turco", "ru": "ruso",
    "ar": "árabe", "th": "tailandés", "hi": "hindi", "he": "hebreo", "el": "griego",
    "ko": "coreano", "ja": "japonés", "zh": "chino", "unknown": "desconocido",
}


def visible_text(soup) -> str:
    for t in soup(["script", "style", "noscript", "template"]):
        t.decompose()
    return soup.get_text(" ", strip=True)


def lang_attr(soup) -> str:
    html = soup.find("html")
    if html is not None:
        v = (html.get("lang") or html.get("xml:lang") or "").strip().lower()
        if v:
            return v.replace("_", "-").split("-")[0][:2]
    return ""


def detect_text(text: str):
    """(codigo_idioma, confianza 0-1). 'unknown' si no hay evidencia suficiente."""
    if not text:
        return "unknown", 0.0
    sample = text[:6000]
    letters = [c for c in sample if c.isalpha()]
    if len(letters) < 40:
        return "unknown", 0.0
    # 1) por escritura
    total = len(letters)
    for code, rx in _SCRIPTS:
        n = len(rx.findall(sample))
        if n / total > 0.3:
            # japones usa kana ademas de kanji
            if code == "zh" and re.search(r"[぀-ヿ]", sample):
                return "ja", 0.9
            return code, min(0.99, 0.6 + n / total / 2)
    # 2) latino por palabras funcionales
    tokens = normalize(sample).split()
    if len(tokens) < MIN_TOKENS:
        return "unknown", 0.0
    counts = Counter(tokens)
    scores = {}
    for lang, stop in _STOP_SETS.items():
        hits = sum(c for w, c in counts.items() if w in stop)
        scores[lang] = hits / len(tokens)
    ranked = sorted(scores.items(), key=lambda kv: kv[1], reverse=True)
    best, best_s = ranked[0]
    second_s = ranked[1][1] if len(ranked) > 1 else 0.0
    if best_s < 0.10 or best_s < second_s * 1.25:
        return "unknown", 0.0
    conf = min(0.97, 0.5 + (best_s - second_s) * 3 + best_s)
    return best, round(conf, 2)


def detect_page(soup):
    """(idioma, confianza, metodo) combinando texto y atributo lang."""
    attr = lang_attr(soup)
    text = visible_text(soup)
    lang, conf = detect_text(text)
    if lang != "unknown":
        return lang, conf, "texto", text
    if attr:
        return attr, 0.5, "atributo lang", text
    return "unknown", 0.0, "sin evidencia", text


def infer_expected(page_langs: list, homepage_url: str, explicit: list) -> list:
    """
    Idiomas esperados:
      - los configurados en la campania, si los hay;
      - si no: el idioma de la pagina de inicio + los que representen >=15% de
        las paginas (sitios bilingues).
    """
    if explicit:
        return sorted(set(explicit))
    known = [p for p in page_langs if p["lang"] != "unknown"]
    if not known:
        return []
    home = homepage_url.rstrip("/")
    expected = set()
    for p in known:
        if p["url"].rstrip("/") == home:
            expected.add(p["lang"])
    if len(known) >= 5:
        counts = Counter(p["lang"] for p in known)
        for lang, n in counts.items():
            if n / len(known) >= 0.15:
                expected.add(lang)
    if not expected:  # sin pagina de inicio legible: el idioma mayoritario
        expected.add(Counter(p["lang"] for p in known).most_common(1)[0][0])
    return sorted(expected)
