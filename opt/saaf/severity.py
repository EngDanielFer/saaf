#!/home/admin_ubuntu/Desktop/proyecto_saaf/opt/saaf/venv/bin/python
# =============================================================
# SAAF Pro — severity.py
# Clasifica amenazas en CRITICAL / HIGH / MEDIUM / LOW / INFO
# evaluando la COMBINACION de señales de riesgo, no solo el tipo.
# Ruta: /home/admin_ubuntu/Desktop/proyecto_saaf/opt/saaf/severity.py
#
# CAMBIOS respecto a la version anterior (CRITICO/ALTO/MEDIO/BAJO):
#   * Escala de 5 niveles en ingles: INFO, LOW, MEDIUM, HIGH, CRITICAL
#     (ver Mejoras_auditoria_y_alertas, punto 2). Los nombres antiguos
#     se siguen ENTENDIENDO via normalize_severity() para tolerar datos
#     o archivos de una version previa.
#   * Cada amenaza parte de una puntuacion base por tipo y suma/resta los
#     puntos de las señales de risk_signals.py (TLD, doble extension,
#     .php como script, marca imitada, ruta anomala, servicio legitimo...).
#   * 3 o mas señales FUERTES => CRITICAL siempre.
#   * Un script externo ya no es CRITICAL "por ser externo": en nichos de
#     alto riesgo suma +2 (antes saltaba directo a CRITICO).
# =============================================================

import logging
import unicodedata
from dataclasses import dataclass, field

from risk_signals import (
    SCRIPT, IFRAME, LINK, Signal, evaluate_resource,
)

logger = logging.getLogger(__name__)

# =============================================================
# Escala de severidad
# =============================================================

CRITICAL = "CRITICAL"
HIGH = "HIGH"
MEDIUM = "MEDIUM"
LOW = "LOW"
INFO = "INFO"

# De menor a mayor
SEVERITY_LEVELS = (INFO, LOW, MEDIUM, HIGH, CRITICAL)
SEVERITY_ORDER = {INFO: 0, LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4}

# Nombres de la version anterior -> canonicos
LEGACY_SEVERITY_MAP = {
    "CRITICO": CRITICAL,
    "ALTO": HIGH,
    "MEDIO": MEDIUM,
    "BAJO": LOW,
}

SEVERITY_COLOR = {
    CRITICAL: "#DC2626",
    HIGH: "#EA580C",
    MEDIUM: "#CA8A04",
    LOW: "#16A34A",
    INFO: "#64748B",
}

SEVERITY_ICON = {
    CRITICAL: "🔴",
    HIGH: "🟠",
    MEDIUM: "🟡",
    LOW: "🟢",
    INFO: "🔵",
}


def _strip_accents(text: str) -> str:
    return "".join(
        c for c in unicodedata.normalize("NFD", text) if unicodedata.category(c) != "Mn"
    )


def normalize_severity(value):
    """
    Devuelve la severidad canonica (CRITICAL/HIGH/MEDIUM/LOW/INFO) o None si no es valida.
    Acepta cualquier mayuscula/minuscula, acentos ('CRÍTICO') y los nombres de la
    version anterior ('CRITICO', 'ALTO', 'MEDIO', 'BAJO').
    """
    if value is None:
        return None
    v = _strip_accents(str(value).strip()).upper()
    if v in SEVERITY_ORDER:
        return v
    return LEGACY_SEVERITY_MAP.get(v)


def severity_rank(value) -> int:
    """Posicion numerica de una severidad (INFO=0 ... CRITICAL=4). Invalida -> -1."""
    n = normalize_severity(value)
    return SEVERITY_ORDER[n] if n else -1


def max_severity(values):
    """La mayor severidad de una coleccion (None si esta vacia o no hay validas)."""
    best = None
    for v in values:
        n = normalize_severity(v)
        if n and (best is None or SEVERITY_ORDER[n] > SEVERITY_ORDER[best]):
            best = n
    return best


# =============================================================
# Puntuacion
# =============================================================
#
# score >= 6 -> CRITICAL   score >= 4 -> HIGH   score >= 2 -> MEDIUM
# score >= 1 -> LOW        score <= 0 -> INFO
#
# La puntuacion BASE reproduce la severidad que tenia cada tipo antes:
#   CRITICO=6, ALTO=4, MEDIO=2. Las señales la suben o la bajan.

BASE_POINTS = {
    "hidden_spam_link": 6,  # antes CRITICO siempre
    "casino_pharma_adult": 4,  # antes ALTO
    "hidden_iframe": 4,  # antes ALTO
    "obfuscated_js": 4,  # antes ALTO
    "external_script": 2,  # antes MEDIO
    "claude_anomaly": 2,  # antes MEDIO
    "broken_internal_link": 2,  # antes MEDIO
}
DEFAULT_BASE_POINTS = 2

# Tipos cuyo recurso (src/href) se evalua con risk_signals y su "kind"
RESOURCE_KIND = {
    "external_script": SCRIPT,
    "hidden_iframe": IFRAME,
    "hidden_spam_link": LINK,
}

# Nichos de alto riesgo: suman puntos a ciertas amenazas (skimmers, clickjacking)
HIGH_RISK_NICHES = {
    "ecommerce", "tienda", "shop", "store", "banking", "finance",
    "health", "medical", "salud", "farmacia",
}
LOW_RISK_NICHES = {"landing", "portfolio", "personal", "hobby"}
ESCALATE_IN_HIGH_RISK = {"obfuscated_js", "hidden_iframe", "external_script"}
NICHE_HIGH_RISK_POINTS = 2

# Siempre CRITICAL salvo que sea un servicio legitimo conocido
ALWAYS_CRITICAL = {"hidden_spam_link"}

# >= N señales fuertes => CRITICAL ; >= 2 => al menos HIGH
STRONG_SIGNALS_FOR_CRITICAL = 3
STRONG_SIGNALS_FOR_HIGH = 2


def level_for_score(score: int) -> str:
    if score >= 6:
        return CRITICAL
    if score >= 4:
        return HIGH
    if score >= 2:
        return MEDIUM
    if score >= 1:
        return LOW
    return INFO


@dataclass
class Classification:
    severity: str
    score: int
    signals: list = field(default_factory=list)
    base: int = 0

    @property
    def strong_count(self) -> int:
        return sum(1 for s in self.signals if s.strong)

    def explain(self) -> str:
        from risk_signals import describe_signals

        return describe_signals(self.signals)


_SPAM_RE = None


def _spam_pattern():
    """Regex de palabras casino/pharma/adult (la misma de analyzer.py)."""
    global _SPAM_RE
    if _SPAM_RE is None:
        try:
            from analyzer import URL_SPAM_PATTERNS

            _SPAM_RE = URL_SPAM_PATTERNS
        except Exception:  # analyzer no disponible: sin esta señal
            _SPAM_RE = False
    return _SPAM_RE or None


def _as_dict(ctx) -> dict:
    # Threat.extra_context era [] por defecto en versiones previas
    return ctx if isinstance(ctx, dict) else {}


def classify_threat(
    threat_type: str,
    niche: str = "general",
    extra_context=None,
    resource_url: str = None,
    base_domain: str = "",
) -> Classification:
    """
    Calcula la severidad de UNA amenaza combinando tipo, nicho y señales.

    Args:
        threat_type:   tipo (ver Threat.VALID_TYPES en analyzer.py).
        niche:         nicho del sitio (ecommerce, blog, ...).
        extra_context: dict con: resource_url, tag_id, is_spam_domain,
                       new_domain, hidden.
        resource_url:  URL del recurso sospechoso (src/href); si no se pasa se
                       toma de extra_context['resource_url'].
        base_domain:   dominio del sitio auditado.
    """
    ctx = _as_dict(extra_context)
    niche_lower = (niche or "general").lower().strip()
    base = BASE_POINTS.get(threat_type, DEFAULT_BASE_POINTS)
    score = base
    signals = []
    
    # --- Señales del recurso (solo para scripts / iframes / enlaces ocultos) ---
    kind = RESOURCE_KIND.get(threat_type)
    res = resource_url or ctx.get("resource_url")
    if kind and res:
        signals = evaluate_resource(
            res,
            kind,
            base_domain=base_domain,
            tag_id=ctx.get("tag_id", ""),
            is_spam_domain=bool(ctx.get("is_spam_domain")),
            new_domain=bool(ctx.get("new_domain")),
            hidden=bool(ctx.get("hidden")),
            spam_pattern=_spam_pattern(),
        )
    elif ctx.get("is_spam_domain"):
        # Compatibilidad: contexto antiguo sin resource_url
        signals = [Signal("known_spam_domain", 3, "Dominio en la lista de spam conocidos", True)]
    score += sum(s.points for s in signals)

    # --- Nicho de alto riesgo (suma, ya no salta directo a CRITICAL) ---
    if any(h in niche_lower for h in HIGH_RISK_NICHES) and threat_type in ESCALATE_IN_HIGH_RISK:
        score += NICHE_HIGH_RISK_POINTS
        signals = signals + [
            Signal("niche_high_risk", NICHE_HIGH_RISK_POINTS, f"Nicho de alto riesgo ({niche_lower})")
        ]
    
    severity = level_for_score(score)
    strong = sum(1 for s in signals if s.strong)
    trusted = any(s.code == "trusted_provider" for s in signals)

    # --- Reglas de combinacion ---
    if strong >= STRONG_SIGNALS_FOR_CRITICAL:
        severity = CRITICAL
    elif strong >= STRONG_SIGNALS_FOR_HIGH and SEVERITY_ORDER[severity] < SEVERITY_ORDER[HIGH]:
        severity = HIGH
    if threat_type in ALWAYS_CRITICAL and not trusted:
        severity = CRITICAL

    # --- Nicho de bajo riesgo: MEDIUM -> LOW (solo sin señales fuertes) ---
    if severity == MEDIUM and strong == 0 and any(l in niche_lower for l in LOW_RISK_NICHES):
        severity = LOW
        logger.debug("Rebajado a LOW: %s en nicho '%s'", threat_type, niche)

    return Classification(severity=severity, score=score, signals=signals, base=base)


def get_severity(
    threat_type: str, niche: str = "general", extra_context: dict = None
) -> str:
    """Compatibilidad con la API anterior: devuelve solo el nivel."""
    return classify_threat(threat_type, niche, extra_context).severity


def classify_threats(threats: list, niche: str = "general", base_domain: str = "") -> list:
    """
    Asigna severidad a una lista de objetos Threat (in-place) y la devuelve
    ordenada de mayor a menor severidad. Cada Threat recibe ademas:
      .severity  .score  .signals (lista de Signal)
    """
    for threat in threats:
        res = getattr(threat, "resource_url", None)
        c = classify_threat(
            threat.threat_type,
            niche,
            getattr(threat, "extra_context", None),
            resource_url=res,
            base_domain=base_domain,
        )
        threat.severity = c.severity
        threat.score = c.score
        threat.signals = c.signals
    threats.sort(key=lambda t: SEVERITY_ORDER.get(t.severity, 0), reverse=True)
    return threats


def summarize_severities(threats: list) -> dict:
    """Cuantas amenazas hay por nivel (incluye los 5 niveles, aunque sean 0)."""
    summary = {lvl: 0 for lvl in reversed(SEVERITY_LEVELS)}
    for t in threats:
        n = normalize_severity(getattr(t, "severity", None))
        if n:
            summary[n] += 1
    return summary


def should_alert(threats: list) -> bool:
    """True si hay al menos una amenaza CRITICAL o HIGH nueva (justifica email)."""
    return any(
        normalize_severity(t.severity) in (CRITICAL, HIGH) and getattr(t, "is_new", True)
        for t in threats
    )
    

# =============================================================
# Entrypoint — autotest
# =============================================================

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s"
    )

    print("\n=== SAAF Pro — Severity classifier (autotest) ===\n")

    # (tipo, nicho, contexto, esperado)
    tests = [
        ("hidden_spam_link", "general", {}, CRITICAL),
        ("hidden_spam_link", "portfolio", {}, CRITICAL),
        ("hidden_spam_link", "ecommerce", {}, CRITICAL),
        ("obfuscated_js", "ecommerce", {}, CRITICAL),
        ("obfuscated_js", "blog", {}, HIGH),
        ("hidden_iframe", "ecommerce", {}, CRITICAL),
        ("hidden_iframe", "landing", {}, HIGH),
        # Un script externo "normal" ya no es CRITICAL ni siquiera en ecommerce
        ("external_script", "ecommerce", {}, HIGH),
        ("external_script", "blog", {}, MEDIUM),
        ("external_script", "portfolio", {}, LOW),
        ("casino_pharma_adult", "general", {}, HIGH),
        ("claude_anomaly", "general", {}, MEDIUM),
        # Caso del documento: debe ser CRITICAL (antes MEDIUM)
        (
            "external_script",
            "general",
            {
                "resource_url": "https://draft-kings.bet/projects/moscwagang/mini.js.php",
                "tag_id": "asahi-jquery-min-bundle-js",
            },
            CRITICAL,
        ),
        # reCAPTCHA legitimo: NO debe ser critico
        (
            "hidden_iframe",
            "general",
            {"resource_url": "https://www.google.com/recaptcha/api2/aframe"},
            INFO,
        ),
        # Dominio de spam conocido: sube de MEDIUM a HIGH (igual que antes)
        ("external_script", "general", {"is_spam_domain": True}, HIGH),
    ]
    
    all_ok = True
    for threat_type, niche, ctx, expected in tests:
        result = classify_threat(threat_type, niche, ctx).severity
        status = "OK" if result == expected else "FAIL"
        if status == "FAIL":
            all_ok = False
        print(
            f"  [{status}] {threat_type:<22} nicho={niche:<10} esperado={expected:<9} obtenido={result}"
        )

    print()
    if all_ok:
        print("[OK] Todos los tests de severidad pasaron")
    else:
        print("[FAIL] Hay clasificaciones incorrectas")