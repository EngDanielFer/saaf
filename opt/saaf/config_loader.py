#!/home/admin_ubuntu/Desktop/proyecto_saaf/opt/saaf/venv/bin/python
# =============================================================
# SAAF Pro — config_loader.py
# Lee sites.csv, valida cada fila y devuelve lista de sitios
# Ruta: /home/admin_ubuntu/Desktop/proyecto_saaf/opt/saaf/config_loader.py
# =============================================================

import csv
import logging
import os
import re
from pathlib import Path

logger = logging.getLogger(__name__)

CSV_PATH = Path("/home/admin_ubuntu/Desktop/proyecto_saaf/opt/saaf/config/sites.csv")

# Columnas requeridas por el CSV
REQUIRED_COLUMNS = {"name", "url"}

# Columnas opcionales con sus valores por defecto
OPTIONAL_DEFAULTS = {
    "sitemap_url": None,
    "niche": "general",
    "priority": "normal",
    "active": "true",
}

VALID_PRIORITIES = {"high", "normal", "low"}
URL_RE = re.compile(r"^https?://.+\..+", re.IGNORECASE)


# -------------------------------------------------------------
# Validación
# -------------------------------------------------------------
def _validate_row(row: dict, line_num: int) -> list:
    """
    Valida una fila del CSV.
    Devuelve lista de errores (vacía si es válida).
    """
    errors = []
    name = row.get("name", "").strip()
    if not name:
        errors.append(f"Línea {line_num}: campo 'name' vacío")

    url = row.get("url", "").strip()
    if not url:
        errors.append(f"Línea {line_num}: campo 'url' vacío")
    elif not URL_RE.match(url):
        errors.append(
            f"Línea {line_num}: URL inválida '{url} (debe comenzar con http:// o https://)"
        )

    sitemap = row.get("sitemap_url", "").strip()
    if sitemap and not URL_RE.match(sitemap):
        errors.append(f"Línea {line_num}: sitemap_url inválido '{sitemap}")

    priority = row.get("priority", "normal").strip().lower()
    if priority and priority not in VALID_PRIORITIES:
        errors.append(
            f"Línea {line_num}: priority inválido '{priority}' (válidos: {VALID_PRIORITIES})"
        )

    return errors


def _normalize_row(row: dict) -> dict:
    """Normaliza y rellena campos opcionales con defaults."""
    normalized = {}
    normalized["name"] = row.get("name", "").strip()
    normalized["url"] = row.get("url", "").strip()
    normalized["sitemap_url"] = row.get("sitemap_url", "").strip() or None
    normalized["niche"] = row.get("niche", "general").strip() or "general"
    normalized["priority"] = row.get("priority", "normal").strip().lower() or "normal"
    active_raw = row.get("active", "true").strip().lower()
    normalized["active"] = active_raw in ("true", "1", "yes", "on")
    return normalized


# -------------------------------------------------------------
# Lectura principal
# -------------------------------------------------------------


def load_sites_from_csv(csv_path: Path = None, strict: bool = False) -> list:
    """
    Lee sites.csv y devuelve lista de dicts con los sitios válidos.

    Args:
        csv_path: Ruta al CSV. Si es None usa CSV_PATH global.
        strict:   Si True, lanza ValueError al primer error de validación.
                  Si False, omite las filas inválidas y continúa.

    Returns:
        Lista de dicts con claves: name, url, sitemap_url, niche, priority, active

    Raises:
        FileNotFoundError: Si el archivo no existe.
        ValueError:        Si strict=True y hay errores de validación,
                           o si faltan columnas requeridas.
    """
    path = Path(csv_path) if csv_path else CSV_PATH

    if not path.exists():
        raise FileNotFoundError(
            f"Archivo de configuración no encontrado: {path}\n"
            f"Crea el archivo con columnas: name,url,sitemap_url,niche,priority,active"
        )

    sites = []
    all_errors = []
    seen_urls = set()

    try:
        with open(path, newline="", encoding="utf-8-sig") as f:
            # Detectar el delimitador automáticamente (coma o punto y coma)
            sample = f.read(2048)
            f.seek(0)
            delimiter = ";" if sample.count(";") > sample.count(",") else ","

            reader = csv.DictReader(f, delimiter=delimiter)

            # Verificar columnas requeridas
            if reader.fieldnames is None:
                raise ValueError("El CSV está vacío o no tiene cabecera")

            fieldnames_lower = [c.strip().lower() for c in reader.fieldnames]
            missing = REQUIRED_COLUMNS - set(fieldnames_lower)
            if missing:
                raise ValueError(
                    f"El CSV no tiene las columnas requeridas: {missing}."
                    f"Columnas encontradas: {fieldnames_lower}"
                )

            # Normalizar nombres de columna a minúsculas
            reader.fieldnames = [c.strip().lower() for c in reader.fieldnames]

            for line_num, row in enumerate(reader, start=2):
                # Limpiar espacios en claves y valores
                row = {
                    k.strip().lower(): (v.strip() if v else "") for k, v in row.items()
                }

                # Rellenar columnas opcionales ausentes
                for col, default in OPTIONAL_DEFAULTS.items():
                    row.setdefault(col, default or "")

                # Validar
                errors = _validate_row(row, line_num)
                if errors:
                    all_errors.extend(errors)
                    for e in errors:
                        logger.warning(e)
                    if strict:
                        raise ValueError("\n".join(errors))
                    continue

                # Verificar URL duplicada
                url_normalized = row["url"].strip().rstrip("/")
                if url_normalized in seen_urls:
                    msg = (
                        f"Línea {line_num}: URL duplicada '{url_normalized}' — se omite"
                    )
                    logger.warning(msg)
                    all_errors.append(msg)
                    continue
                seen_urls.add(url_normalized)

                sites.append(_normalize_row(row))

    except (csv.Error, UnicodeDecodeError) as e:
        raise ValueError(f"Error leyendo el CSV: {e}")

    logger.info(
        "CSV cargado: %d sitios válidos, %d errores/omitidos (archivo: %s)",
        len(sites),
        len(all_errors),
        path,
    )

    if all_errors:
        logger.warning("Errores encontrados en el CSV:\n  %s", "\n ".join(all_errors))

    return sites


def get_active_sites(csv_path: Path = None) -> list:
    """Devuelve solo los sitios con active=True."""
    return [s for s in load_sites_from_csv(csv_path) if s["active"]]


# -------------------------------------------------------------
# Utilidad: crear CSV de ejemplo
# -------------------------------------------------------------


def create_example_csv(path: Path = None):
    """Crea un sites.csv de ejemplo si no existe."""
    target = Path(path) if path else CSV_PATH
    target.parent.mkdir(parents=True, exist_ok=True)
    if target.exists():
        logger.info("sites.csv ya existe, no se sobreescribe: %s", target)
        return

    rows = [
        {
            "name": "Mi Blog",
            "url": "https://miblog.com",
            "sitemap_url": "https://miblog.com/sitemap.xml",
            "niche": "blog",
            "priority": "high",
            "active": "true",
        },
        {
            "name": "Tienda Online",
            "url": "https://tienda.com",
            "sitemap_url": "https://tienda.com/sitemap_index.xml",
            "niche": "ecommerce",
            "priority": "high",
            "active": "true",
        },
        {
            "name": "Sitio Corporativo",
            "url": "https://empresa.com",
            "sitemap_url": "",
            "niche": "corporate",
            "priority": "normal",
            "active": "true",
        },
    ]

    with open(target, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)

    logger.info("CSV de ejemplo creado en %s", target)
    print(f"[OK] CSV de ejemplo creado: {target}")


# -------------------------------------------------------------
# Entrypoint
# -------------------------------------------------------------

if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s"
    )

    import sys

    path = Path(sys.argv[1]) if len(sys.argv) > 1 else CSV_PATH

    print(f"\n=== SAAF Pro — Cargando sitios desde {path} ===\n")

    try:
        sites = load_sites_from_csv(path)
    except FileNotFoundError:
        print(f"[INFO] No se encontró {path} — creando CSV de ejemplo...")
        create_example_csv(path)
        sites = load_sites_from_csv(path)

    active = [s for s in sites if s["active"]]
    print(f"Total sitios: {len(sites)}")
    print(f"Activos: {len(active)}")
    print(f"Inactivos: {len(sites) - len(active)}")

    if sites:
        print("\nSitios cargados:")
        for s in sites:
            estado = "activo" if s["active"] else "inactivo"
            sitemap = s["sitemap_url"] or "(sin sitemap — se hará crawl)"
            print(f"[{estado}] {s['name']:<25} {s['url']}")
            print(
                f"nicho: {s['niche']:<12} prioridad: {s['priority']:<8} sitemap: {sitemap}"
            )
