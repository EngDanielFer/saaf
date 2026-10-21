# =============================================================
# SAAF Pro — enhancements/log.py
# Logger PROPIO de las mejoras. Escribe SOLO en logs/enhancements.log y NO
# propaga al logger raiz: asi la consola (stdout) y los logs existentes
# (saaf.log, scheduler.log, app.log) quedan exactamente como antes.
# =============================================================

import logging
import os
from logging.handlers import RotatingFileHandler
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent  # .../opt/saaf
LOG_DIR = Path(os.environ.get("SAAF_LOG_DIR", str(BASE_DIR / "logs")))

_NAME = "saaf.enh"


def get_logger() -> logging.Logger:
    lg = logging.getLogger(_NAME)
    if getattr(lg, "_saaf_enh_ready", False):
        return lg
    lg.setLevel(logging.INFO)
    lg.propagate = False  # <- clave: nada de esto llega a la consola
    try:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        handler = RotatingFileHandler(
            LOG_DIR / "enhancements.log", maxBytes=2_000_000, backupCount=3, encoding="utf-8"
        )
        handler.setFormatter(
            logging.Formatter("%(asctime)s %(levelname)-8s enh — %(message)s")
        )
    except OSError:
        handler = logging.NullHandler()
    lg.addHandler(handler)
    lg._saaf_enh_ready = True
    return lg
