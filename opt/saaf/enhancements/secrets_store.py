# =============================================================
# SAAF Pro — enhancements/secrets_store.py
# Almacen de secretos de las mejoras (contrasena de aplicacion de WordPress,
# URL del webhook de Teams). Estos valores NUNCA se muestran de vuelta en la
# interfaz ni se escriben en los logs.
#
# Donde se guardan:
#   1. Archivo config/enh_secrets.json (permisos 0600) — ruta cambiable con
#      SAAF_SECRETS_PATH. Es el mismo criterio que saaf.env.
#   2. Si el archivo no se puede escribir, la tabla enh_kv de la BD.
# Cifrado opcional: si esta instalado el paquete `cryptography` y existe la
# variable SAAF_SECRET_KEY, los valores se cifran (Fernet). Sin eso se guardan
# en claro (prefijo "plain:") y la interfaz lo avisa.
# =============================================================

import base64
import hashlib
import json
import os
import threading
from pathlib import Path

from . import store
from .log import get_logger

BASE_DIR = Path(__file__).resolve().parent.parent
_lock = threading.Lock()


def _path() -> Path:
    return Path(os.environ.get("SAAF_SECRETS_PATH") or (BASE_DIR / "config" / "enh_secrets.json"))


def _fernet():
    key = os.environ.get("SAAF_SECRET_KEY", "").strip().strip("\r")
    if not key:
        return None
    try:
        from cryptography.fernet import Fernet
    except ImportError:
        return None
    return Fernet(base64.urlsafe_b64encode(hashlib.sha256(key.encode()).digest()))


def encryption_available() -> bool:
    return _fernet() is not None


def _encode(value: str) -> str:
    f = _fernet()
    if f:
        return "enc:" + f.encrypt(value.encode()).decode()
    return "plain:" + value


def _decode(stored: str):
    if not stored:
        return None
    if stored.startswith("plain:"):
        return stored[6:]
    if stored.startswith("enc:"):
        f = _fernet()
        if not f:
            get_logger().warning("Secreto cifrado pero falta SAAF_SECRET_KEY / cryptography")
            return None
        try:
            return f.decrypt(stored[4:].encode()).decode()
        except Exception:
            get_logger().warning("No se pudo descifrar un secreto (clave distinta?)")
            return None
    return stored


def _read_file() -> dict:
    p = _path()
    try:
        return json.loads(p.read_text(encoding="utf-8")) if p.exists() else {}
    except (OSError, ValueError):
        return {}


def _write_file(data: dict) -> bool:
    p = _path()
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        tmp = p.with_suffix(".tmp")
        fd = os.open(str(tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f)
        os.replace(tmp, p)
        try:
            os.chmod(p, 0o600)
        except OSError:
            pass
        return True
    except OSError as e:
        get_logger().warning("No se pudo escribir %s (%s); se usara la BD", p, e.__class__.__name__)
        return False


def set_secret(name: str, value: str):
    value = (value or "").strip()
    if not value:
        delete_secret(name)
        return
    enc = _encode(value)
    with _lock:
        data = _read_file()
        data[name] = enc
        if _write_file(data):
            store.kv_delete("secret:" + name)  # evita duplicados
        else:
            store.kv_set("secret:" + name, enc)


def get_secret(name: str):
    with _lock:
        stored = _read_file().get(name)
    if stored is None:
        stored = store.kv_get("secret:" + name)
    return _decode(stored) if stored else None


def has_secret(name: str) -> bool:
    return bool(get_secret(name))


def delete_secret(name: str):
    with _lock:
        data = _read_file()
        if name in data:
            data.pop(name)
            _write_file(data)
    store.kv_delete("secret:" + name)


def mask(value) -> str:
    return "••••••••" if value else ""
