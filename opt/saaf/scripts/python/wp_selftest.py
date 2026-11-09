#!/usr/bin/env python3
# =============================================================
# SAAF Pro — scripts/python/wp_selftest.py
# Prueba REAL de la conexion y de las correcciones en WordPress.
#
#   wp_selftest.py --site-id 3                 solo comprueba conexion y permisos (no cambia nada)
#   wp_selftest.py --site-id 3 --apply --yes   ademas crea paginas de prueba, ejecuta las correcciones
#                                              y comprueba en la pagina PUBLICA que el enlace malicioso
#                                              desaparecio y que el contenido legitimo sigue ahi.
#
# Credenciales: las de la campania (Campañas → WordPress) con --site-id, o bien
#   --url https://sitio --user bot   y la variable SAAF_WP_APP_PASSWORD (o se pide por teclado).
#
# Que hace --apply (solo toca paginas que ESTE script crea, con slug saaf-selftest-XXXX):
#   1. crea una pagina publica con un enlace legitimo y un enlace «inyectado» oculto
#      hacia un dominio de prueba (saaf-selftest-xxxx.example.org);
#   2. comprueba que el enlace SE VE en la pagina publica (si no, la prueba no vale);
#   3. ejecuta la misma accion que usa el sistema (remove_link) y la verifica;
#   4. crea otra pagina «spam», la envia a la papelera y comprueba que responde 404;
#   5. deja las paginas de prueba en la papelera (--purge las borra definitivamente).
# No toca ninguna otra pagina del sitio ni la portada.
# =============================================================

import argparse
import getpass
import os
import secrets
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))  # .../opt/saaf

from enhancements.wordpress import WPClient, WPError  # noqa: E402


def row(ok, label, detail=""):
    print(("  ✔ " if ok else "  ✖ ") + label + (f" — {detail}" if detail else ""))
    return bool(ok)


def load_creds(args):
    if args.site_id:
        from database import get_all_sites, init_db
        from enhancements import config as cfgmod
        init_db()
        site = next((s for s in get_all_sites() if s["id"] == args.site_id), None)
        if not site:
            sys.exit(f"No existe la campaña {args.site_id}")
        w = cfgmod.get_site_config(args.site_id)["wp"]
        pw = cfgmod.get_wp_password(args.site_id)
        if not (w["base_url"] and w["username"] and pw):
            sys.exit("La campaña no tiene URL, usuario y contraseña de WordPress guardados (Campañas → WordPress).")
        return site["url"], w["base_url"], w["username"], pw
    if not (args.url and args.user):
        sys.exit("Indica --site-id, o bien --url y --user.")
    pw = os.environ.get("SAAF_WP_APP_PASSWORD") or getpass.getpass("Contraseña de aplicación: ")
    return args.url, args.url, args.user, pw


def main() -> int:
    ap = argparse.ArgumentParser(description="Prueba real de conexión y correcciones en WordPress")
    ap.add_argument("--site-id", type=int)
    ap.add_argument("--url")
    ap.add_argument("--user")
    ap.add_argument("--apply", action="store_true", help="crear páginas de prueba y ejecutar las correcciones")
    ap.add_argument("--yes", action="store_true", help="confirmo que se creen páginas de prueba en el sitio")
    ap.add_argument("--purge", action="store_true", help="borrar definitivamente las páginas de prueba al terminar")
    args = ap.parse_args()

    site_url, base, user, pw = load_creds(args)
    client = WPClient(base, user, pw)
    good = True

    print(f"\n[1] Conexión con {base}")
    t = client.test()
    for name, ok, detail in t.get("steps", []):
        good &= row(ok, name, detail)
    print("  →", t.get("message", ""))
    if not t.get("ok") or not (t.get("can_edit") and t.get("can_delete")):
        print("\n✖ La conexión no permite corregir. Revisa usuario, contraseña de aplicación, HTTPS y rol (Editor).")
        return 1
    if not args.apply:
        print("\n✔ Conexión y permisos correctos. Para probar las correcciones: --apply --yes")
        return 0 if good else 1
    if not args.yes:
        print("\nPara crear páginas de prueba (públicas durante unos segundos) añade --yes.")
        return 2

    from enhancements import remediation as rem
    tag = secrets.token_hex(3)
    bad_host = f"saaf-selftest-{tag}.example.org"
    bad_url = f"https://{bad_host}/promo"
    legit = f"{site_url.rstrip('/')}/"
    created = []

    def make(slug, content):
        r = client._call("POST", "/wp/v2/pages", json={"slug": slug, "status": "publish",
                                                       "title": f"SAAF selftest {tag} (borrar)", "content": content})
        if r.status_code not in (200, 201):
            raise WPError(f"No se pudo crear la página de prueba: {client._err(r, 'error')}", r.status_code)
        d = r.json()
        created.append(d["id"])
        return d

    try:
        print("\n[2] Corrección de enlace inyectado (remove_link)")
        body = (f'<p>Texto legítimo SAAF {tag}</p><p><a href="{legit}">Inicio</a></p>'
                f'<div style="display:none"><a href="{bad_url}">oferta casino</a></div>')
        p = make(f"saaf-selftest-{tag}", body)
        url = p["link"]
        _, html = client.fetch_public(url)
        if not row(bad_host in html, "Antes: el enlace inyectado SE VE en la página pública", url):
            print("  La prueba no es válida (caché o página no publicada). Se detiene.")
            return 1
        res = rem.run_action(client, site_url, "remove_link", url, bad_url, p["id"])
        good &= row(res["status"] == rem.APPLIED, "Corrección aplicada", res["message"])
        _, html2 = client.fetch_public(url)
        good &= row(bad_host not in html2, "Después: el enlace inyectado YA NO está en la página pública")
        good &= row(f"Texto legítimo SAAF {tag}" in html2 and legit in html2, "Después: el contenido legítimo sigue intacto")
        raw = client.get_content("pages", p["id"])
        good &= row(bad_host not in raw and "display:none" not in raw, "Después: el contenido editable está limpio")
        if res.get("backup"):
            client.set_content("pages", p["id"], res["backup"])
            _, html3 = client.fetch_public(url)
            good &= row(bad_host in html3, "Revertir con la copia guardada restaura el estado anterior")

        print("\n[3] Página spam a la papelera (trash_post)")
        s = make(f"saaf-selftest-spam-{tag}", f"<h1>Casino gratis {tag}</h1>")
        surl = s["link"]
        good &= row(client.fetch_public(surl)[0] == 200, "Antes: la página spam responde 200")
        res = rem.run_action(client, site_url, "trash_post", surl, "", s["id"])
        good &= row(res["status"] == rem.APPLIED, "Enviada a la papelera", res["message"])
        good &= row(client.fetch_public(surl)[0] in (404, 410), "Después: la página pública ya no existe (404/410)")
        client.untrash("pages", s["id"])
        good &= row(client.fetch_public(surl)[0] == 200, "Restaurar desde la papelera la vuelve a publicar")
    except WPError as e:
        print("  ✖ Error de WordPress:", e)
        good = False
    finally:
        print("\n[4] Limpieza")
        for pid in created:
            try:
                client.trash("pages", pid)
                if args.purge:
                    client._call("DELETE", f"/wp/v2/pages/{pid}", params={"force": "true"})
            except WPError as e:
                print(f"  ⚠ No se pudo limpiar la página #{pid}: {e}")
        print(f"  {len(created)} página(s) de prueba " + ("borradas." if args.purge else "en la papelera de WordPress."))

    print("\n" + ("✔ PRUEBA SUPERADA: la corrección se ejecutó y se comprobó en la página pública."
                  if good else "✖ PRUEBA NO SUPERADA: revisa los pasos marcados con ✖."))
    return 0 if good else 1


if __name__ == "__main__":
    sys.exit(main())
