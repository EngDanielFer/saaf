#!/usr/bin/env python3
# =============================================================
# SAAF Pro — scripts/python/teams_login.py
# Prepara y comprueba el envio de reportes a Microsoft Teams SIN webhook.
#
#   teams_login.py                    Abre Chromium con ventana: inicia sesion TU (usuario, contrasena y MFA).
#                                     La sesion queda guardada en el perfil de SAAF. Se hace una sola vez
#                                     (y de nuevo solo si Microsoft cierra la sesion).
#   teams_login.py --check            Comprueba (sin escribir nada) que la sesion sigue activa.
#   teams_login.py --send-test --chat-url URL [--chat-name NOMBRE]
#                                     Envia un mensaje REAL al chat y verifica que aparece. Guarda captura.
#   teams_login.py --diagnose [--chat-url URL]
#                                     Si Teams cambio su interfaz: muestra que selectores encuentra y guarda
#                                     una captura, para ajustar SAAF_TEAMS_SELECTORS.
#
# Este script NO guarda tu contrasena ni evita el MFA: solo conserva la sesion
# del navegador, igual que cuando eliges «Mantener la sesion iniciada».
# Uso:  venv/bin/python opt/saaf/scripts/python/teams_login.py
# =============================================================

import argparse
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))  # .../opt/saaf

from enhancements import teams_browser as tb  # noqa: E402


def cmd_login(args) -> int:
    ok, why = tb.playwright_ready()
    if not ok:
        print("✖", why)
        return 2
    sync_playwright, _, _ = tb._import_playwright()
    print(f"Perfil de sesión: {tb.PROFILE_DIR}")
    print("Se abrirá Chromium. Inicia sesión en Microsoft Teams con la cuenta que publicará los reportes")
    print("(incluye el MFA que te pida Microsoft) y espera a ver tus chats. Tienes 10 minutos.")
    with tb.profile_lock(wait_s=10) as got:
        if not got:
            print("✖ Otro proceso (el scheduler o el dashboard) está usando la sesión. Inténtalo en un minuto.")
            return 3
        with sync_playwright() as pw:
            ctx = tb._launch(pw, headless=False)
            try:
                page = ctx.pages[0] if ctx.pages else ctx.new_page()
                page.goto(tb.TEAMS_URL, wait_until="domcontentloaded", timeout=tb.NAV_TIMEOUT_MS)
                deadline = time.time() + 600
                seen_ready = 0
                while time.time() < deadline:
                    try:
                        if not tb.is_login_page(page) and (tb._first(page, "ready") or tb._first(page, "composer")):
                            seen_ready += 1
                            if seen_ready >= 3:  # estable unos segundos
                                break
                        else:
                            seen_ready = 0
                    except Exception:
                        pass
                    time.sleep(2)
                else:
                    print("✖ No se detectó una sesión de Teams iniciada a tiempo.")
                    return 1
                time.sleep(3)  # deja que Chromium escriba las cookies al disco
            finally:
                ctx.close()
    print("✔ Sesión de Teams guardada. Ahora prueba:  teams_login.py --check   y   --send-test")
    return 0


def cmd_check(args) -> int:
    st = tb.session_status(headless=True)
    print(json.dumps(st, ensure_ascii=False))
    return 0 if st["state"] == "ok" else 1


def cmd_send_test(args) -> int:
    marker = tb.new_marker("SAAF-PRUEBA")
    res = tb.send_message(args.chat_url or "", args.chat_name or "",
                          ["✅ SAAF Pro — prueba de envío a Teams", "Mensaje de prueba generado por teams_login.py"],
                          marker=marker, headless=not args.show)
    print(json.dumps(res, ensure_ascii=False, indent=2))
    if res["ok"] and res["verified"]:
        print(f"\n✔ Mensaje recibido y verificado en Teams. Referencia: {marker}. Evidencia: {res['proof']}")
        return 0
    print(f"\n✖ No se pudo comprobar la entrega: {res['error']} [{res['code']}]")
    return 1


def cmd_diagnose(args) -> int:
    sync_playwright, _, _ = tb._import_playwright()
    if not sync_playwright:
        print("✖", tb.playwright_ready()[1])
        return 2
    with tb.profile_lock(wait_s=10) as got:
        if not got:
            print("✖ La sesión está en uso.")
            return 3
        with sync_playwright() as pw:
            ctx = tb._launch(pw, headless=not args.show)
            try:
                page = ctx.pages[0] if ctx.pages else ctx.new_page()
                page.goto(args.chat_url or tb.TEAMS_URL, wait_until="domcontentloaded", timeout=tb.NAV_TIMEOUT_MS)
                state = tb._wait_ready(page, tb.NAV_TIMEOUT_MS)
                time.sleep(4)
                report = {"estado": state, "url": page.url, "titulo": page.title(), "selectores": {}}
                for key, sels in tb.SELECTORS.items():
                    report["selectores"][key] = {s: page.locator(s).count() for s in sels}
                tb.PROOF_DIR.mkdir(parents=True, exist_ok=True)
                shot = tb.PROOF_DIR / "diagnostico.png"
                page.screenshot(path=str(shot), full_page=False)
                report["captura"] = str(shot)
                print(json.dumps(report, ensure_ascii=False, indent=2))
            finally:
                ctx.close()
    print("\nSi 'composer' o 'messages' muestran 0 en todos los selectores, Teams cambió su interfaz: "
          "define SAAF_TEAMS_SELECTORS en saaf.env con los nuevos selectores (ver guía).")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description="Sesión y pruebas de envío a Microsoft Teams (sin webhook)")
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--send-test", action="store_true")
    ap.add_argument("--diagnose", action="store_true")
    ap.add_argument("--chat-url", default="")
    ap.add_argument("--chat-name", default="")
    ap.add_argument("--show", action="store_true", help="mostrar la ventana del navegador en --send-test/--diagnose")
    args = ap.parse_args()
    if args.check:
        return cmd_check(args)
    if args.send_test:
        return cmd_send_test(args)
    if args.diagnose:
        return cmd_diagnose(args)
    return cmd_login(args)


if __name__ == "__main__":
    sys.exit(main())
