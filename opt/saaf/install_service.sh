#!/bin/bash
# =============================================================
# SAAF Pro — Instala y activa el servicio systemd
# Ejecutar con: sudo bash install_service.sh
# =============================================================
 
set -e
 
SAAF_BASE="/home/admin_ubuntu/Desktop/proyecto_saaf/opt/saaf"
SERVICE_SRC="${SAAF_BASE}/saaf.service"
SERVICE_DST="/etc/systemd/system/saaf.service"
ENV_FILE="${SAAF_BASE}/config/saaf.env"
START_SH="${SAAF_BASE}/saaf_start.sh"
 
echo "=== SAAF Pro — Instalando servicio systemd ==="
 
# Verificar que el archivo .env existe antes de instalar
# if [ ! -f "${ENV_FILE}" ]; then
#     echo "[ERROR] No se encontro ${ENV_FILE}"
#     echo "        Copia saaf.env a esa ruta y edita las credenciales antes de continuar."
#     exit 1
# fi

# # Verificar que saaf.service existe
# if [ ! -f "${SERVICE_SRC}" ]; then
#     echo "[ERROR] No se encontro ${SERVICE_SRC}"
#     echo "        Asegurate de haber copiado saaf.service a ${SAAF_BASE}/"
#     exit 1
# fi

[ -f "$ENV_FILE" ]    || { echo "[ERROR] No existe $ENV_FILE"; exit 1; }
[ -f "$SERVICE_SRC" ] || { echo "[ERROR] No existe $SERVICE_SRC"; exit 1; }
[ -f "$START_SH" ]    || { echo "[ERROR] No existe $START_SH"; exit 1; }
 
# Copiar el archivo de servicio
# cp "${SERVICE_SRC}" "${SERVICE_DST}"
# echo "[OK] Servicio copiado a ${SERVICE_DST}"
 
# # Recargar systemd, habilitar e iniciar
# systemctl daemon-reload
# systemctl enable saaf
# systemctl start saaf
 
# echo ""
# echo "=== Estado del servicio ==="
# systemctl status saaf --no-pager
 
# echo ""
# echo "=== Comandos utiles ==="
# echo "  Ver logs en tiempo real : sudo journalctl -u saaf -f"
# echo "  Ver logs del scheduler  : tail -f '${SAAF_BASE}/logs/scheduler.log'"
# echo "  Detener el servicio     : sudo systemctl stop saaf"
# echo "  Reiniciar el servicio   : sudo systemctl restart saaf"

# Quitar CRLF (rompe EnvironmentFile y scripts)
sed -i 's/\r$//' "$ENV_FILE" "$SERVICE_SRC" "$START_SH"
chmod +x "$START_SH"

# El timer alternativo ignora el Dashboard y duplicaria ejecuciones
systemctl disable --now saaf-schedule.timer 2>/dev/null || true
rm -f /etc/systemd/system/saaf-schedule.timer /etc/systemd/system/saaf-schedule.service

install -m 644 "$SERVICE_SRC" "$SERVICE_DST"
systemctl daemon-reload
systemctl enable saaf
systemctl restart saaf

sleep 3
systemctl status saaf --no-pager || true
echo "Logs: tail -f ${SAAF_BASE}/logs/scheduler.log"