#!/bin/bash
# /home/admin_ubuntu/Desktop/proyecto_saaf/opt/saaf/install.sh - SAAF Pro v6.7.14

set -e

echo "=== SAAF Pro Installation v6.7.14 ==="

apt-get update
apt-get install -y \
    nginx \
    python3 \
    python3-pip \
    python3-venv \
    nodejs \
    npm \
    logrotate \
    sqlite3

# INSTALAR CHROMIUM OBLIGATORIAMENTE
echo "Installing Chromium..."
CHROMIUM_INSTALLED=0
if apt-get install -y chromium-browser 2>/dev/null; then
    CHROMIUM_INSTALLED=1
    CHROMIUM_PATH=$(which chromium-browser)
elif apt-get install -y chromium 2>/dev/null; then
    CHROMIUM_INSTALLED=1
    CHROMIUM_PATH=$(which chromium)
elif apt-get install -y chromium-chromium 2>/dev/null; then
    CHROMIUM_INSTALLED=1
    CHROMIUM_PATH=$(which chromium-chromium)
fi

if [ $CHROMIUM_INSTALLED -eq 0 ]; then
    echo "ERROR: Cannot install Chromium. SAAF Pro requires Chromium."
    exit 1
fi

if ! "$CHROMIUM_PATH" --version > /dev/null 2>&1; then
    echo "ERROR: Chromium installed but cannot execute: $CHROMIUM_PATH"
    exit 1
fi

echo "Chromium OK: $CHROMIUM_PATH ($($CHROMIUM_PATH --version))"

# ------------------------------------------------------------
# Python virtualenv con versiones fijadas
# ----------------------------------------------------------
SAAF_BASE="/home/admin_ubuntu/Desktop/proyecto_saaf/opt/saaf"
# El venv activo (y el que usan los servicios systemd) esta en proyecto_saaf/venv
PYTHON_VENV="/home/admin_ubuntu/Desktop/proyecto_saaf/venv"
python3 -m venv "${PYTHON_VENV}"

cat > "${SAAF_BASE}/requirements.txt" << 'REQEOF'
fastapi==0.110.3
uvicorn==0.29.0
streamlit==1.28.1
pandas==2.1.4
requests==2.31.0
beautifulsoup4==4.12.2
tldextract==5.1.0
python-whois==0.8.0
twilio==8.10.0
apscheduler==3.10.4
reportlab
anthropic
playwright>=1.45
REQEOF

"${PYTHON_VENV}/bin/pip" install --no-cache-dir -r "${SAAF_BASE}/requirements.txt"

# Chromium de Playwright para enviar reportes a Teams (sin webhook). Se instala en una ruta
# compartida para que el servicio (User=admin_ubuntu) lo encuentre aunque install.sh corra como root.
export PLAYWRIGHT_BROWSERS_PATH=/opt/ms-playwright
"${PYTHON_VENV}/bin/playwright" install --with-deps chromium || echo "AVISO: no se pudo instalar Chromium de Playwright; el envio a Teams no funcionara hasta instalarlo."
chmod -R a+rX /opt/ms-playwright 2>/dev/null || true

# ------------------------------------------------------------
# Node.js con versiones fijadas
# ------------------------------------------------------------
NODE_DIR="${SAAF_BASE}/scripts/node"
mkdir -p "${NODE_DIR}"
cd "${NODE_DIR}"

cat > package.json << 'PKGEOF'
{
  "name": "saaf-scraper",
  "version": "6.7.14",
  "private": true,
  "type": "module",
  "dependencies": {
    "puppeteer": "21.6.1",
    "puppeteer-extra": "3.3.6",
    "puppeteer-extra-plugin-stealth": "2.11.2",
    "ghost-cursor": "1.4.2"
  }
}
PKGEOF

export PUPPETEER_SKIP_DOWNLOAD=true
export PUPPETEER_EXECUTABLE_PATH="$CHROMIUM_PATH"

npm install --package-lock-only --no-audit --no-fund
npm ci --no-audit --no-fund

mkdir -p "${SAAF_BASE}/config"
echo "$CHROMIUM_PATH" > "${SAAF_BASE}/config/chromium.path"

# ------------------------------------------------------------
# Crear usuario no-root 'saaf'
# ------------------------------------------------------------
if ! id -u saaf > /dev/null 2>&1; then
    useradd -r -s /bin/bash -d "${SAAF_BASE}" saaf
    echo "Usuario 'saaf' creado."
else
    echo "Usuario 'saaf' ya existe, omitiendo creacion."
fi
chown -R saaf:saaf "${SAAF_BASE}"

echo "=== Installation complete ==="
echo "Chromium: $CHROMIUM_PATH"
echo "Python virtualenv: $PYTHON_VENV"
echo "Versions pinned in requirements.txt and package.json"
echo "Usuario de ejecucion: saaf (no-root)"
echo ""
echo "=== SECURITY NOTICE ==="
echo "Ejecutar el scraper siempre como usuario 'saaf':"
echo "  su -s /bin/bash saaf -c 'node /home/admin_ubuntu/Desktop/proyecto_saaf/opt/saaf/scripts/node/scraper.js <url>'"
echo "NUNCA ejecutar Chromium con --no-sandbox como root en produccion."
echo "========================"
