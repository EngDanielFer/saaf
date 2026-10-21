set -e
echo "=== Test: Chromium installation ==="
CHROMIUM_PATH=""
if [ -f /opt/saaf/config/chromium.path ]; then
    CHROMIUM_PATH=$(cat /opt/saaf/config/chromium.path)
fi
if [ -z "$CHROMIUM_PATH" ]; then
    CHROMIUM_PATH=$(which chromium-browser 2>/dev/null || which chromium 2>/dev/null)
fi
if [ -n "$CHROMIUM_PATH" ] && [ -f "$CHROMIUM_PATH" ]; then
    VERSION=$($CHROMIUM_PATH --version 2>/dev/null)
    echo "[OK] Chromium found: $CHROMIUM_PATH"
    echo "   Version: $VERSION"
else
    echo "[FAIL] Chromium not found"
    exit 1
fi
