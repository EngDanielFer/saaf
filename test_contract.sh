set -e

echo "=== Test: stdout contract verification ==="

TARGET_URL="${1:-https://example.com}"

if [ -z "$1" ]; then
    echo "[INFO] No se proporcionó URL, usando default: $TARGET_URL"
fi

echo "[INFO] Verificando accesibilidad de: $TARGET_URL"
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 10 "$TARGET_URL" 2>/dev/null || echo "000")

if [ "$HTTP_CODE" = "000" ]; then
    echo "[SKIP] URL no accesible (sin respuesta): $TARGET_URL"
    exit 0
fi

if [ "$HTTP_CODE" -ge 400 ] 2>/dev/null; then
    echo "[SKIP] URL respondió con error HTTP $HTTP_CODE: $TARGET_URL"
    exit 0
fi

echo "[INFO] URL accesible (HTTP $HTTP_CODE), ejecutando test..."

if [ -f /opt/saaf/scripts/node/scraper.mjs ]; then
    OUTPUT=$(node /opt/saaf/scripts/node/scraper.mjs "$TARGET_URL" 2>/dev/null)
else
    OUTPUT=$(node test_real_scraper.js 2>/dev/null)
fi

# Verificar que es JSON valido Y es un objeto Y tiene los campos esperados
if ! echo "$OUTPUT" | python3 -c '
import sys, json
try:
    data = json.loads(sys.stdin.read())
    if not isinstance(data, dict):
        print("ERROR: not a dict")
        sys.exit(1)
    required = ["html", "url", "status_code", "error", "redirect_url"]
    for field in required:
        if field not in data:
            print(f"ERROR: missing field {field}")
            sys.exit(1)
    print("OK")
except Exception as e:
    print(f"ERROR: {e}")
    sys.exit(1)
' 2>/dev/null; then
    echo "[FAIL] stdout contract violated"
    exit 1
fi

echo "[OK] Contract verified - stdout is pure JSON with required fields"
