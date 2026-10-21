set +e

SCRAPER="node /opt/saaf/scripts/node/scraper.mjs"
PASS=0
FAIL=0

cleanup_redirect_test() {
    if [ -n "$REDIRECT_PID" ] && kill -0 $REDIRECT_PID 2>/dev/null; then
        kill $REDIRECT_PID 2>/dev/null || true
    fi
    if [ -n "$HOSTS_ADDED" ] && [ "$HOSTS_ADDED" -eq 1 ]; then
        sed -i "/$HOSTS_LINE/d" /etc/hosts 2>/dev/null || true
    fi
}
trap cleanup_redirect_test EXIT

check_blocked() {
    local url="$1"
    local label="$2"
    OUTPUT=$($SCRAPER "$url" 2>/dev/null)
    if echo "$OUTPUT" | python3 -c "import sys,json; d=json.load(sys.stdin); exit(0 if d.get('error') else 1)" 2>/dev/null; then
        echo "[OK] Bloqueado correctamente: $label"
        PASS=$((PASS+1))
    else
        echo "[FAIL] Deberia estar bloqueado: $label"
        FAIL=$((FAIL+1))
    fi
}

check_allowed() {
    local url="$1"
    local label="$2"
    OUTPUT=$($SCRAPER "$url" 2>/dev/null)
    if echo "$OUTPUT" | python3 -c "import sys,json; d=json.load(sys.stdin); exit(0 if not d.get('error','').startswith('URL no permitida') else 1)" 2>/dev/null; then
        echo "[OK] Permitido correctamente: $label"
        PASS=$((PASS+1))
    else
        echo "[FAIL] Deberia estar permitido: $label"
        FAIL=$((FAIL+1))
    fi
}

echo "=== Test SSRF: validateUrl() ==="
check_blocked "file:///etc/passwd" "file:// protocol"
check_blocked "ftp://example.com/file" "ftp:// protocol"
check_blocked "http://localhost:8080" "localhost"
check_blocked "http://127.0.0.1:3306" "127.0.0.1 loopback"
check_blocked "http://169.254.169.254/metadata" "AWS metadata IP"
check_blocked "http://10.0.0.1" "10.x.x.x private"
check_blocked "http://192.168.1.1" "192.168.x.x private"
check_blocked "http://172.20.0.1" "172.16-31.x.x private"
check_blocked "http://0.0.0.0:8080" "0.0.0.0"
check_blocked "http://0.42.42.42" "0.x.x.x"
check_blocked "http://user:pass@example.com" "embedded credentials"
check_allowed "https://example.com" "https publico"
check_allowed "http://example.com" "http publico"
check_allowed "http://8.8.8.8" "IP publica directa"
check_allowed "https://1.1.1.1" "IP publica directa"

echo ""
echo "=== Test SSRF: validacion de redirecciones ==="
if [ -f /opt/saaf/scripts/node/scraper.mjs ]; then
    if [ "$(id -u)" -ne 0 ]; then
        echo "[SKIP-needs-root] Test de redireccion omitido: ejecutar como root"
    else
        FAKE_HOST="redirect-test.saaf.local"
        HOSTS_LINE="127.0.0.1 ${FAKE_HOST}"
        HOSTS_ADDED=0
        if ! grep -qF "$HOSTS_LINE" /etc/hosts 2>/dev/null; then
            echo "$HOSTS_LINE" >> /etc/hosts
            HOSTS_ADDED=1
        fi
        node -e "
            const http = require('http');
            const s = http.createServer((req, res) => {
                res.writeHead(302, { Location: 'http://127.0.0.1/' });
                res.end();
            });
            s.listen(19999, '127.0.0.1', () => {});
            setTimeout(() => s.close(), 8000);
        " &
        REDIRECT_PID=$!
        # Verificar que el servidor de redirección esté listo (loop con curl)
        MAX_WAIT=30
        WAITED=0
        while ! curl -s -o /dev/null "http://${FAKE_HOST}:19999/" 2>/dev/null; do
            sleep 0.1
            WAITED=$((WAITED+1))
            if [ $WAITED -ge $MAX_WAIT ]; then
                echo "[FAIL] Servidor de redirección no inició en ${MAX_WAIT} intentos"
                FAIL=$((FAIL+1))
                kill $REDIRECT_PID 2>/dev/null || true
                if [ $HOSTS_ADDED -eq 1 ]; then
                    sed -i "/$HOSTS_LINE/d" /etc/hosts
                fi
                HOSTS_ADDED=0
                continue 2
            fi
        done
        OUT=$(node /opt/saaf/scripts/node/scraper.mjs "http://${FAKE_HOST}:19999/" 2>/dev/null || true)
        if echo "$OUT" | python3 -c "import sys,json; d=json.load(sys.stdin); exit(0 if d.get('error') else 1)" 2>/dev/null; then
            echo "[OK] DNS rebinding / redireccion a IP privada bloqueada"
            PASS=$((PASS+1))
        else
            echo "[FAIL] Deberia haber bloqueado"
            FAIL=$((FAIL+1))
        fi
        kill $REDIRECT_PID 2>/dev/null || true
        if [ $HOSTS_ADDED -eq 1 ]; then
            sed -i "/$HOSTS_LINE/d" /etc/hosts
        fi
        HOSTS_ADDED=0
    fi
else
    echo "[SKIP] scraper.mjs no instalado"
fi

echo ""
echo "Resultado: $PASS OK, $FAIL FAIL"
[ $FAIL -eq 0 ] && echo "[OK] Todos los tests SSRF pasaron" || exit 1