set -e
echo "=== Test: Variables de entorno SMTP ==="

ALERTS_FILE="/opt/saaf/scripts/python/alerts.py"

# 1. Verificar que no haya credenciales hardcodeadas
if grep -q "smtp_user.*@gmail.com" "$ALERTS_FILE" 2>/dev/null; then
    echo "[FAIL] Credencial hardcodeada encontrada"
    exit 1
fi
if grep -q "smtp_password.*app_password" "$ALERTS_FILE" 2>/dev/null; then
    echo "[FAIL] Password hardcodeado encontrado"
    exit 1
fi
echo "[OK] Sin credenciales hardcodeadas"

# 2. Verificar que usa os.environ.get()
if grep -q "os.environ.get" "$ALERTS_FILE" 2>/dev/null; then
    echo "[OK] Usa os.environ.get() correctamente"
else
    echo "[FAIL] No usa os.environ.get()"
    exit 1
fi

# 3. Test funcional real: simular variables de entorno y verificar lectura
echo "[INFO] Ejecutando test funcional de lectura de variables..."

# Crear script temporal de test
TEST_SCRIPT=$(mktemp)
cat > "$TEST_SCRIPT" << 'PYEOF'
import os
import sys
import re

# Simular variables de entorno
os.environ['SAAF_EMAIL_ENABLED'] = '1'
os.environ['SAAF_SMTP_SERVER'] = 'smtp.test.local'
os.environ['SAAF_SMTP_PORT'] = '587'
os.environ['SAAF_SMTP_TLS'] = '1'
os.environ['SAAF_SMTP_FROM'] = 'test@saaf.local'
os.environ['SAAF_SMTP_USER'] = 'testuser'
os.environ['SAAF_SMTP_PASSWORD'] = 'testpass123'

# Ejecutar la función get_config() de alerts.py
sys.path.insert(0, '/opt/saaf/scripts/python')
from alerts import get_config

config = get_config()
errors = []

if config.get('email_enabled') != '1':
    errors.append(f"email_enabled: esperado '1', got {config.get('email_enabled')}")
if config.get('smtp_server') != 'smtp.test.local':
    errors.append(f"smtp_server: esperado 'smtp.test.local', got {config.get('smtp_server')}")
if config.get('smtp_port') != '587':
    errors.append(f"smtp_port: esperado '587', got {config.get('smtp_port')}")
if config.get('smtp_tls') != '1':
    errors.append(f"smtp_tls: esperado '1', got {config.get('smtp_tls')}")
if config.get('smtp_from') != 'test@saaf.local':
    errors.append(f"smtp_from: esperado 'test@saaf.local', got {config.get('smtp_from')}")
if config.get('smtp_user') != 'testuser':
    errors.append(f"smtp_user: esperado 'testuser', got {config.get('smtp_user')}")
if config.get('smtp_password') != 'testpass123':
    errors.append(f"smtp_password: esperado 'testpass123', got {config.get('smtp_password')}")


if errors:
    print("[FAIL] Errores en lectura de variables de entorno:")
    for e in errors:
        print(f"   - {e}")
    sys.exit(1)
else:
    print("[OK] Todas las variables de entorno leídas correctamente")
    sys.exit(0)
PYEOF

if python3 "$TEST_SCRIPT"; then
    echo "[OK] Test funcional de variables de entorno pasado"
else
    echo "[FAIL] Test funcional de variables de entorno falló"
    rm -f "$TEST_SCRIPT"
    exit 1
fi

rm -f "$TEST_SCRIPT"
echo "[OK] Test completado"