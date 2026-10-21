#!/home/admin_ubuntu/Desktop/proyecto_saaf/opt/saaf/venv/bin/python
# =============================================================
# SAAF Pro — app.py
# App principal Streamlit: login, navegacion y estado de sesion
# Ruta: /home/admin_ubuntu/Desktop/proyecto_saaf/opt/saaf/app.py
# Ejecutar: /home/admin_ubuntu/Desktop/proyecto_saaf/opt/saaf/venv/bin/streamlit run /home/admin_ubuntu/Desktop/proyecto_saaf/opt/saaf/app.py
# =============================================================

import os
import sys
import hashlib
import hmac
import logging
from pathlib import Path
import streamlit as st

sys.path.insert(0, '/home/admin_ubuntu/Desktop/proyecto_saaf/opt/saaf')
sys.path.insert(0, '/home/admin_ubuntu/Desktop/proyecto_saaf/opt/saaf/scripts/python')

# =============================================================
# Logging — igual que scheduler.py, para ver en consola/logs las
# acciones del Dashboard (init_db, set_setting, etc). Sin esto,
# los logger.info() de database.py y otros modulos no se ven en
# ningun lado cuando se corre via "streamlit run app.py", porque
# el proceso nunca configuraba el logging.
# =============================================================
LOG_DIR = Path("/home/admin_ubuntu/Desktop/proyecto_saaf/opt/saaf/logs")
LOG_DIR.mkdir(parents=True, exist_ok=True)

if not logging.getLogger().handlers:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-8s %(name)s — %(message)s",
        handlers=[
            logging.FileHandler(LOG_DIR / "app.log", encoding="utf-8"),
            logging.StreamHandler(sys.stdout),
        ],
    )
logger = logging.getLogger("app")

# Configuracion de pagina — debe ser lo primero
st.set_page_config(
    page_title="SAAF Pro",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# Importar vistas
from views.dashboard import render as render_dashboard
from views.site_detail import render as render_site_detail
from views.alerts import render as render_alerts
from views.history import render as render_history
from views.settings import render as render_settings

# Pagina de mejoras (agrupacion, IA, autorizaciones, programacion y reportes).
# Import aislado: si falta el paquete o SAAF_ENHANCEMENTS=0, el menu queda igual que antes.
try:
    if os.environ.get("SAAF_ENHANCEMENTS", "1").strip() == "0":
        raise ImportError("mejoras desactivadas")
    from views.enhancements import render as render_enhancements
except Exception:
    render_enhancements = None

# =============================================================
# Estilos globales
# =============================================================
st.markdown("""
<style>
    /* Fuente y colores base */
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap');
    html, body, [class*="css"] { font-family: 'Inter', sans-serif; }
 
    /* Sidebar */
    [data-testid="stSidebar"] { background: #0F1117; }
    [data-testid="stSidebar"] * { color: #E2E8F0 !important; }
 
    /* Quitar padding superior innecesario */
    .block-container { padding-top: 1.5rem; }
 
    /* Badges de severidad */
    .badge-critico { background:#DC2626; color:white; padding:2px 8px; border-radius:4px; font-size:11px; font-weight:600; }
    .badge-alto    { background:#EA580C; color:white; padding:2px 8px; border-radius:4px; font-size:11px; font-weight:600; }
    .badge-medio   { background:#CA8A04; color:white; padding:2px 8px; border-radius:4px; font-size:11px; font-weight:600; }
    .badge-bajo    { background:#16A34A; color:white; padding:2px 8px; border-radius:4px; font-size:11px; font-weight:600; }
    .badge-info    { background:#64748B; color:white; padding:2px 8px; border-radius:4px; font-size:11px; font-weight:600; }
    .badge-caido   { background:#DC2626; color:white; padding:2px 8px; border-radius:4px; font-size:11px; font-weight:700; animation: pulse 1.5s infinite; }
    .badge-ok      { background:#16A34A; color:white; padding:2px 8px; border-radius:4px; font-size:11px; font-weight:600; }
 
    @keyframes pulse { 0%,100%{ opacity:1; } 50%{ opacity:0.6; } }
 
    /* Codigo sospechoso */
    .code-snippet { font-family:'JetBrains Mono',monospace; font-size:12px;
                    background:#1E1E2E; color:#CDD6F4; padding:10px 14px;
                    border-radius:6px; border-left:3px solid #DC2626;
                    white-space:pre-wrap; word-break:break-all; }
 
    /* Metricas */
    [data-testid="metric-container"] { background:#F8FAFC; border:1px solid #E2E8F0;
                                        border-radius:8px; padding:12px; }
</style>
""", unsafe_allow_html=True)


# =============================================================
# Autenticacion
# =============================================================

# SAL fija por instalacion — en produccion usar variable de entorno SAAF_AUTH_SALT
_AUTH_SALT = os.environ.get('SAAF_AUTH_SALT', 'saaf-pro-default-salt-2024').encode()

def _hash_password(password: str) -> str:
    """PBKDF2-HMAC-SHA256 con sal — resistente a ataques de diccionario."""
    return hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        _AUTH_SALT,
        iterations=260_000,   # NIST 2023 recomendacion minima
    ).hex()
    
USERS = {
    os.environ.get('SAAF_USER', 'admin'): _hash_password(
        os.environ.get('SAAF_PASSWORD', 'saaf2024')
    )
}

def _check_credentials(username: str, password: str) -> bool:
    """Verifica credenciales con PBKDF2 + hmac.compare_digest (sin timing attack)."""
    stored = USERS.get(username, '')
    hashed = _hash_password(password)
    return hmac.compare_digest(stored, hashed)

def render_login():
    col1, col2, col3 = st.columns([1, 1.2, 1])
    with col2:
        st.markdown("<br><br>", unsafe_allow_html=True)
        st.markdown("## 🛡️ SAAF Pro")
        st.markdown("*Security Audit & Alert Framework*")
        st.markdown("---")
 
        with st.form("login_form"):
            username = st.text_input("Usuario", placeholder="admin")
            password = st.text_input("Contraseña", type="password")
            submitted = st.form_submit_button("Entrar", use_container_width=True)
 
        if submitted:
            if _check_credentials(username, password):
                st.session_state['saaf_authenticated'] = True
                st.session_state['saaf_username']      = username
                st.rerun()
            else:
                st.error("Usuario o contraseña incorrectos.")
 
        st.markdown("<br>", unsafe_allow_html=True)
        st.caption("Configurar credenciales con variables de entorno: SAAF_USER / SAAF_PASSWORD")


# =============================================================
# Navegacion
# =============================================================

NAV_ITEMS = {
    "🏠  Dashboard":    "dashboard",
    "🚨  Alertas":      "alerts",
    "📋  Historial":    "history",
    "⚙️  Configuración": "settings",
}

if render_enhancements is not None:
    _items = list(NAV_ITEMS.items())
    _items.insert(3, ("🧠  Auditoría IA", "enhancements"))
    NAV_ITEMS = dict(_items)

@st.cache_resource
def _init_database():
    """Inicializa la BD una sola vez por proceso — no en cada render."""
    from database import init_db
    init_db()

def render_sidebar():
    with st.sidebar:
        st.markdown("### 🛡️ SAAF Pro")
        st.caption(f"Usuario: {st.session_state.get('saaf_username', '')}")
        st.markdown("---")
        
        # Contadores rapidos en sidebar
        try:
            from database import get_dashboard_summary
            summary = get_dashboard_summary()
            col1, col2 = st.columns(2)
            with col1:
                st.metric("Sitios", summary['total_sites'])
                st.metric("🔴 Critico", summary['open_critical'])
            with col2:
                st.metric("Caidos", summary['sites_down'])
                st.metric("🟠 Alto", summary['open_high'])
        except Exception:
            pass
 
        st.markdown("---")
        
        # Menu de navegacion
        current = st.session_state.get('saaf_page', 'dashboard')
        for label, page_id in NAV_ITEMS.items():
            is_active = current == page_id
            if st.button(label, key=f"nav_{page_id}",
                         use_container_width=True,
                         type="primary" if is_active else "secondary"):
                st.session_state['saaf_page']         = page_id
                st.session_state['saaf_selected_site'] = None
                st.rerun()
 
        st.markdown("---")
        if st.button("🚪  Cerrar sesion", use_container_width=True):
            for key in list(st.session_state.keys()):
                del st.session_state[key]
            st.rerun()
            

# =============================================================
# Router principal
# =============================================================

def main():
    # Inicializar BD una sola vez
    _init_database()
 
    # Inicializar estado
    if 'saaf_authenticated' not in st.session_state:
        st.session_state['saaf_authenticated'] = False
    if 'saaf_page' not in st.session_state:
        st.session_state['saaf_page'] = 'dashboard'
    if 'saaf_selected_site' not in st.session_state:
        st.session_state['saaf_selected_site'] = None
 
    # Login
    if not st.session_state['saaf_authenticated']:
        render_login()
        return
 
    # App principal
    render_sidebar()
 
    page = st.session_state.get('saaf_page', 'dashboard')
 
    # Si hay un sitio seleccionado, mostrar detalle
    if st.session_state.get('saaf_selected_site'):
        render_site_detail(st.session_state['saaf_selected_site'])
    elif page == 'dashboard':
        render_dashboard()
    elif page == 'alerts':
        render_alerts()
    elif page == 'history':
        render_history()
    elif page == 'settings':
        render_settings()
    elif page == 'enhancements' and render_enhancements is not None:
        render_enhancements()
    else:
        render_dashboard()
 
 
if __name__ == '__main__':
    main()