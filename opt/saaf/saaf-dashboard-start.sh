#!/bin/bash
PYTHON="/home/admin_ubuntu/Desktop/proyecto_saaf/venv/bin/streamlit"
APP="/home/admin_ubuntu/Desktop/proyecto_saaf/opt/saaf/app.py"
exec "$PYTHON" run "$APP" --server.port 8501 --server.headless true