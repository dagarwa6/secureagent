#!/bin/bash
# Wrapper script for Streamlit preview server
# Changes to the project directory before launching (required when spawned
# from a sandbox environment that sets an inaccessible working directory)

PROJECT_DIR="/Users/devansh/Desktop/Georgia State/Spring 2026 Classes/CyberSecurity Experience/secureagent"
STREAMLIT="/Users/devansh/Library/Python/3.9/bin/streamlit"

cd "$PROJECT_DIR" || exit 1
exec "$STREAMLIT" run app/streamlit_app.py --server.port 8501 --server.headless true
