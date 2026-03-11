#!/Library/Developer/CommandLineTools/usr/bin/python3
"""
Streamlit launcher wrapper.
Changes to the project directory before importing streamlit (which calls
os.getcwd() on startup). This avoids PermissionError when the process is
spawned from an inaccessible working directory.
"""
import os
import sys

PROJECT_DIR = "/Users/devansh/Desktop/Georgia State/Spring 2026 Classes/CyberSecurity Experience/secureagent"

# ── Step 1: Move to an accessible directory BEFORE any other imports ──────────
os.chdir(PROJECT_DIR)

# ── Step 2: Add our site-packages so streamlit is importable ─────────────────
sys.path.insert(0, "/Users/devansh/Library/Python/3.9/lib/python/site-packages")

# ── Step 3: Set argv as if we ran: streamlit run app/streamlit_app.py ─────────
sys.argv = [
    "streamlit",
    "run",
    "app/streamlit_app.py",
    "--server.port=8501",
    "--server.headless=true",
]

# ── Step 4: Launch streamlit ───────────────────────────────────────────────────
from streamlit.web.cli import main
sys.exit(main())
