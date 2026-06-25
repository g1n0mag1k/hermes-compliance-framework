# =============================================================================
# conftest.py — Pytest root configuration
# =============================================================================
# Ensures that the project root (the directory containing the `hermes/`
# package) is on sys.path regardless of where pytest is invoked from.
# This resolves `ModuleNotFoundError: No module named 'hermes'` in both:
#   - Local dev runs:      pytest tests/
#   - CI container runs:   pytest (CWD = /app)
# =============================================================================

import sys
import os

# Insert the project root at the front of sys.path
sys.path.insert(0, os.path.dirname(__file__))
