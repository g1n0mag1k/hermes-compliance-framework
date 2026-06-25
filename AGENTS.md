# AGENTS.md

## Cursor Cloud specific instructions

### Project overview
`hermes-compliance-framework` is a pure-Python project (Python 3.12). It is an
early-stage codebase: the package modules (`hermes/__init__.py`, `hermes/agent.py`,
`hermes/classifier.py`, `hermes/auditor.py`) and the entrypoint `demo.py` are still
empty placeholders, so there is no runnable application UI or implemented redaction
logic yet. Dependencies, a `pytest` suite (`tests/`), and tooling config now exist.
Per the README, the intended product is a Streamlit-based PHI-redaction middleware
layer; that UI does not exist yet. It is a single Python package plus a `demo.py`
entrypoint — there is no separate backend/frontend service.

### Environment / dependencies
- The startup update script creates/refreshes a virtualenv at `.venv` and installs
  `requirements.txt` (runtime: spacy, streamlit, pydantic) and `requirements-dev.txt`
  (pytest, pytest-cov). Use this interpreter: `.venv/bin/python` (and `.venv/bin/pip`).
- Creating the venv requires the system package `python3.12-venv` (provided by the VM
  snapshot, not the update script). If `python3 -m venv .venv` ever fails with an
  `ensurepip is not available` error, install it with
  `sudo apt-get update && sudo apt-get install -y python3.12-venv` and recreate the venv.
- The README mentions Redis and the spaCy `en-core-web-lg` model, but no current code
  imports/uses them, so neither is required to run the tests or the entrypoint today.

### Run / verify
- Run the entrypoint: `.venv/bin/python demo.py` (currently a no-op since `demo.py` is empty).
- Import smoke check: `.venv/bin/python -c "import hermes, spacy, streamlit, pydantic"`.
- Syntax/compile check across the package: `.venv/bin/python -m compileall hermes demo.py`.
- The Streamlit CLI is installed (`.venv/bin/streamlit --version`), but there is no
  Streamlit app module to run yet.

### Lint / test
- Tests: `.venv/bin/python -m pytest` (config in `pytest.ini`, tests live in `tests/`).
  Coverage: `.venv/bin/python -m pytest --cov=hermes`.
- No local linter is configured to run here. Static analysis is wired through DeepSource
  (`.deepsource.toml`, python + secrets analyzers) and a `pip-audit` GitHub Action
  (`.github/workflows/dependency-audit.yml`) that runs on PRs to `main`; these run in CI,
  not locally.
- When introducing new runtime deps, add them to `requirements.txt` (dev/test deps to
  `requirements-dev.txt`) so the update script installs them automatically.
