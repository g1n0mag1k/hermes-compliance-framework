# AGENTS.md

## Cursor Cloud specific instructions

### Project overview
`hermes-compliance-framework` is a pure-Python project (Python 3.12). At the time of
environment setup it is **scaffolding only**: the package modules
(`hermes/__init__.py`, `hermes/agent.py`, `hermes/classifier.py`, `hermes/auditor.py`)
and the entrypoint `demo.py` are empty placeholders, `requirements.txt` is empty, and
there are no tests yet. There is no separate backend/frontend service — it is a single
Python package plus a `demo.py` entrypoint.

### Environment / dependencies
- The startup update script creates/refreshes a virtualenv at `.venv` and installs
  `requirements.txt` into it. Use this interpreter: `.venv/bin/python` (and `.venv/bin/pip`).
- Creating the venv requires the system package `python3.12-venv` (provided by the VM
  snapshot, not the update script). If `python3 -m venv .venv` ever fails with an
  `ensurepip is not available` error, install it with
  `sudo apt-get install -y python3.12-venv` and recreate the venv.

### Run / verify
- Run the entrypoint: `.venv/bin/python demo.py` (currently a no-op since `demo.py` is empty).
- Import smoke check: `.venv/bin/python -c "import hermes"`.
- Syntax/compile check across the package: `.venv/bin/python -m compileall hermes demo.py`.

### Lint / test
- No linter or test framework is configured yet (no `pyproject.toml`, `setup.cfg`,
  `pytest.ini`, `tox.ini`, `ruff`/`flake8` config, or `tests/` directory). Until tooling
  is added, use `compileall` (above) as a basic check. Once dependencies are introduced,
  add them to `requirements.txt` so the update script installs them automatically.
