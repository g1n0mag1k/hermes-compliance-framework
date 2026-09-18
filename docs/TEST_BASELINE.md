# Hermes Relay — Test Baseline

| Field | Value |
|---|---|
| **Date** | 2026-09-18 |
| **Python** | 3.12.3 |
| **pytest** | 8.3.5 (from `requirements-dev.txt`) |
| **Environment** | `/workspace/.venv` — `pip install -r requirements.txt -r requirements-dev.txt` + `python -m spacy download en_core_web_sm` |
| **Command** | `.venv/bin/python -m pytest -q` |

## Results (executed)

| Metric | Count |
|---|---|
| **Collected** | 530 |
| **Passed** | 530 |
| **Failed** | 0 |
| **Skipped** | 0 |
| **Errors** | 0 |
| **Collection failures** | 0 |

## Security regression suite

| Command | Result |
|---|---|
| `.venv/bin/python -m pytest -q tests/security/test_phi_never_egresses.py` | 16 passed |

## Known environment limitations

- Initial Cloud Agent VM had no `python3.12-venv` or spaCy model; both were installed before the baseline run.
- Tests use ephemeral gateway signing keys unless `HERMES_GATEWAY_KEYSTORE_*` is set in a test fixture.
- Gateway production signing enforcement is validated in `tests/test_gateway_failures.py` with explicit keystore fixtures.

## Notes

- Do not infer pass counts from `def test_` grep alone — always run pytest collection and execution.
- Test floor after gateway evidence export: **530** (must not decrease).
