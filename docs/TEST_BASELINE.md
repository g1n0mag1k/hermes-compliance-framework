# Hermes Relay — Test Baseline

| Field | Value |
|---|---|
| **Date** | 2026-11-18 |
| **Python** | 3.12.3 |
| **pytest** | 8.3.5 (from `requirements-dev.txt`) |
| **Environment** | fresh clone of `main` (`90f979f`) — `pip install -r requirements.txt -r requirements-dev.txt` + `python -m spacy download en_core_web_sm` |
| **Command** | `python -m pytest -q` |

## Results (executed)

| Metric | Count |
|---|---|
| **Collected** | 881 |
| **Passed** | 869 |
| **XFailed (strict, documented findings)** | 12 |
| **Failed** | 0 |
| **Skipped** | 0 |
| **Errors** | 0 |
| **Collection failures** | 0 |

The remaining `xfail`s are intentional: each documents one open, named bug in `tests/test_audit_findings.py` (strict mode, so an accidental fix without removing the marker fails the suite). See `docs/CURRENT_LIMITATIONS.md` and the findings list in that test file for what each one is. Five gateway-surface findings (inspector key/double-count bugs, `validate_path` dot-segment escape, unfiltered request headers, stale `content-encoding` header) were fixed same-day — down from 17.

## Security regression suite

| Command | Result |
|---|---|
| `python -m pytest -q tests/security/test_phi_never_egresses.py` | 18 passed |

## Known environment limitations

- A fresh environment needs the spaCy model (`python -m spacy download en_core_web_sm`) before collection succeeds — without it, every module importing `hermes/classifier.py` fails collection with a `RuntimeError`, not a normal test failure.
- Tests use ephemeral gateway signing keys unless `HERMES_GATEWAY_KEYSTORE_*` is set in a test fixture.
- Gateway production signing enforcement is validated in `tests/test_gateway_failures.py` with explicit keystore fixtures.

## Notes

- Do not infer pass counts from `def test_` grep alone — always run pytest collection and execution.
- Test floor per `CURSORRULES.md` / `AGENTS.md`: **836 passed** (must not decrease). Current count (869 passed, 12 xfailed) is above floor as of this baseline — 15 new tests added same-day covering the new reversible-redaction vault wiring (`/v1/scrub-reversible`, `/v1/vault/retrieve`, `hermes/vault_access_log.py`), plus 5 xfail markers removed same-day as their underlying gateway bugs were fixed.
- Previous baseline (2026-09-18): 532 passed. This file had not been refreshed since, despite the floor and test count moving substantially — re-run and update this file whenever the floor in `CURSORRULES.md`/`AGENTS.md` changes, not on a fixed schedule.
