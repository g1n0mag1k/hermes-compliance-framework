# AGENTS.md

## Build rule

Always read `CURSORRULES.md` before touching any code. It defines build order, hard constraints, and current project state.

## Project overview

Hermes Relay is a local-first PHI enforcement gateway for MSPs serving HIPAA-covered entities. It provides deterministic PHI/PII detection, redaction, and cryptographically signed compliance evidence — without sending PHI to external infrastructure.

The repository contains two FastAPI services:

| Service | Path | Default port | Role |
|---------|------|--------------|------|
| Hermes Relay API | `hermes/` | 8787 | PHI scrubbing (`/v1/scrub`), human review (`/v1/review`), HMAC attestation chain, webhooks |
| AI Enforcement Gateway | `gateway/` | 8788 | Fail-closed proxy for OpenAI, Azure OpenAI, and Anthropic — inspects and redacts PHI in outbound AI requests |

Additional components: React dashboard (`dashboard/`), Next.js landing page (`landing/`), CLI entry points (`hermes-relay`, `hermes-verify` via `pyproject.toml`).

## Environment

- **Python:** 3.12
- **Virtualenv:** `.venv` (created by the Cloud Agent update script)
- **Runtime deps:** `requirements.txt`
- **Dev/test deps:** `requirements-dev.txt`

Use `.venv/bin/python` and `.venv/bin/pip` for all commands.

### Required environment variables

| Variable | Purpose |
|----------|---------|
| `HERMES_API_KEY` | Tenant auth for `/v1/scrub` and `/v1/review` |
| `HERMES_SIGNING_KEY` | HMAC signing key for the attestation chain (hex string) |
| `HERMES_VAULT_KEY` | AES-256-GCM key for the reversible token vault |

See `CURSORRULES.md` for optional variables (`HERMES_WEBHOOK_URL`, Drata CCT, gateway settings, etc.).

## Run / verify

```bash
# Hermes Relay API (port 8787)
.venv/bin/hermes-relay serve

# Gateway (port 8788)
.venv/bin/uvicorn gateway.app:app --host 127.0.0.1 --port 8788
```

Import smoke check:

```bash
.venv/bin/python -c "import hermes, gateway, fastapi, pydantic"
```

## Tests

```bash
.venv/bin/python -m pytest
```

Target: **562+ tests passing, 0 failures**. The test floor must never decrease.

Coverage (optional):

```bash
.venv/bin/python -m pytest --cov=hermes
```

## Key modules

- `hermes/classifier.py` — PHI detection engine (spaCy NER, Presidio, regex, Luhn)
- `hermes/attestation.py` — HMAC-SHA256 compliance receipt chain (SQLite)
- `hermes/api.py` — FastAPI application and `/v1/*` endpoints
- `gateway/pipeline.py` — Gateway intercept pipeline (read before modifying `gateway/`)

## Dependencies

All runtime dependencies use exact version pins (`==`). When adding deps, update both `requirements.txt` and `pyproject.toml`.
