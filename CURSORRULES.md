# Hermes Relay — Build Plan & AI Rules

## What This Is
Local-first PHI detection and compliance evidence tool for MSPs 
serving HIPAA-covered entities. Integrates with Drata via Custom 
Connections and Tests (CCT) API to push audit evidence automatically.

Owner: Andrew Rogers / Sui-Generis LLC  
Target customer: MSPs managing HIPAA compliance for healthtech clients  
Exit target: Drata or Nightfall acquisition

---

## Current State
- 544 tests passing, 0 failures
- 16 of 18 HIPAA Safe Harbor categories covered (P and Q are 
  reference_only — binary artifacts, acknowledged)
- FastAPI /v1/scrub and /v1/review endpoints functional
- HMAC-SHA256 attestation chain wired and persisting to SQLite
- Generic webhook dispatcher working in webhooks.py
- No Drata CCT integration yet
- No pipx install path yet

---

## Build Order — Do Not Skip Steps

### Step 1 — Drata CCT Integration (CURRENT)
Add dispatch_drata_cct() to hermes/webhooks.py
Wire it into /v1/scrub in hermes/api.py alongside dispatch_webhook
Add tests to tests/test_webhooks.py
Target: 119+ tests passing after this step

### Step 2 — pyproject.toml + pipx install
Create pyproject.toml with hermes-relay CLI entry point
Add hermes-relay install-service subcommand for systemd
Target: pipx install hermes-relay works on Linux

### Step 3 — MSP Integration Guide
Create docs/MSP_INTEGRATION.md
One-page guide showing Hermes + Drata setup in under 10 minutes

### Step 4 — Demo preparation
90-second terminal demo script
PHI caught — receipt generated — evidence in Drata dashboard

---

## Hard Rules — Never Violate These

- PYTEST MUST STAY GREEN. 544 tests is the floor. Never decrease.
- Never add external API calls to classifier.py or the scanner
- Never remove HERMES_SIGNING_KEY or HERMES_API_KEY checks
- Never add ML inference to the detection pipeline
- All new dependencies use exact version pins (==)
- Never rename existing variables, functions, or classes
- No Electron, no Streamlit in production paths
- One change at a time — no refactoring unless explicitly requested
- Show BEFORE/AFTER/REASON for every code change

---

## Key Files
- hermes/classifier.py — PHI detection engine. Do not touch without explicit instruction.
- hermes/attestation.py — HMAC chain. Do not touch without explicit instruction.
- hermes/webhooks.py — Current session target for Step 1
- hermes/api.py — Wire CCT after webhooks.py is done
- tests/test_webhooks.py — Add CCT tests here

---

## Environment Variables
HERMES_API_KEY        — tenant auth for /v1/scrub and /v1/review
HERMES_SIGNING_KEY    — HMAC signing key for attestation chain
HERMES_VAULT_KEY      — AES-256-GCM vault key
HERMES_WEBHOOK_URL    — existing generic webhook target
HERMES_DRATA_CCT_URL  — Drata CCT endpoint (Step 1 target)
HERMES_DRATA_API_KEY  — Drata API key for CCT auth (Step 1 target)

### Gateway — AI Enforcement Proxy (ADDED Sept 17 2026)
gateway/app.py              — FastAPI gateway application
gateway/pipeline.py         — full intercept pipeline
gateway/inspector.py        — recursive JSON field inspection
gateway/providers.py        — OpenAI, Azure OpenAI, Anthropic
gateway/policy.py           — allow/block/redact policy engine
gateway/evidence.py         — evidence generation per decision
gateway/credentials.py      — credential injection, auth stripping
gateway/response_headers.py — provider disclosure header stripping
Dockerfile + docker-compose.yml (repo root) — the one container deployment
                              (API + gateway, one image); see docs/DEPLOYMENT.md
tests/test_gateway.py       — 568 gateway tests

Current test count: 544 passing
Gateway supports: OpenAI, Azure OpenAI, Anthropic
Auth: Bearer (OpenAI), api-key (Azure), x-api-key (Anthropic)
Recursive JSON inspection covers tool arguments, nested blocks,
streaming deltas — per Perplexity field spec Sept 17 2026

Do not modify gateway/ without reading gateway/pipeline.py first.

### Pricing (Updated Sept 17 2026)
Small MSP (1-10 employees):
  Free 30-Day Sprint
  90-Day Pilot: $750/month ($2,250 total)
  Founding Partner: $1,500/month locked 12 months

Mid MSP (10-30 employees):
  Free 30-Day Sprint
  90-Day Pilot: $1,500/month ($4,500 total)
  Founding Partner: $2,500/month locked 12 months

Large MSP (30+ employees):
  Free 30-Day Sprint
  90-Day Pilot: $1,500/month ($4,500 total)
  Founding Partner: $3,000/month locked 12 months
