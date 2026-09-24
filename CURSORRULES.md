# Hermes Relay — Build Plan & AI Rules

## What This Is
Local-first PHI detection and compliance evidence tool for MSPs 
serving HIPAA-covered entities. Includes Drata Custom Connections and
Tests (CCT) export code that is contract-tested against mocks only and
NOT live-validated (see "Drata Integration — Honest State").

Owner: Andrew Rogers / Sui-Generis LLC  
Target customer: MSPs managing HIPAA compliance for healthtech clients  
Exit target: Drata or Nightfall acquisition

---

## Current State
- 562 tests passing, 0 failures
- 16 of 18 HIPAA Safe Harbor categories covered (P and Q are 
  reference_only — binary artifacts, acknowledged)
- FastAPI /v1/scrub and /v1/review endpoints functional
- HMAC-SHA256 attestation chain wired and persisting to SQLite
- Generic webhook dispatcher working in webhooks.py
- Drata CCT: TWO active implementations exist. Path A: hermes/webhooks.py dispatch_drata_cct() — flat JSON, no retry, no idempotency. Path B: gateway/evidence_export/ DrataExporter — {"data":...} wrapper, idempotency key, retries. Both use HERMES_DRATA_CCT_URL + HERMES_DRATA_API_KEY. CONTRACT-TESTED against mocks only. NOT live-validated.
- pyproject.toml defines the hermes-relay and hermes-verify CLI entry
  points (local install via pip/pipx from the repo). PyPI availability: UNKNOWN

---

## Build Order — Do Not Skip Steps

### Step 1 — pyproject.toml + pipx install
Create pyproject.toml with hermes-relay CLI entry point
Add hermes-relay install-service subcommand for systemd
Target: pipx install hermes-relay works on Linux

### Step 3 — Demo preparation
90-second terminal demo script
PHI caught — receipt generated — Drata CCT export attempted (contract-tested
against mocks only; live Drata acceptance is UNKNOWN — see Honest State)

---

## Hard Rules — Never Violate These

- PYTEST MUST STAY GREEN. 562 tests is the floor. Never decrease.
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
- hermes/webhooks.py — generic webhooks and dispatch_drata_cct() (Drata Path A)
- hermes/api.py — /v1/scrub and webhook/CCT wiring
- tests/test_webhooks.py — webhook and Drata CCT contract tests
- gateway/evidence_export/event.py — gateway evidence event model (Drata Path B)
- gateway/evidence_export/exporters.py — DrataExporter (Drata Path B)
- gateway/evidence_export/dispatch.py — gateway evidence export dispatch (Drata Path B)
- tests/test_gateway_evidence_export.py — gateway evidence export / DrataExporter contract tests

---

## Environment Variables
HERMES_API_KEY        — tenant auth for /v1/scrub and /v1/review
HERMES_SIGNING_KEY    — HMAC signing key for attestation chain
HERMES_VAULT_KEY      — AES-256-GCM vault key
HERMES_WEBHOOK_URL    — existing generic webhook target
HERMES_DRATA_CCT_URL  — Drata CCT endpoint
HERMES_DRATA_API_KEY  — Drata API key for CCT auth

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
NOTE: The root Caddyfile was deleted in commit 9f99c97. docker-compose.yml still references it. This must be resolved before docker compose up will succeed.
tests/test_gateway.py       — gateway app/pipeline/policy/provider tests
                              (one of several gateway test files)

Current test count: 562 passing
Gateway supports: OpenAI, Azure OpenAI, Anthropic
Auth: Bearer (OpenAI), api-key (Azure), x-api-key (Anthropic)
Recursive JSON inspection covers tool arguments, nested blocks,
streaming deltas — per Perplexity field spec Sept 17 2026
NOTE: Streaming/SSE is NOT currently enforced — streaming requests are not
inspected field-by-field in real time (see docs/CURRENT_LIMITATIONS.md).

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

## Drata Integration — Honest State (updated 2026-09-24)
STATUS: CONTRACT-TESTED | NOT LIVE-VALIDATED | NOT PARTNER-APPROVED | NOT PARTNER-CONNECTION

Two Drata export paths exist. They must not be conflated with a validated integration:
- Path A (scrub): dispatch_drata_cct() in hermes/webhooks.py — flat JSON payload, no retries, no idempotency key
- Path B (gateway): DrataExporter in gateway/evidence_export/ — {"data":...} wrapper, X-Idempotency-Key, 2 retries
- Dashboard: "Check Drata Status" button + POST /api/v1/drata/config do NOT call Drata. The endpoint returns HTTP 501 not_implemented with state NOT_CONFIGURED or CONFIGURED derived from HERMES_DRATA_CCT_URL. No connection test exists, so CONNECTION_TEST_* states are never reported.
- Payload shape mismatch between Path A and Path B is unresolved — live Drata behavior unknown.
- No per-workspace Drata config. Both paths use a single global HERMES_DRATA_CCT_URL.

Never claim: live Drata validation, Partner Connection, OAuth, approved control mappings, or per-tenant Drata routing.

## Drata Integration State

LIVE DRATA VALIDATION IS NOT CLAIMED UNLESS A REAL DRATA TENANT
HAS BEEN SUCCESSFULLY TESTED AND THE RESULT IS COMMITTED.

Two active Drata export paths exist:
- Path A: hermes/webhooks.py dispatch_drata_cct() — flat JSON,
  background task, no retries, no idempotency. Called from
  /v1/scrub and /v1/trial-scan.
- Path B: gateway/evidence_export/exporters.py DrataExporter —
  {data:…} wrapper, runs inline in the gateway event loop, 2
  retries, per-event X-Idempotency-Key. Called from the gateway.

These two paths send different payload shapes. Whether Drata
accepts either shape is UNKNOWN.

POST /api/v1/drata/config and the 'Check Drata Status' dashboard
button do not contact Drata. The endpoint returns HTTP 501 with the
env-derived config state and must never claim success.

ANTI-HALLUCINATION RULE:
NEVER invent Drata API endpoints, request schemas, permissions,
OAuth flows, control IDs, evidence IDs, connection IDs, resource
IDs, or Partner Connection requirements. If Drata documentation
or a real Drata environment does not establish a detail, label
it UNKNOWN and do not implement it.

## Git Rules

Every implementation session must:
- run git pull origin main first
- verify git status is clean before starting
- run targeted tests
- run the full pytest suite (floor: 562 passed — must not decrease)
- inspect git diff and git status before staging
- use git add -p to review staged changes
- create a descriptive commit message
- push to origin/main
- verify push with git log --oneline -3
- NEVER force push
- NEVER rewrite existing commits
- NEVER push secrets
- NEVER push to cursor/* branches without explicit instruction
