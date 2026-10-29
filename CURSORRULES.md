# Hermes Relay — Build Plan & AI Rules

## What This Is
Local-first PHI detection and compliance evidence tool for HIPAA-covered
entities, their business associates, and the MSPs that serve them. Includes Drata Custom Connections and
Tests (CCT) export code that is contract-tested against mocks only and
NOT live-validated (see "Drata Integration — Honest State").

Owner: Andrew Rogers / Sui-Generis  
Target customer: MSPs managing HIPAA compliance for healthtech clients  
Exit target: Drata or Nightfall acquisition

---

## Current State
- 836 tests passing, 0 failures (17 strict xfails document open audit findings)
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

- PYTEST MUST STAY GREEN. 836 tests is the floor. Never decrease.
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
- hermes/tenant_keys.py — per-workspace key derivation + key_scheme migration guard. See docs/MULTI_TENANCY.md.
- tests/test_multi_tenant.py — multi-tenant isolation, RBAC, per-workspace policy/credentials
- scripts/install_workspaces.py — OBSOLETE one-time bootstrap; overwrites core files with an old snapshot. Guarded; never run it.
- hermes/webhooks.py — generic webhooks and dispatch_drata_cct() (Drata Path A)
- hermes/api.py — /v1/scrub and webhook/CCT wiring
- tests/test_webhooks.py — webhook and Drata CCT contract tests
- gateway/evidence_export/event.py — gateway evidence event model (Drata Path B)
- gateway/evidence_export/drata_connector.py — DrataConnector, canonical Drata connector (Drata Path B)
- gateway/evidence_export/exporters.py — DrataExporter, thin wrapper around DrataConnector
- hermes/drata_state.py — DrataConfigState state machine shared by hermes/api.py and DrataConnector
- gateway/evidence_export/dispatch.py — gateway evidence export dispatch (Drata Path B)
- gateway/evidence_export/outbox.py — persistent Drata evidence outbox, retry/dead-letter (Drata Path B)
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
NOTE: The root Caddyfile was deleted in commit 9f99c97. docker-compose.yml no longer references it (resolved). docker compose up succeeds without a Caddyfile.
scripts/demo.py             — Streamlit investor demo (run: streamlit run scripts/demo.py)
scripts/install_workspaces.py — bootstrap workspace installer (moved from repo root)
tests/test_gateway.py       — gateway app/pipeline/policy/provider tests
                              (one of several gateway test files)

Current test count: 836 passing
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
- Path B (gateway, CANONICAL): DrataConnector in gateway/evidence_export/drata_connector.py — {"data":...} wrapper, X-Idempotency-Key, 2 retries. DrataExporter in exporters.py is a thin wrapper around it. send_test_evidence() returns UNSUPPORTED (no network call). test_connection() is an offline STRUCTURAL check only (NOT_CONFIGURED / CONFIG_INVALID / CONFIGURED, live_validated always False); test_connection(live=True) returns UNSUPPORTED. send_evidence() refuses non-https CCT URLs with a warning.
- Path A is LEGACY: kept unchanged for backward compatibility, not routed through DrataConnector.
- POST /api/v1/drata/config does NOT call Drata. It returns HTTP 501 not_implemented with state NOT_CONFIGURED, CONFIG_INVALID, or CONFIGURED from DrataConnector.test_connection() (URL set, https, API key present). No live connection test exists, so CONNECTION_TEST_* / CONNECTION_* states are never reported. It is kept but no longer used by the dashboard.
- GET /v1/integrations/drata/status (org_admin / operator; legacy msp_admin / msp_tech) does NOT call Drata. It returns configured, connection_state (offline test_connection() state), live_validated=false, transport="CCT", partner_connection=false, and the caller workspace's outbox counts (pending incl. PROCESSING / exported / dead_letter), last_exported_at, and sanitized last_error. Outbox fields are null if the outbox cannot be read. The dashboard "Check Drata Status" button calls this endpoint; CONNECTED / SYNCING labels are reserved and never shown.
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
  {data:…} wrapper, 2 retries, per-event X-Idempotency-Key. Called
  from the gateway via the persistent evidence outbox
  (gateway/evidence_export/outbox.py): events are enqueued to local
  SQLite after the receipt is persisted and flushed to Drata in a
  background task after the response is sent. Whether Drata honors
  X-Idempotency-Key is UNKNOWN.

These two paths send different payload shapes. Whether Drata
accepts either shape is UNKNOWN.

POST /api/v1/drata/config, GET /v1/integrations/drata/status, and
the 'Check Drata Status' dashboard button do not contact Drata. They
report env-derived config state and local outbox counts only and must
never claim success, live validation, or a Partner Connection.

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
- run the full pytest suite (floor: 836 passed — must not decrease)
- inspect git diff and git status before staging
- use git add -p to review staged changes
- create a descriptive commit message
- push to origin/main
- verify push with git log --oneline -3
- NEVER force push
- NEVER rewrite existing commits
- NEVER push secrets
- NEVER push to cursor/* branches without explicit instruction
