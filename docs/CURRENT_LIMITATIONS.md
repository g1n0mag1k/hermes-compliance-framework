# Current Limitations

Customer-facing quality control for Hermes Relay as of 2026-09-18.

## Routing and scope

- **Routing requirement:** PHI enforcement applies only to traffic routed through the Hermes Gateway. Direct calls to OpenAI/Azure/Anthropic bypass Hermes.
- **Three supported providers:** OpenAI, Azure OpenAI, Anthropic only. No generic AI proxy.
- **Legacy `/v1/scrub` path:** Separate integration API with V1 HMAC receipts; not a substitute for gateway routing.
- **Deployment:** Limitations of the Docker Compose deployment are listed in `DEPLOYMENT.md` §16. They include: no built-in TLS, a single gateway instance only, and Azure `api-version` query values detected as PHI dates.

## Enforcement modes

- **Default policy (`HIPAA_STRICT`):** `text_action = REDACT` — detected PHI is redacted and forwarded unless policy is changed.
- **Production block policy (`HIPAA_PRODUCTION_BLOCK`):** Set `HERMES_GATEWAY_POLICY=HIPAA_PRODUCTION_BLOCK` for PHI-detected → BLOCK.
- Hermes can **redact or block** detected PHI according to policy. Do not describe Hermes as universally "blocking PHI."

## Content and detection

- **No streaming/SSE enforcement** — streaming requests are not inspected field-by-field in real time.
- **Binary/multimodal content:** Blocked (not inspected) per `binary_action`; not parsed for PHI.
- **Detector scope:** 16/18 HIPAA Safe Harbor categories in documented text scope; categories P and Q are reference-only for binary artifacts.
- **English-language NER:** spaCy `en_core_web_sm` — non-English PHI may not be detected.
- **No claim of complete Safe Harbor de-identification** or "detects all PHI."

## Evidence and storage

- **SQLite storage** — mutable filesystem storage; not WORM/immutable.
- **HMAC-SHA256 receipts** (`/v1/scrub`, `/v1/telemetry/receipt`, canary audit) require the signing key for verification; they are not third-party non-repudiable without that key.
- **Receipt timestamps** come from the host or CI runner clock. External RFC 3161 timestamping is not enabled on the per-request issue path.
- **External anchoring not connected** (RFC 3161 TSA, SCITT, S3 Object Lock paths exist as stubs only).
- **Persistent gateway signing key required in production** (`HERMES_GATEWAY_KEYSTORE_PATH` + passphrase).
- **Receipt persistence failure:** If persistence fails after upstream forward, client receives HTTP 503; upstream may have already received data.

## Upstream failures

- **PRE-FORWARD SECURITY FAILURE:** BLOCK/detector/parse/policy failures — Hermes guarantees no upstream request (`forwarded=false`).
- **UPSTREAM TRANSPORT FAILURE:** Connection/timeout/5xx after forward — Hermes cannot retroactively guarantee zero bytes were transmitted (`forwarded=true` on receipt).

## Integrations

- **Canary passes** demonstrate that the scrubber caught the synthetic test vectors used; they do not measure recall on unstructured real-world free text.
- **`canary-action`** does not transmit canaries to Sentry today; it runs them through a local scrub probe shaped like Sentry events.
- **Gateway evidence export** — optional webhook and Drata CCT exporters via `gateway/evidence_export/` (see `GATEWAY_EVIDENCE_EXPORT.md`). Best-effort post-decision export; exporter outage does not affect enforcement.
- **Live Drata gateway integration** — Drata adapter implemented and contract-tested; live tenant validation pending. Hermes sends metadata-only records wrapped in `{"data": {...}}`; never raw PHI.
- **Canonical Drata connector** — `DrataConnector` in `gateway/evidence_export/drata_connector.py`. `send_test_evidence()` returns `UNSUPPORTED` without any network call. `test_connection()` is an offline structural check only (URL set, `https://`, API key present → `CONFIGURED`; otherwise `NOT_CONFIGURED` or `CONFIG_INVALID`); `live_validated` is always `false` and live connection validation is `UNSUPPORTED`. `send_evidence()` refuses non-`https://` CCT URLs.
- **`/v1/scrub` Drata export (legacy)** — separate V1 path via `dispatch_drata_cct()` in `hermes/webhooks.py`, kept for backward compatibility. It sends a different, flat payload shape than the canonical connector, with no retries and no idempotency key.

## Multi-tenancy

- Full detail: [MULTI_TENANCY.md](MULTI_TENANCY.md).
- Isolated per workspace: API key, V1 attestation chain and its HMAC key, vault DB and its key, canary DB, trial quota, gateway policy, AI provider credentials (encrypted), evidence-outbox rows, gateway receipts (rows in the workspace chain DB).
- Not isolated: gateway V2 receipts share one deployment-wide Ed25519 signing key (each signed payload carries `workspace_id`); Drata CCT config is global; PSA credentials are per-tenant but unencrypted.
- Workspace chains/vaults that already held data before per-workspace keys keep using the deployment-wide key so historical receipts still verify (`key_scheme: global`).
- Storage is SQLite on a single host; multi-host shared storage is not supported.
