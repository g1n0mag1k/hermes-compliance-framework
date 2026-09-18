# Current Limitations

Customer-facing quality control for Hermes Relay as of 2026-09-18.

## Routing and scope

- **Routing requirement:** PHI enforcement applies only to traffic routed through the Hermes Gateway. Direct calls to OpenAI/Azure/Anthropic bypass Hermes.
- **Three supported providers:** OpenAI, Azure OpenAI, Anthropic only. No generic AI proxy.
- **Legacy `/v1/scrub` path:** Separate integration API with V1 HMAC receipts; not a substitute for gateway routing.

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
- **External anchoring not connected** (RFC 3161 TSA, SCITT, S3 Object Lock paths exist as stubs only).
- **Persistent gateway signing key required in production** (`HERMES_GATEWAY_KEYSTORE_PATH` + passphrase).
- **Receipt persistence failure:** If persistence fails after upstream forward, client receives HTTP 503; upstream may have already received data.

## Upstream failures

- **PRE-FORWARD SECURITY FAILURE:** BLOCK/detector/parse/policy failures — Hermes guarantees no upstream request (`forwarded=false`).
- **UPSTREAM TRANSPORT FAILURE:** Connection/timeout/5xx after forward — Hermes cannot retroactively guarantee zero bytes were transmitted (`forwarded=true` on receipt).

## Integrations

- **Gateway evidence export** — optional webhook and Drata CCT exporters via `gateway/evidence_export/` (see `GATEWAY_EVIDENCE_EXPORT.md`). Best-effort post-decision export; exporter outage does not affect enforcement.
- **Live Drata gateway integration** — contract-tested via mocks only; production Drata connectivity must be validated per deployment.
- **`/v1/scrub` Drata export** — separate V1 path via `dispatch_drata_cct()` in `hermes/webhooks.py`.

## Multi-tenancy

- Workspace isolation exists for gateway receipts and API keys.
- Documentation previously mixed "single-tenant deployment" with workspace isolation — both are true: one deployment per customer environment, multiple workspaces per deployment.
