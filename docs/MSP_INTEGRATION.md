# Hermes Relay — MSP Integration Guide

**Setup time: under 10 minutes**
**Requires: Python 3.12+, pipx, a Drata account with Custom Connections and Tests enabled and the required permissions**

> This guide covers the pipx + systemd install. The supported container
> deployment (API + gateway, persistent keystore, receipt verification) is
> [`DEPLOYMENT.md`](./DEPLOYMENT.md).

---

## What This Does

Hermes Relay runs inside your client's environment. When Drata export is
configured, it sends metadata-only PHI detection evidence from each scan to
the client's Drata account via the Custom Connections and Tests (CCT) API.
Exporter failures do not block scan results.

Every `/v1/scrub` scan generates a signed, hash-chained V1 compliance receipt
(HMAC-SHA256; verification requires the shared signing key) documenting:
- Which PHI identifiers were found (16 of 18 HIPAA Safe Harbor categories)
- Which CFR citation applies to each finding
- What action was taken (redaction to typed placeholders)
- Chain linkage via HMAC-SHA256 over prior receipts in SQLite

---

## The AI Gateway

Hermes now includes a transparent AI enforcement gateway. Instead of requiring applications to call /v1/scrub explicitly, the gateway sits between your client's applications and their AI provider — OpenAI, Azure OpenAI, or Anthropic.

Every request is inspected before it reaches the model:
- PHI detected → redacted or blocked according to policy (default dev: REDACT; design partner: BLOCK via `HERMES_GATEWAY_POLICY=HIPAA_PRODUCTION_BLOCK`)
- Clean request → forwarded to AI provider
- Every decision → V2 gateway receipt (Ed25519 / COSE_Sign1, public-key
  verifiable via `hermes-verify`; local SQLite chain)
- `/v1/scrub` evidence → may push to Drata CCT when configured (`HERMES_DRATA_CCT_URL`)
- Gateway evidence → V2 receipts stored locally **and** optionally exported via webhook/Drata when configured (see `docs/GATEWAY_EVIDENCE_EXPORT.md`)
- Fail-closed for defined failure classes (detector/parse/binary/policy) — upstream transport failures are documented separately

Supported providers:
- OpenAI (/v1/chat/completions, /v1/assistants, /v1/threads, /v1/audio/transcriptions)
- Azure OpenAI (/openai/deployments/, /openai/v1/)
- Anthropic (/v1/messages, /v1/messages/batches)

Gateway configuration (add to ~/.env.hermes):
  HERMES_OPENAI_API_KEY=your-openai-key
  HERMES_ANTHROPIC_API_KEY=your-anthropic-key
  HERMES_AZURE_OPENAI_KEY=your-azure-key
  HERMES_AZURE_OPENAI_ENDPOINT=your-azure-endpoint

Start the gateway:
  hermes-relay serve --gateway

### Starting both services

    hermes-relay serve --both

This starts the Hermes scrub API (port 8787) and the AI enforcement gateway
(port 8788) together. Press Ctrl+C to stop both.

Provider disclosure protection: Hermes strips all provider-identifying response headers so clients cannot detect which AI provider is behind the gateway.

---

## Step 1 — Install Hermes Relay

On the client machine:

    pipx install hermes-relay

PyPI availability of `hermes-relay` is UNKNOWN. To install from a local
checkout of this repository instead, run `pipx install .` from the repository
root.

Verify:

    hermes-relay version

Expected output:

    Hermes Relay v1.0.0
    hermesrelay.dev | Sui-Generis

---

## Step 2 — Configure Environment Variables

    HERMES_API_KEY=your-secure-api-key-here
    HERMES_SIGNING_KEY=your-64-char-hex-signing-key-here
    HERMES_VAULT_KEY=your-64-char-hex-vault-key-here
    HERMES_DRATA_CCT_URL=https://public-api.drata.com/public/v2/custom-connections/YOUR_CONNECTION_ID/resources/YOUR_RESOURCE_ID/records
    HERMES_DRATA_API_KEY=your-drata-api-key-here

Generate secure keys:

    python3 -c "import secrets; print(secrets.token_hex(32))"

Run that twice — once for HERMES_SIGNING_KEY, once for HERMES_VAULT_KEY.

---

## Step 3 — Set Up Drata Custom Connection

In the client Drata account:

1. Go to Connections in the left navigation
2. Click Create connection (top right)
3. Name it: Hermes Relay — PHI Detection
4. Copy the Connection ID from the URL
5. Go to Settings → API Keys and generate a new API key
6. Paste both into your environment variables above

`HERMES_DRATA_CCT_URL` also contains a resource ID (`YOUR_RESOURCE_ID` in
Step 2). Hermes does not create or discover it: obtain the resource ID from
the Drata UI and embed it in `HERMES_DRATA_CCT_URL` alongside the connection
ID. Where the resource ID appears in the Drata UI is not documented in this
repository. See `docs/integrations/DRATA.md`.

---

## Step 4 — Install the systemd Service

    source ~/.env.hermes
    hermes-relay install-service
    hermes-relay status

Hermes Relay now starts automatically on boot at 127.0.0.1:8787.

---

## Step 5 — Send Your First Scan

    curl -s -X POST http://127.0.0.1:8787/v1/scrub \
      -H "Content-Type: application/json" \
      -H "X-API-Key: your-secure-api-key-here" \
      -d '{"payload": "Patient John Smith SSN 372-18-5421 DOB 1982-03-15"}' \
      | python3 -m json.tool

When `HERMES_DRATA_CCT_URL` is set, Hermes also schedules a best-effort
background POST of the receipt metadata to that URL after the response is
returned. `/v1/scrub` uses the legacy Drata export path (flat payload, one
attempt, no retries, no idempotency key). Whether the record appears in the
Drata dashboard has not been validated against a live Drata tenant; see
`docs/integrations/DRATA_VALIDATION.md`.

---

## Environment Variable Reference

| Variable | Required | Description |
|---|---|---|
| HERMES_API_KEY | Yes | Auth key for /v1/scrub and /v1/review |
| HERMES_SIGNING_KEY | Yes (production) | HMAC key for attestation chain |
| HERMES_VAULT_KEY | Yes (production) | AES-256-GCM vault key |
| HERMES_DRATA_CCT_URL | Yes (Drata) | Drata CCT endpoint URL |
| HERMES_DRATA_API_KEY | Yes (Drata) | Drata API key |
| HERMES_WEBHOOK_URL | Optional | Generic SIEM/webhook endpoint (scrub + gateway evidence) |
| HERMES_GATEWAY_POLICY | Optional | Default `HIPAA_STRICT` (REDACT). Set `HIPAA_PRODUCTION_BLOCK` for BLOCK. |
| HERMES_HOST | Optional | Server host (default: 127.0.0.1) |
| HERMES_PORT | Optional | Server port (default: 8787) |

---

## Support

andrew@hermesrelay.dev
hermesrelay.dev
Sui-Generis — Rocky Top, Tennessee

## Vanta Integration Environment Variables

## Sprinto Integration Environment Variables
