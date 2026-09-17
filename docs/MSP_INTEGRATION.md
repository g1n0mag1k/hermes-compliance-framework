# Hermes Relay — MSP Integration Guide

**Setup time: under 10 minutes**
**Requires: Python 3.12+, pipx, a Drata account on Advanced or Enterprise plan**

---

## What This Does

Hermes Relay runs inside your client environment and automatically pushes
PHI detection evidence into their Drata compliance dashboard via the Custom
Connections and Tests (CCT) API — zero manual evidence collection required.

Every scan generates a signed, hash-chained compliance receipt documenting:
- Which PHI identifiers were found (16 of 18 HIPAA Safe Harbor categories)
- Which CFR citation applies to each finding
- What action was taken (redaction to typed placeholders)
- Cryptographic proof of chain integrity via HMAC-SHA256

---

## Step 1 — Install Hermes Relay

On the client machine:

    pipx install hermes-relay

Verify:

    hermes-relay version

Expected output:

    Hermes Relay v1.0.0
    hermesrelay.dev | Sui-Generis LLC

---

## Step 2 — Configure Environment Variables

    HERMES_API_KEY=your-secure-api-key-here
    HERMES_SIGNING_KEY=your-64-char-hex-signing-key-here
    HERMES_VAULT_KEY=your-64-char-hex-vault-key-here
    HERMES_DRATA_CCT_URL=https://api.drata.com/public/custom-connection/YOUR_CONNECTION_ID/data
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

---

## Step 4 — Install the systemd Service

    source ~/.env.hermes
    hermes-relay install-service
    hermes-relay status

Hermes Relay now starts automatically on boot at 127.0.0.1:8787.

---

## Step 5 — Send Your First Scan

    curl -s -X POST http://127.0.0.1:8787/v1/scrub       -H "Content-Type: application/json"       -H "X-API-Key: your-secure-api-key-here"       -d "{"payload": "Patient John Smith SSN 372-18-5421 DOB 1982-03-15"}"       | python3 -m json.tool

Within seconds the receipt appears in the client Drata dashboard
under their Hermes Relay custom connection.

---

## Environment Variable Reference

| Variable | Required | Description |
|---|---|---|
| HERMES_API_KEY | Yes | Auth key for /v1/scrub and /v1/review |
| HERMES_SIGNING_KEY | Yes (production) | HMAC key for attestation chain |
| HERMES_VAULT_KEY | Yes (production) | AES-256-GCM vault key |
| HERMES_DRATA_CCT_URL | Yes (Drata) | Drata CCT endpoint URL |
| HERMES_DRATA_API_KEY | Yes (Drata) | Drata API key |
| HERMES_WEBHOOK_URL | Optional | Generic SIEM/webhook endpoint |
| HERMES_HOST | Optional | Server host (default: 127.0.0.1) |
| HERMES_PORT | Optional | Server port (default: 8787) |

---

## Support

andrew@hermesrelay.dev
hermesrelay.dev
Sui-Generis LLC — Rocky Top, Tennessee
