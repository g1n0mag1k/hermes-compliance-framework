# Controlled Design-Partner Deployment

This profile is for a **small healthcare MSP design partner** evaluating Hermes Relay. It is **not** a general production deployment guide.

**Installation:** use the Docker Compose procedure in [`DEPLOYMENT.md`](./DEPLOYMENT.md). This page only describes the evaluation profile.

## Topology

```
Application (client network)
    → Hermes Gateway (:8788)
    → inspect / policy / receipt
    → OpenAI | Azure OpenAI | Anthropic
```

Optional legacy path: `/v1/scrub` on Hermes Relay API (:8787) for batch scrubbing — separate from gateway enforcement.

## Required configuration

| Variable | Purpose |
|---|---|
| `HERMES_ENV=production` | Fail-fast on missing secrets |
| `HERMES_GATEWAY_POLICY=HIPAA_PRODUCTION_BLOCK` | PHI detected → BLOCK |
| `HERMES_GATEWAY_KEYSTORE_PATH` | Persistent Ed25519 signing identity |
| `HERMES_GATEWAY_KEYSTORE_PASSPHRASE` | Keystore decryption |
| `HERMES_OPENAI_API_KEY` / `HERMES_ANTHROPIC_API_KEY` / Azure vars | Upstream provider credentials |
| Workspace `X-API-Key` | Per-tenant gateway authentication |

Create the keystore once (Docker deployment, `DEPLOYMENT.md` §6):

```bash
docker compose run --rm --no-deps hermes-gateway hermes-relay keystore-init
```

## Routing

- Point application SDK base URL to `http://<hermes-host>:8788/gateway/<provider>/...` (behind your TLS proxy, see `DEPLOYMENT.md` §13)
- Supported providers: `openai`, `azure_openai`, `anthropic`
- Unsupported paths/providers return controlled 400/403 without upstream contact

## Policy

- Design partner default: **BLOCK** on PHI, detector error, parse error, binary content
- REDACT mode available by assigning `HIPAA_STRICT` policy per workspace (explicit opt-in)

## Receipt storage

- SQLite per workspace: `gateway_receipts` table in workspace chain DB
- Backup: the `hermes_data` and `hermes_keys` volumes plus `.env.hermes` (see `DEPLOYMENT.md` §15)
- Verify receipts with `hermes-verify` (see `RECEIPT_VERIFICATION.md`)

## Monitoring

- `GET /gateway/health` — component status
- `GET /gateway/stats` (authenticated) — allow/redact/block counters
- Alert on `detector_errors_total` increases and 502 upstream transport failures

## Rollback

1. Route application traffic directly to provider (bypass gateway)
2. Preserve SQLite + keystore for audit continuity
3. Do not delete the keystore. Without it the gateway cannot keep signing under the same `key_id`, and prior receipts can be verified only with the separately exported `gateway-public.pem`.

## Known limitations

See `CURRENT_LIMITATIONS.md` — especially streaming, binary content, and live Drata tenant validation (adapter is contract-tested; live connectivity pending per deployment).

## Evidence verification

Design partner acceptance should include:

1. Clean request → upstream receives unchanged body → receipt verifies
2. PHI + BLOCK → HTTP 403, upstream request count 0, `forwarded=false`
3. PHI + REDACT (optional demo) → redacted body upstream, receipt verifies
4. Independent `hermes-verify` on exported receipt COSE bytes
