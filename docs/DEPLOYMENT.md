# Hermes Relay — Docker Deployment Guide

This is the **one supported Docker deployment** of Hermes Relay: the root
`docker-compose.yml`, built locally from this repository. Follow it top to
bottom on a clean Linux host. Every command below was run end to end on a
clean Ubuntu 24.04 VM (Docker Engine 29.8.1, Compose v5.5.1). Items that
could not be verified there are marked **UNVERIFIED**.

The same procedure is automated in `tests/docker/e2e.sh` (see §18).

---

## 1. Architecture

```
tenant application
      │  HTTP  (TLS: add a reverse proxy — §13)
      ▼
hermes-gateway  :8788  ── inspects every request, applies policy ──▶ OpenAI / Azure OpenAI / Anthropic (HTTPS)
      │  writes a signed V2 receipt for every decision (ALLOW / REDACT / BLOCK)
      ▼
hermes_data volume  ── workspace registry + per-workspace chain.db (receipt chain)
      ▲
hermes-api  :8787  (bound to 127.0.0.1 on the host) ── workspace creation, /v1/scrub
      ▲
Operator, on the Docker host only
```

| Container | Command | Host port | Purpose |
|---|---|---|---|
| `hermes-api` | `uvicorn hermes.api:app` | `127.0.0.1:8787` | Workspace administration (`POST /v1/workspaces`), legacy `/v1/scrub` / `/v1/review` |
| `hermes-gateway` | `uvicorn gateway.app:app` | `127.0.0.1:8788` by default (`HERMES_GATEWAY_BIND`) | AI enforcement proxy |

Both containers run the same image (`hermes-relay:1.0.0`, built from the root
`Dockerfile`) as the same non-root user (uid 10001) and share two named volumes:

| Volume | Mounted at | Contents |
|---|---|---|
| `hermes-relay_hermes_data` | `/app/data` (both) | `workspaces/registry.db` (workspaces + hashed API keys), `workspaces/<id>/chain.db` (receipts), `hermes_chain.db`, `hermes_vault.db` |
| `hermes-relay_hermes_keys` | `/app/keys` (gateway only) | `gateway.keystore` — encrypted Ed25519 receipt-signing key |

The gateway does not call the API over the network. They cooperate through
the shared `hermes_data` volume: a workspace created through the API is
immediately usable at the gateway.

---

## 2. Prerequisites

- Linux host with Docker Engine and the Docker Compose v2 plugin
  (`docker compose version` must work). Verified: Ubuntu 24.04, Docker
  29.8.1, Compose v5.5.1. Other distributions: **UNVERIFIED**.
  Docker's convenience installer was used for verification:
  `curl -fsSL https://get.docker.com | sudo sh`, then
  `sudo usermod -aG docker $USER` and log out/in.
- `git`, `curl`, `openssl` (present on stock Ubuntu).
- Outbound internet during the build (Docker Hub `python:3.12-slim`, PyPI,
  the spaCy `en_core_web_sm` model from GitHub) and at runtime to the AI
  provider(s) you use.
- About 1.2 GB for the image (measured: 1.14 GB) plus build cache.
- Host ports `127.0.0.1:8787` and `8788` free.
- A provider API key (OpenAI, Anthropic, or Azure OpenAI key + endpoint).

## 3. Obtain the repository

The repository and the GHCR image `ghcr.io/g1n0mag1k/hermes-compliance` are
**private**. This deployment does not pull any Hermes image; it builds the
image locally from the repository. You need read access to the repository
(ask Sui-Generis LLC).

```bash
git clone https://github.com/g1n0mag1k/hermes-compliance-framework.git hermes
cd hermes
```

All following commands run from this directory.

## 4. Configuration and secret generation

```bash
./scripts/generate-env.sh
```

This copies `.env.hermes.example` to `.env.hermes` (mode 600) and fills
every secret with `openssl rand -hex 32`. It refuses to overwrite an
existing `.env.hermes`.

Then edit `.env.hermes` and set **at least one** provider credential:

```bash
nano .env.hermes
#   HERMES_OPENAI_API_KEY=sk-...
# or HERMES_ANTHROPIC_API_KEY=...
# or HERMES_AZURE_OPENAI_KEY=... and HERMES_AZURE_OPENAI_ENDPOINT=https://<resource>.openai.azure.com
```

`.env.hermes.example` documents every variable, grouped as: runtime mode,
required secrets, administrative credentials, gateway policy, provider
credentials, paths fixed by Compose, and optional evidence export. The
defaults you should keep:

- `HERMES_ENV=production` — both services refuse to start without their
  secrets, and the gateway refuses to use an ephemeral signing key. Without
  it, the gateway generates a new random signing key in every process, so
  receipts from before a restart can no longer be verified with the current
  key.
- `HERMES_GATEWAY_POLICY=HIPAA_PRODUCTION_BLOCK` — detected PHI → HTTP 403,
  nothing forwarded. (`HIPAA_STRICT` redacts and forwards instead.)

Do not set the data or keystore paths in `.env.hermes`; `docker-compose.yml`
fixes them so both services use the same files.

Keep `.env.hermes` secret: it contains the keystore passphrase and the admin
token. Never commit it (it is in `.gitignore`).

## 5. Build the image

```bash
docker compose build
```

This builds `hermes-relay:1.0.0` once; both services use it.

## 6. Create the persistent signing keystore (once)

```bash
docker compose run --rm --no-deps hermes-gateway hermes-relay keystore-init
```

Output:

```
Created gateway keystore: /app/keys/gateway.keystore
algorithm: EdDSA
key_id: <16 hex chars>
```

Record the `key_id`. Every gateway receipt carries it. The command refuses to
overwrite an existing keystore. Do not delete the `hermes_keys` volume: without
the keystore, and the passphrase in `.env.hermes`, the gateway can no longer
sign with that key. Receipts it already signed can still be verified with the
exported public key (step below).

If you skip this step, the gateway exits at startup with
`FileNotFoundError: Key store not found at /app/keys/gateway.keystore` and
never reports healthy. That is intentional.

Export the public key that verifiers (auditors, the covered entity) use, and
store it with your compliance records:

```bash
docker compose run --rm --no-deps -T hermes-gateway hermes-relay keystore-public-key > gateway-public.pem
```

The PEM goes to stdout and the key ID to stderr, so the file contains only
the key. `-T` disables terminal allocation.

## 7. Start

```bash
docker compose up -d --wait --wait-timeout 300
```

Compose starts `hermes-api` first and starts `hermes-gateway` only after
the API health check passes. `--wait` returns once both containers are
healthy, or fails if either becomes unhealthy.

## 8. Health verification

```bash
docker compose ps
curl -s http://127.0.0.1:8787/health
curl -s http://127.0.0.1:8788/gateway/health
```

Expected: both containers `Up … (healthy)`, and:

```
{"status":"operational","compliance_mode":"enforced","version":"1.0.0"}
{"gateway_service":"healthy","policy_engine":"healthy","detector_state":"healthy","evidence_chain":"healthy","provider_connectivity":{"openai":true,"azure_openai":false,"anthropic":false}}
```

What the health checks do and do not prove:

- API `/health` is a static liveness response.
- Gateway `/gateway/health` runs the PHI detectors on a probe string and
  checks the policy engine. It returns **503 (container unhealthy) when no
  provider credential is configured**.
- `provider_connectivity` only reports whether a credential **is set**. The
  health check never contacts the provider, so a wrong key or a blocked
  egress route still shows `true`. Section 11 is the real connectivity test.

## 9. Workspace creation and credentials

Each covered-entity client gets its own workspace, with its own API key and
receipt chain. Workspaces are created on the loopback-only API port with the
admin token, **from a shell on the Docker host**. The admin endpoint is not
reachable from the network.

```bash
ADMIN_TOKEN=$(grep '^HERMES_ADMIN_TOKEN=' .env.hermes | cut -d= -f2)
curl -s -X POST http://127.0.0.1:8787/v1/workspaces \
  -H "X-Admin-Token: $ADMIN_TOKEN" -H "Content-Type: application/json" \
  -d '{"workspace_id":"clinic-a","name":"Clinic A","owner_email":"it@clinic-a.example","plan":"production"}'
```

The response contains `"api_key": "<64 hex chars>"`. **It is shown once.**
Only its SHA-256 hash is stored, so give it to the application owner through
your secrets process.

- `workspace_id`: 3–64 characters; lowercase letters, digits and hyphens;
  must start and end with a letter or digit. A duplicate ID returns 409; a
  missing or wrong admin token returns 401.
- To rotate a workspace key (the old key stops working immediately):

  ```bash
  curl -s -X POST http://127.0.0.1:8787/v1/workspaces/clinic-a/rotate-key -H "X-API-Key: <current workspace key>"
  ```

## 10. Configure an application to use the gateway

Gateway URL format (POST only):

```
http://<gateway-host>:8788/gateway/<provider>/<provider path>
```

| Provider | `<provider>` | Allowed path prefixes |
|---|---|---|
| OpenAI | `openai` | `/v1/chat/completions`, `/v1/assistants`, `/v1/threads`, `/v1/audio/transcriptions`, `/v1/embeddings` |
| Azure OpenAI | `azure_openai` | `/openai/deployments/`, `/openai/v1/` |
| Anthropic | `anthropic` | `/v1/messages`, `/v1/messages/batches` |

Every request must carry the workspace key in `X-API-Key`. The gateway strips
any `Authorization`, `x-api-key` or `api-key` header sent by the client and
injects the provider credential from `.env.hermes`. Applications therefore
never hold provider keys.

OpenAI Python SDK example:

```python
from openai import OpenAI
client = OpenAI(
    base_url="http://<gateway-host>:8788/gateway/openai/v1",
    api_key="unused-the-gateway-injects-the-provider-key",
    default_headers={"X-API-Key": "<workspace api_key>"},
)
```

## 11. Clean-request and PHI-blocking test

Run from the Docker host with the workspace key from §9 (`WS_KEY=<api_key>`).
This example uses OpenAI; for another provider, use the matching path from §10.

Clean request, which should be forwarded:

```bash
curl -s -w '\nHTTP %{http_code}\n' -X POST http://127.0.0.1:8788/gateway/openai/v1/chat/completions \
  -H "X-API-Key: $WS_KEY" -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Summarize the benefits of regular exercise in two sentences."}]}'
```

Expected: the provider's normal response (HTTP 200). A provider error is
passed through unchanged; for example, an invalid OpenAI key returns
OpenAI's `invalid_api_key` 401. Either result proves the gateway reached the
provider.

Synthetic PHI request, which must be blocked:

```bash
curl -s -w '\nHTTP %{http_code}\n' -X POST http://127.0.0.1:8788/gateway/openai/v1/chat/completions \
  -H "X-API-Key: $WS_KEY" -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o-mini","messages":[{"role":"user","content":"Patient John Smith, SSN 234-56-7891, MRN 4452981, needs a follow-up."}]}'
```

Expected: HTTP 403, `"code":"phi_detected"`, plus a `transaction_id` and
`receipt_digest`. The request is not sent to the provider. The e2e test
(§18) proves this with a mock upstream that records every request it receives.

A request without a valid `X-API-Key` returns 401.

## 12. Receipt verification

Export a workspace's receipts from the gateway, copy them to the host, and
verify them in a fresh container. That container has no network and no access
to the keystore or data volumes; it sees only the receipts and the public key.

```bash
EXPORT=clinic-a-$(date +%Y%m%d-%H%M%S)
docker compose exec -T hermes-gateway hermes-relay export-receipts --workspace clinic-a --out /app/exports/$EXPORT
mkdir -p receipt-export
docker compose cp hermes-gateway:/app/exports/$EXPORT receipt-export/$EXPORT

# Whole chain: every signature, digest links, gap-free sequence, one workspace
docker run --rm --network none -v "$PWD/receipt-export/$EXPORT:/r:ro" -v "$PWD/gateway-public.pem:/key.pem:ro" \
  hermes-relay:1.0.0 hermes-verify chain /r --public-key /key.pem --workspace-id clinic-a

# One receipt (e.g. the BLOCK just produced)
docker run --rm --network none -v "$PWD/receipt-export/$EXPORT:/r:ro" -v "$PWD/gateway-public.pem:/key.pem:ro" \
  hermes-relay:1.0.0 hermes-verify receipt /r/<file>-BLOCK-<digest>.cose --public-key /key.pem
```

`export-receipts` writes one `NNNNNNNN-<DECISION>-<digest>.cose` file per
receipt, in chain order, plus `gateway-public.pem`. It refuses a non-empty
output directory. `/app/exports` lives in the container's writable layer and
is discarded when the container is recreated.

Expected `hermes-verify chain` output:

```
VALID
receipts: <n>
signer_key_ids: <the key_id from §6>
```

For a BLOCK receipt, `hermes-verify receipt` prints `VALID`,
`decision: BLOCK`, `forwarded: False`, and `policy_id: HIPAA_PRODUCTION_BLOCK`.
Exit codes: 0 valid, 1 invalid, 2 malformed input. Receipts contain PHI
category names and counts only, never PHI values. See
`docs/RECEIPT_VERIFICATION.md`.

## 13. TLS

**The Compose deployment serves plain HTTP only.** Hermes itself has no TLS
configuration. Request bodies sent to the gateway contain PHI before
inspection, so traffic from applications to the gateway must be encrypted by
a reverse proxy or load balancer that **you** operate in front of port 8788.

The gateway's host port binds to `127.0.0.1` by default, so it is not
reachable from the network until you choose one of these:

- **Recommended:** run a TLS reverse proxy on the same host, forwarding to
  `127.0.0.1:8788`. Keep the default binding.
- Bind the gateway to a specific interface (only on a network segment you
  control), by setting `HERMES_GATEWAY_BIND` in `./.env`. This is the Compose
  project env file, not `.env.hermes`:

  ```bash
  echo "HERMES_GATEWAY_BIND=10.0.0.5" > .env     # interface address; 0.0.0.0 = all
  docker compose up -d --wait
  ```

Example: Caddy as the TLS proxy on the same host.

```bash
cat > Caddyfile.tls <<'EOF'
gateway.clinic-a.example {
    tls internal
    reverse_proxy 127.0.0.1:8788
}
EOF
docker run -d --name hermes-tls --restart unless-stopped --network host \
  -v "$PWD/Caddyfile.tls:/etc/caddy/Caddyfile:ro" -v hermes_tls_data:/data caddy:2.8-alpine
```

`tls internal` issues a certificate from Caddy's own local CA. Clients must
trust that CA's root certificate (`/data/caddy/pki/authorities/local/root.crt`
in the `hermes_tls_data` volume). This configuration was verified: `curl`
with that root as `--cacert` reached `/gateway/health` and a gateway request
over HTTPS. Removing `tls internal` makes Caddy request a public Let's
Encrypt certificate. That requires public DNS for the name and inbound
ports 80/443, and is **UNVERIFIED** (no public DNS was available for testing).
Applications then use `https://gateway.clinic-a.example/gateway/...`.

## 14. Restart, shutdown, and persistence

| Action | Command | Data, workspaces, receipts, keystore |
|---|---|---|
| Restart | `docker compose restart` | kept |
| Stop / start | `docker compose stop` / `docker compose start` | kept |
| Remove containers | `docker compose down` then `docker compose up -d --wait` | kept (volumes survive `down`) |
| Upgrade | `git pull && docker compose build && docker compose up -d --wait` | kept. **UNVERIFIED** across real version changes (no newer release exists) |
| **Destroy everything** | `docker compose down -v` | **deleted**: the volumes, and with them every receipt and the signing key. Never run this on a production host without a verified backup |

Containers use `restart: unless-stopped`, so they come back after a crash or
Docker daemon restart. `docker compose restart` and
`docker compose down`/`up` were verified to keep the workspace key working,
continue the same receipt chain (sequence numbers and digest links intact),
and keep the same signer `key_id`.

After a restart, re-run §8 and §11. Then verify the chain again (§12, into
a new `EXPORT` directory).

## 15. Backup requirements

Back up three things. Without all three, receipts cannot be verified or
extended:

1. The `hermes-relay_hermes_data` volume (workspaces, receipt chains).
2. The `hermes-relay_hermes_keys` volume (encrypted signing key).
3. `.env.hermes`. It holds the keystore passphrase and the V1 signing and
   vault keys. Store it **separately** from the keystore backup, for example
   in your password manager or vault.

Also keep `gateway-public.pem` with your compliance records.

The databases are SQLite, so stop the stack during the copy to get a
consistent snapshot:

```bash
mkdir -p backups
docker compose stop
docker run --rm --user 0 -v hermes-relay_hermes_data:/data:ro -v hermes-relay_hermes_keys:/keys:ro \
  -v "$PWD/backups:/backup" hermes-relay:1.0.0 tar czf /backup/hermes-$(date +%Y%m%d-%H%M%S).tgz -C / data keys
docker compose start
```

The archive is created as root. Move it off the host with `sudo`, or run
`sudo chown $USER backups/*.tgz` first.

Restore onto a host where `.env.hermes` is already in place:

```bash
docker compose down
docker volume rm hermes-relay_hermes_data hermes-relay_hermes_keys
docker volume create hermes-relay_hermes_data && docker volume create hermes-relay_hermes_keys
docker run --rm --user 0 -v hermes-relay_hermes_data:/data -v hermes-relay_hermes_keys:/keys \
  -v "$PWD/backups:/backup:ro" hermes-relay:1.0.0 tar xzpf /backup/<file>.tgz --numeric-owner -C /
docker compose up -d --wait --wait-timeout 300
```

The archive contains the (encrypted) keystore and every workspace's hashed
API key. Encrypt it, or keep it on encrypted storage, according to your
HIPAA backup policy. Backup and restore were verified: after restoring into
new volumes, the workspace key still worked, the chain verified `VALID` with
the same `key_id`, and new receipts continued the chain.

## 16. Known limitations

- **No built-in TLS** (§13). Default gateway binding is loopback.
- **Single gateway instance only.** The chain head is cached in process
  memory, and the sequence number is read, then written. Do not
  `--scale hermes-gateway` and do not add uvicorn workers; parallel gateways
  writing one workspace chain would produce conflicting sequence numbers.
- **Health ≠ provider reachability** (§8).
- **Workspace administration needs a shell on the Docker host** (loopback
  API + admin token). There is no remote admin UI in this deployment.
- **Azure OpenAI `api-version` query parameter.** Values like
  `api-version=2024-06-01` are detected as a PHI date
  (`HIPAA_PHI_DATE`), so under `HIPAA_PRODUCTION_BLOCK` every request carrying
  one is blocked with 403. This was observed against the running gateway. The
  `/openai/v1/...` paths without `api-version` pass; this was tested against
  a mock only. Calls to a real Azure resource through the gateway are
  **UNVERIFIED**.
- **Provider responses are inspected and may be altered.** Observed:
  `"object": "chat.completion"` in a chat-completion response is detected
  as a URL and returned to the client as `"object": "[REDACTED_URL]pletion"`.
  The OpenAI Python SDK accepted the altered response. Clients that validate
  that field strictly may reject it.
- **No streaming (SSE) enforcement**, POST routes only. See
  `docs/CURRENT_LIMITATIONS.md`.
- `hermes-verify receipt` prints `issued_at: n/a` for gateway receipts.
- `/gateway/stats` counters are in memory and reset on every restart;
  receipts are the durable record.
- Signing-key **rotation** is not provided by this deployment. Replacing the
  keystore starts receipts under a new `key_id`, and older receipts still need
  the old public key.
- Secrets live in `.env.hermes` on the host. Anyone with Docker access on the
  host can read them (`docker inspect`). Restrict membership of the `docker`
  group.
- PSA ticket credentials (`gateway/credentials.py`) are stored under
  `/tmp/.hermes` in the container and are not persisted. PSA integration is
  not part of this deployment.
- Real OpenAI / Anthropic / Azure calls with valid keys: **UNVERIFIED**
  (no credentials available during testing). Verified: the gateway reached
  `api.openai.com` over HTTPS and passed OpenAI's 401 for an invalid key
  through to the client.

## 17. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `docker compose up` / `run` → `env file …/.env.hermes not found` | Run `./scripts/generate-env.sh` (§4). |
| Gateway restarting; log `Key store not found at /app/keys/gateway.keystore` | Run `keystore-init` (§6). |
| Gateway log `Key decryption failed — wrong passphrase` | `HERMES_GATEWAY_KEYSTORE_PASSPHRASE` in `.env.hermes` does not match the keystore. Restore the original `.env.hermes`. **Do not** create a new keystore, or receipts will be signed under a new `key_id`. |
| Log `HERMES_SIGNING_KEY is required` / `HERMES_VAULT_KEY must be exactly 64 hex characters` | Secret missing or malformed in `.env.hermes`. Values must be unquoted hex. |
| `hermes-gateway` `(unhealthy)`, `/gateway/health` 503 with all `provider_connectivity` false | No provider credential set. Add one to `.env.hermes`, then run `docker compose up -d --wait` (a plain `restart` does not re-read `.env.hermes`). |
| `dependency failed to start: container … hermes-api … is unhealthy` | `docker compose logs hermes-api`, usually a missing secret. |
| `PermissionError` / `unable to open database file` | The volume was created by an older image, or is a bind mount not owned by uid 10001. Use the named volumes from this Compose file. Bind mounts are not part of this procedure (**UNVERIFIED**); they would need `chown -R 10001:10001`. |
| 401 `Invalid API key` at the gateway | Wrong or rotated workspace key, or the key was sent in `Authorization` instead of `X-API-Key`. |
| 403 `phi_detected` on a request you expected to pass | The detector found a PHI category. Check `phi_categories_detected` in the exported receipt. See the Azure `api-version` limitation. |
| 400 `Path … not allowed` | Path not in the allow-list (§10). |
| 502 `upstream_transport_failure` | Gateway could not reach the provider or got a 5xx. Check egress, DNS, and the Azure endpoint. |
| 503 `receipt_persistence_failure` | Receipt could not be written. Check disk space and `hermes_data` volume health. |
| Containers cannot reach each other (timeouts to `hermes-api:8787`) | Host firewall issue. On one test VM, stale `iptables-legacy` rules with `FORWARD DROP` blocked traffic between containers until they were flushed and Docker was restarted. |
| Port already in use | Another service holds 8787/8788 on the host. Stop it. |

## 18. Automated verification

`tests/docker/e2e.sh` runs this procedure against a fresh copy of the
repository. It uses a test-only Compose override
(`tests/docker/docker-compose.test.yml`) that points the `azure_openai`
provider at a recording mock upstream, and it creates its own stack
(`-p hermes-e2e`) and removes it at the end.

```bash
tests/docker/e2e.sh                        # E2E_NO_CACHE=1 to rebuild from scratch
E2E_PROVIDER_PROBE=1 tests/docker/e2e.sh   # also probes api.openai.com with an invalid key
```

It checks:

- The gateway refuses to start without a keystore, and a second
  `keystore-init` is refused.
- Health of both containers and their ports, and that the API is not
  reachable on non-loopback addresses.
- Workspace creation needs the admin token.
- A clean request is forwarded once with an unchanged body and client
  credentials stripped.
- A PHI request returns 403 with zero upstream requests.
- An invalid workspace key returns 401.
- The receipt and chain verify independently with a single `key_id`: first
  after start, then after `restart`, then after `down`/`up`.

---

## Appendix A — Legacy `/v1/scrub` API

`/v1/scrub` and `/v1/review` are served by `hermes-api` on
`127.0.0.1:8787`. They accept the `HERMES_API_KEY` from `.env.hermes` or a
workspace key in `X-API-Key`.

```bash
API_KEY=$(grep '^HERMES_API_KEY=' .env.hermes | cut -d= -f2)
curl -s -X POST http://127.0.0.1:8787/v1/scrub -H "X-API-Key: $API_KEY" -H "Content-Type: application/json" \
  -d '{"payload": "Patient John Smith, SSN 234-56-7891, contact john@example.com"}'
```

The response contains `clean_text`, `audit_log` and a `compliance_receipt`
(V1, HMAC-SHA256). A `/v1/review` call references a prior scrub's
`transaction_id`, and `decision` must be one of `accepted`, `overridden`,
`escalated`.

V1 receipt fields:

| Field | Meaning |
|---|---|
| `receipt_id` / `transaction_id` / `issued_at` / `issuer` | Identity and time of the receipt. |
| `pii_classes_detected` / `pii_classes_redacted` / `count_detected` / `count_redacted` | Classes found/redacted and per-class occurrence counts. `zero_pii_egress_confirmed` is computed from the counts. |
| `zero_pii_egress_confirmed` + `zero_pii_egress_scope_note` | True only when, for every class **within `declared_scope`**, detected count == redacted count. Not a claim that the payload has no PHI of any kind. |
| `declared_scope` / `evidence_incomplete_categories` | CFR citations checked / not checked. |
| `detectors_executed` | Per-category `ran_clean` / `ran_error` / `not_run`. |
| `previous_receipt_hash` / `receipt_hash` / `chain_position` | HMAC chain linkage. |

Verify the legacy V1 chain inside the API container. It uses the
`HERMES_SIGNING_KEY` from `.env.hermes`; a different key reports `False` on
an intact chain.

```bash
docker compose exec -T hermes-api python -c "from hermes.attestation import ATTESTATION_CHAIN; print(ATTESTATION_CHAIN.verify_chain())"
```

Detection scope (16 of 18 Safe Harbor categories; see
`docs/SCOPE_BOUNDARY.md`): P (biometric) and Q (full-face photographs) are
reference-only, and quasi-identifier combinations and contextual identifiers
are not detected. The NER model is general-purpose English, not clinical.

Running without Docker (pipx + systemd) is described in
`docs/MSP_INTEGRATION.md`. That path is not covered by this guide's
verification.
