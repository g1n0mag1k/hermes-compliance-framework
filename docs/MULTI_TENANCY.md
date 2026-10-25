# Multi-Tenancy

One Hermes Relay deployment can serve many isolated tenants. The shape is a
**parent workspace** for the organization that runs Hermes and a **child
workspace** for each client, facility or customer whose data must stay separate:

| Parent organization | Child workspaces |
|---|---|
| MSP | each HIPAA-covered client |
| Health system | each hospital or clinic |
| Healthtech / AI vendor | each customer tenant |
| Insurance agency or broker | each client group |
| Billing company | each provider client |

```
acme                    (top-level, role org_admin)   ← parent organization's key
 ├── clinic-one         (parent = acme, role operator)
 └── clinic-two         (parent = acme, role operator)
```

A single organization with no clients can simply use one top-level workspace.

The legacy single-tenant setup (`HERMES_API_KEY` env var, global chain at
`HERMES_DB_PATH`) keeps working unchanged.

## What is isolated per workspace

| Resource | Isolation | Where |
|---|---|---|
| API key | Own key, stored as SHA-256 only, rotatable | `registry.db` |
| V1 attestation chain | Own SQLite DB **and** own HMAC signing key | `<HERMES_DATA_DIR>/<id>/chain.db` |
| Gateway V2 receipts | Own table rows in the workspace chain DB | same `chain.db` |
| Token vault | Own SQLite DB **and** own AES-256-GCM / token key | `<HERMES_DATA_DIR>/<id>/vault.db` |
| Canary results | Own SQLite DB | `<HERMES_DATA_DIR>/<id>/canary.db` |
| Trial quota | Own row | `registry.db` |
| Gateway policy | Own assignment, applied on the next gateway request | `<HERMES_DATA_DIR>/workspace_policies.db` |
| AI provider credentials | Own OpenAI / Anthropic / Azure key (+ Azure endpoint), encrypted at rest | `<HERMES_DATA_DIR>/provider_credentials.db` |
| Evidence outbox (Drata Path B) | Rows scoped by `workspace_id` | existing outbox DB |
| Gateway stats | Per workspace (in-process counters) | memory |

### Per-workspace keys

Keys are derived, not stored:

```
signing_key(ws)    = HMAC-SHA256(HERMES_SIGNING_KEY, "hermes-relay:attestation:v1:<ws>")
vault_key(ws)      = HMAC-SHA256(HERMES_VAULT_KEY,   "hermes-relay:vault:v1:<ws>")
credential_key(ws) = HMAC-SHA256(HERMES_VAULT_KEY,   "hermes-relay:provider-credentials:v1:<ws>")
```

Consequences:

- One workspace's receipts do not verify under another workspace's key, and a
  derived key can be handed to that tenant's auditor without exposing anyone else.
- The same SSN produces **different** vault tokens in different workspaces, so
  tokens cannot be used to correlate patients across clients.
- Rotating `HERMES_SIGNING_KEY` or `HERMES_VAULT_KEY` changes every derived key.
  As before, keep old root keys to verify old receipts; stored provider
  credentials must be re-entered after a vault-key rotation.

### Existing data is never re-keyed

Each chain/vault DB records its key scheme (`chain_meta` / `vault_meta` table):

- A workspace DB that **already contains receipts or vault entries** when this
  version first opens it is marked `global` and keeps using the deployment-wide
  key. Its historical receipts keep verifying. A warning is logged.
- A **new or empty** workspace DB is marked `per_workspace_v1`.
- A `per_workspace_v1` DB refuses to open without its key, instead of failing
  verification later.

`GET /v1/workspaces/{id}/chain-integrity` reports which scheme a chain uses.

## Roles

| Role | Earlier name (still accepted) | Can |
|---|---|---|
| `org_admin` | `msp_admin` | Everything below, plus list workspaces, rotate keys, set policies and AI credentials (on workspaces it manages) |
| `operator` | `msp_tech` | `/v1/scrub`, `/v1/review`, `/v1/trial-scan`, `/api/v1/evaluate`, `/v1/telemetry/canary-audit`, chain integrity, read status |
| `viewer` | `client_readonly` | `/v1/status`, `/v1/scan-history`, `/v1/workspace`, read policy |

Earlier names behave exactly like the current ones and stored roles are never
rewritten, so existing registries, API clients and dashboards keep working.
New workspaces default to `org_admin`. The legacy `HERMES_API_KEY` maps to the
`default` workspace with role `org_admin`.

Role names are not secrets: `GET /v1/workspace` returns the caller's role and
the dashboard reads it. A caller cannot claim a role — the server takes it from
the registry row that matches the caller's API key.

**Management rule:** a workspace with a parent is managed by its parent. A
child workspace cannot change its own gateway policy or AI credentials — even
with an `org_admin` key. Give child workspaces `operator` keys.

**Hierarchy is one level deep.** `parent_workspace_id` must name an existing
top-level workspace; the API rejects unknown parents (otherwise whoever later
registered that ID would inherit access) and grandchildren.

## Endpoints

All take `X-API-Key`. Creating a workspace takes `X-Admin-Token` (`HERMES_ADMIN_TOKEN`).

```
POST   /v1/workspaces                                        create (role optional, default org_admin)
GET    /v1/workspaces                                        list children            org_admin
GET    /v1/workspace                                         caller's own workspace   any
POST   /v1/workspaces/{id}/rotate-key                        rotate                   org_admin

GET    /v1/workspaces/{id}/policy                            effective policy         any, self or parent
PUT    /v1/workspaces/{id}/policy        {"policy_id": ...}  assign                   org_admin, manager
DELETE /v1/workspaces/{id}/policy                            revert to default        org_admin, manager

GET    /v1/workspaces/{id}/chain-integrity                   verify chain             org_admin/operator, self or parent

GET    /v1/workspaces/{id}/provider-credentials              which are set (never values)  org_admin, manager
PUT    /v1/workspaces/{id}/provider-credentials/{provider}   {"credential": ..., "base_url": ...}
DELETE /v1/workspaces/{id}/provider-credentials/{provider}
```

`provider` is `openai`, `anthropic` or `azure_openai`. `base_url` is accepted
only for `azure_openai` and must be `https://<name>.openai.azure.com` or
`https://<name>.cognitiveservices.azure.com` with no path, port, query or
credentials, so a tenant cannot redirect the gateway (and its injected key)
to an arbitrary host. Without a workspace credential the gateway falls back to
the deployment-wide `HERMES_*_API_KEY` env vars, exactly as before.

### Fail-closed behavior

- If the policy store cannot be read, or holds a policy ID this build does not
  know, the gateway returns 503 and forwards nothing. It never falls back to a
  weaker default.
- If a workspace's stored credential cannot be decrypted, the gateway returns
  503. It never falls back to the deployment-wide key.

## Provisioning example

```bash
# 1. Parent workspace
curl -s -X POST localhost:8787/v1/workspaces -H "X-Admin-Token: $HERMES_ADMIN_TOKEN" \
  -H 'content-type: application/json' \
  -d '{"workspace_id":"acme","name":"Acme Health","owner_email":"ops@acme.example","plan":"production"}'
# → save api_key as PARENT_KEY (shown once)

# 2. Child workspace under it
curl -s -X POST localhost:8787/v1/workspaces -H "X-Admin-Token: $HERMES_ADMIN_TOKEN" \
  -H 'content-type: application/json' \
  -d '{"workspace_id":"clinic-one","name":"Clinic One","owner_email":"it@clinic.example",
       "plan":"production","parent_workspace_id":"acme","role":"operator"}'
# → save api_key as CHILD_KEY; give it to that client's or facility's integration

# 3. Parent sets the child's policy and AI key
curl -s -X PUT localhost:8787/v1/workspaces/clinic-one/policy -H "X-API-Key: $PARENT_KEY" \
  -H 'content-type: application/json' -d '{"policy_id":"HIPAA_PRODUCTION_BLOCK"}'
curl -s -X PUT localhost:8787/v1/workspaces/clinic-one/provider-credentials/openai \
  -H "X-API-Key: $PARENT_KEY" -H 'content-type: application/json' -d '{"credential":"sk-..."}'

# 4. Parent checks the child's evidence chain
curl -s localhost:8787/v1/workspaces/clinic-one/chain-integrity -H "X-API-Key: $PARENT_KEY"
```

## Not multi-tenant yet (do not claim)

- **Gateway V2 receipts** are signed with one deployment-wide Ed25519 key. Each
  receipt's signed payload includes `workspace_id`, so receipts cannot be moved
  between tenants undetected, but there are no per-tenant V2 signing keys.
- **Drata CCT export** uses one global `HERMES_DRATA_CCT_URL` / `HERMES_DRATA_API_KEY`.
  There is no per-tenant Drata routing.
- **PSA credentials** (`CredentialManager`, HaloPSA/ConnectWise) are keyed per
  tenant but stored unencrypted.
- **Storage is SQLite on one host.** Multiple processes on one host are fine;
  multiple hosts sharing storage are not supported.
- **Gateway stats** are in-process counters and reset on restart.
- The `default` workspace ID is reserved for the legacy single-tenant key and
  cannot be created through the API (an existing `default` row keeps working).
