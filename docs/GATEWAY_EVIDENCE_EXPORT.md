# Gateway Evidence Export

## Architecture

```
Gateway enforcement decision
    → V2 COSE_Sign1 receipt (local SQLite)
    → EvidenceEvent (metadata-only contract)
    → optional exporters (best-effort, post-decision):
        - WebhookExporter (HERMES_WEBHOOK_URL) — inline, before the response
        - Drata: enqueue to local evidence outbox (SQLite, no network)
            → response returned to client
            → background flush_outbox() → DrataConnector (HERMES_DRATA_CCT_URL)
```

Export runs **after** receipt persistence inside `issue_gateway_receipt()`. Exporter failure never changes the enforcement decision. Drata is never contacted before the gateway response is sent.

## Drata evidence outbox

`gateway/evidence_export/outbox.py` stores each Drata-bound `EvidenceEvent` in
`evidence_outbox` inside `{HERMES_DATA_DIR}/evidence_outbox.db` (stdlib `sqlite3`,
same as the receipt chain). The gateway route schedules `flush_outbox(workspace_id)`
as a FastAPI background task, which runs after the response has been sent.

| Column | Meaning |
|---|---|
| `event_id` | Primary key; set once by `build_evidence_event()`. Duplicate inserts raise `DuplicateEventError`. |
| `workspace_id`, `created_at` | Owning workspace; UTC ISO-8601 enqueue time |
| `evidence_payload` | `EvidenceEvent.serialize()` — metadata-only; `assert_phi_safe()` runs before insert |
| `attempt_count` | Drata send attempts, counted when a flush claims the row |
| `next_attempt_at` | Next retry time (PENDING) or lease expiry (PROCESSING) |
| `status` | `PENDING`, `PROCESSING`, `EXPORTED`, `DEAD_LETTER` (`FAILED` is not used) |
| `last_error` | `sanitize_error()` output: URLs, hosts, bearer/basic tokens, key=value secrets, long tokens, configured Drata URL/key, and PHI-shaped values removed; max 200 chars |

Retry semantics:

- Each flush makes one `DrataConnector.send_evidence()` call per due row (which itself retries 5xx/network errors twice inline, 3s timeout).
- Transient (5xx, 429, network error, timeout, exporter exception, malformed exporter result): back to `PENDING`, backoff `30s × 2^(attempt−1)` capped at 1h.
- Permanent (4xx except 429, `phi_safety_check_failed`, `insecure_url_refused`, `not_configured`, unparsable stored payload): `DEAD_LETTER` immediately.
- `MAX_OUTBOX_ATTEMPTS = 8`: the 8th failed attempt moves the row to `DEAD_LETTER`.
- `DEAD_LETTER` rows are never retried and never deleted; they remain for operator review.
- A `PROCESSING` row whose 300s lease expired (flush crashed mid-send) is reclaimed.
- Every attempt sends the same `event_id` as `X-Idempotency-Key`. Whether Drata honors that header is **UNKNOWN**, so a retry after a lost 2xx could create a duplicate Drata record.

If the outbox write fails, the error is logged and the gateway response is returned unchanged.

## EvidenceEvent

Defined in `gateway/evidence_export/event.py`. Metadata-only fields include:

- `event_id`, `transaction_id`, `workspace_id`, `timestamp`
- `gateway_version`, `upstream_provider`, `endpoint_path`
- `decision` (`ALLOW` | `REDACT` | `BLOCK`)
- `policy_id`, `policy_version`, `policy_digest`
- `phi_categories_detected`, `phi_categories_redacted` (category names only)
- `content_types_inspected`, `content_types_not_inspected`
- `detector_states`, `all_detectors_clean`
- `upstream_contacted` (derived from receipt `forwarded`)
- `failure_class`, `upstream_status` (when applicable)
- `receipt_id`, `receipt_digest`, `prev_receipt_digest`, `gateway_sequence`
- `signature_algorithm`, `cose_sign1_hex`

**Never exported:** raw request/response bodies, prompts, completions, PHI values, detector snippets.

## Exporters

| Exporter | Env vars | Notes |
|---|---|---|
| Webhook | `HERMES_WEBHOOK_URL`, optional `HERMES_WEBHOOK_AUTH_*` | Posts full EvidenceEvent JSON |
| Drata CCT | `HERMES_DRATA_CCT_URL`, optional `HERMES_DRATA_API_KEY` | Drata-compatible mapped payload |

Both exporters:

- Bounded retries on 5xx / transient errors (max 2 retries)
- `X-Idempotency-Key: {event_id}` header
- 3s timeout
- Structured logging without PHI or credentials

## Canonical Drata connector

`DrataConnector` in `gateway/evidence_export/drata_connector.py` is the single
Drata implementation. `get_configured_exporters()` (used by `dispatch.py`)
returns it directly; `DrataExporter` in `exporters.py` is a thin backward-compatible
wrapper that delegates every call to it.

| Method | Behavior |
|---|---|
| `is_configured()` | `True` only when `HERMES_DRATA_CCT_URL` is set. No network call. |
| `status()` | `{connector, state, cct_url_configured, api_key_configured, connection_tested}`. `state` is `NOT_CONFIGURED`, `CONFIG_INVALID`, or `CONFIGURED` from the shared state machine in `hermes/drata_state.py`. `connection_tested` is always `false`. No network call; no credential values. |
| `send_evidence(event)` | The POST described below. Refuses (no network call) with `error="insecure_url_refused"` and a warning log (URL value never logged) if `HERMES_DRATA_CCT_URL` is not `https://`, and with `error="phi_safety_check_failed"` if `event.assert_phi_safe()` fails. |
| `send_test_evidence()` | Returns `ExportResult(success=False, attempts=0, error="UNSUPPORTED", reason=...)`. No network call: the only verified transport is the CCT POST URL, which writes into a real Drata tenant, and no sandbox endpoint is known. |
| `test_connection()` | Offline **structural** check returning `ConnectionResult(state, success, reason, live_validated=False)`. It is **not** a live connection test and does not prove Drata accepts the credentials or URL. See the state table below. |

`test_connection()` states (no network call in any state; the reason names env
vars only and never includes the URL or API key):

| State | When |
|---|---|
| `NOT_CONFIGURED` | `HERMES_DRATA_CCT_URL` is not set (even if the API key is set). |
| `CONFIG_INVALID` | URL is malformed, does not use `https://` (also logs a warning), or `HERMES_DRATA_API_KEY` is absent. |
| `CONFIGURED` | URL is a well-formed `https://` URL and the API key is present. `success=True` means only that this structural check passed. |
| `UNSUPPORTED` | Returned for `test_connection(live=True)`: no verified read-only Drata endpoint exists. |
| `CONNECTION_SUCCESS` / `CONNECTION_FAILED` | Reserved for future live validation; never returned today. |

`POST /api/v1/drata/config` still returns HTTP 501 and reports `state`, `reason`,
and `live_validated` from `test_connection()`.

### Legacy `/v1/scrub` Drata path (Path A)

`dispatch_drata_cct()` in `hermes/webhooks.py` is **legacy** and kept unchanged
for backward compatibility. It is **not** routed through `DrataConnector` because
the payloads are built from different source models (V1 `ComplianceReceipt` vs
gateway `EvidenceEvent`) and share no payload-building step.

Known payload-shape divergence (live Drata acceptance of either shape is UNKNOWN):

| | Path A (legacy, `/v1/scrub`) | Path B (canonical, gateway) |
|---|---|---|
| Body | flat JSON object | `{"data": {...}}` |
| Category fields | `phi_classes_detected/redacted`, counts | `phi_categories_detected/redacted` |
| Chain fields | `chain_position`, `receipt_hash` | `receipt_digest`, `prev_receipt_digest`, `gateway_sequence` |
| Retries | none | 2 on 5xx / transient errors |
| Idempotency | none | `X-Idempotency-Key: {event_id}` |
| Timeout | 3s | 3s |

## Configuration

Unset exporter URLs = no-op for that exporter. Gateway enforcement works without any exporter configured.

```bash
# Optional gateway evidence export (same vars as /v1/scrub)
HERMES_WEBHOOK_URL=https://your-siem.example/webhook
HERMES_DRATA_CCT_URL=https://public-api.drata.com/public/v2/custom-connections/{connectionId}/resources/{resourceId}/records
HERMES_DRATA_API_KEY=your-drata-api-key
```

## Drata CCT — what Hermes sends

Hermes posts to the **full URL** configured in `HERMES_DRATA_CCT_URL` (Drata v2 Custom Data Records upsert endpoint). Request shape:

```http
POST {HERMES_DRATA_CCT_URL}
Authorization: Bearer {HERMES_DRATA_API_KEY}
Content-Type: application/json
X-Idempotency-Key: {event_id}
User-Agent: hermes-gateway-drata-cct/1.0
```

Body (top-level `data` key required by Drata v2 API):

```json
{
  "data": {
    "id": "<event_id>",
    "timestamp": "<ISO 8601 UTC>",
    "transaction_id": "<gw_* id>",
    "receipt_id": "<receipt id>",
    "event_id": "<uuid>",
    "event_type": "gateway_enforcement",
    "source": "hermes-gateway",
    "workspace_id": "<workspace id>",
    "gateway_decision": "ALLOW|REDACT|BLOCK",
    "upstream_contacted": true,
    "upstream_provider": "openai|azure_openai|anthropic",
    "endpoint_path": "/v1/chat/completions",
    "phi_categories_detected": ["HIPAA_SSN"],
    "phi_categories_redacted": [],
    "policy_id": "<policy id>",
    "policy_version": "<semver>",
    "policy_digest": "<hex>",
    "receipt_digest": "<hex>",
    "prev_receipt_digest": "<hex or null>",
    "gateway_sequence": 0,
    "failure_class": null,
    "gateway_version": "<semver>",
    "signature_algorithm": "EdDSA"
  }
}
```

### What Hermes does NOT send to Drata

- Raw request or response bodies
- Prompts, completions, or message content
- PHI values (SSN, names, MRNs, emails, phone numbers, etc.)
- Detector snippets or redacted text
- Full COSE_Sign1 envelope (`cose_sign1_hex` is webhook-only; Drata receives digests only)
- API keys, vault keys, or signing key material
- Upstream provider credentials

Category names (e.g. `HIPAA_SSN`) and counts of categories are metadata — not PHI values.

## Upstream contacted semantics

| Decision | upstream_contacted |
|---|---|
| BLOCK (pre-forward) | `false` |
| ALLOW | `true` |
| REDACT | `true` |
| Upstream transport failure (after forward attempt) | `true` |

## Testing

- `tests/test_gateway_evidence_export.py` — schema, PHI safety, BLOCK/REDACT/ALLOW, exporter failures
- `tests/security/test_phi_never_egresses.py` — BLOCK invariant unchanged

## Limitations (not implemented)

- Drata adapter implemented and contract-tested; live tenant validation pending
- Outbox is flushed only by gateway traffic for the same workspace; there is no periodic scheduler, so queued events for an idle workspace wait for its next request (or a manual `flush_outbox()` call)
- No API or dashboard view of `DEAD_LETTER` rows yet; inspect `evidence_outbox.db` directly
- No immutable external storage (WORM/TSA/SCITT)
- No streaming enforcement evidence
- SQLite receipt storage remains mutable local filesystem
