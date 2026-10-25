# Hermes Relay — Drata Integration

**Status: CONTRACT-TESTED | NOT LIVE-VALIDATED | NOT PARTNER-APPROVED | NOT A PARTNER CONNECTION**

This document describes only what the Hermes Relay repository implements and
tests. Anything Hermes has not verified against a real Drata tenant is labeled
**UNKNOWN**. Hermes Relay is not an official Drata partner integration.

Companion documents:

- [`DRATA_DATA_BOUNDARY.md`](./DRATA_DATA_BOUNDARY.md) — exactly what is and is not sent to Drata
- [`DRATA_VALIDATION.md`](./DRATA_VALIDATION.md) — validation levels, what is proven, and open questions for Drata
- [`../GATEWAY_EVIDENCE_EXPORT.md`](../GATEWAY_EVIDENCE_EXPORT.md) — engineering reference for gateway evidence export

---

## 1. What Hermes Relay is

Hermes Relay is a local-first PHI enforcement gateway for HIPAA-covered
entities, their business associates, and the MSPs that serve them. It runs inside the customer's environment as two
FastAPI services: the Hermes Relay API (`hermes/`, port 8787), which scrubs
PHI from text submitted to `/v1/scrub`, and the AI Enforcement Gateway
(`gateway/`, port 8788), a fail-closed proxy that inspects outbound requests
to OpenAI, Azure OpenAI, and Anthropic and redacts or blocks detected PHI
according to policy. Every gateway decision produces a signed V2 COSE_Sign1
receipt stored in a local SQLite hash chain. PHI detection is deterministic
(spaCy NER, Presidio, regex, Luhn) and does not send PHI to external
infrastructure.

## 2. What the Drata integration does

Proven by the repository:

- Hermes exports **gateway enforcement evidence** (metadata only) to Drata
  using Drata **Custom Connections / Custom Data Records (CCT)**: one HTTP POST
  per gateway decision to a URL the operator configures.
- The integration is **contract-tested against deterministic mocks**
  (`tests/test_drata_demo.py`, `tests/test_gateway_evidence_export.py`).
- **Live tenant validation is pending.** No real Drata tenant has returned a
  successful response to a Hermes request, and no such result is committed.

Not provided: Drata control mappings, Drata test definitions, workspace
discovery, OAuth, per-workspace Drata configuration, or a Partner Connection.

## 3. Current integration model

| Aspect | Implementation |
|---|---|
| Transport | HTTPS `POST` to the full URL in `HERMES_DRATA_CCT_URL` |
| Authentication | `Authorization: Bearer {HERMES_DRATA_API_KEY}` (static token) |
| Payload | `{"data": {...}}` wrapping a metadata-only record mapped from `EvidenceEvent` |
| Idempotency | `X-Idempotency-Key: {event_id}` on every attempt |
| Delivery | Local SQLite outbox, flushed in a background task after the gateway response is sent |
| Configuration scope | Global (process environment); one CCT URL for all workspaces |

There is **no OAuth**, **no workspace discovery**, and **no Partner Connection**.

Canonical code: `DrataConnector` in `gateway/evidence_export/drata_connector.py`.
`DrataExporter` in `gateway/evidence_export/exporters.py` is a thin wrapper
that delegates to it.

### Legacy `/v1/scrub` path

A second, older Drata path exists: `dispatch_drata_cct()` in
`hermes/webhooks.py`, scheduled as a background task by `/v1/scrub` and
`/v1/trial-scan` whenever `HERMES_DRATA_CCT_URL` is set. It is kept unchanged
for backward compatibility and is **not** the integration described in this
document. It sends a flat JSON body (no `data` wrapper) with different field
names, makes one attempt with no retry and no idempotency key, does not use
the outbox, does not refuse non-`https://` URLs, and does not run
`assert_phi_safe()`. Its fields are listed in
[`DRATA_DATA_BOUNDARY.md`](./DRATA_DATA_BOUNDARY.md). Whether Drata accepts
either payload shape is UNKNOWN.

## 4. Architecture

```
AI Client → Hermes Relay → EvidenceEvent → Local Outbox → Drata Connector → Drata
```

Expanded, with where each step runs:

```
AI Client
   │  POST /gateway/{provider}/{path}
   ▼
Hermes Relay gateway (gateway/app.py → gateway/pipeline.py)
   │  inspect → policy decision (ALLOW / REDACT / BLOCK)
   │  issue_gateway_receipt(): sign + persist V2 receipt (local SQLite)
   ▼
EvidenceEvent (gateway/evidence_export/event.py)
   │  build_evidence_event() + assert_phi_safe()
   ▼
Local Outbox (gateway/evidence_export/outbox.py, evidence_outbox.db)
   │  enqueue_event(): local INSERT, status PENDING, no network
   │
   │  ── gateway response returned to AI Client ──
   │
   │  FastAPI background task: flush_outbox(workspace_id)
   ▼
Drata Connector (gateway/evidence_export/drata_connector.py)
   │  send_evidence(): https check, assert_phi_safe(), POST {"data": {...}}
   ▼
Drata (HERMES_DRATA_CCT_URL)
```

## 5. Evidence flow

What the code does for one gateway request, in order:

1. The client sends a request to `POST /gateway/{provider_id}/{path}` on the
   gateway. `gateway_relay()` authenticates the workspace and runs the
   enforcement pipeline.
2. The pipeline reaches a decision (`ALLOW`, `REDACT`, or `BLOCK`) and calls
   `issue_gateway_receipt()`, which signs a V2 COSE_Sign1 receipt and persists
   it to the workspace's local SQLite chain. If persistence fails, the request
   fails with HTTP 503 and no evidence is exported.
3. After persistence, `try_export_evidence()` runs. If no exporter is
   configured (`HERMES_DRATA_CCT_URL` and `HERMES_WEBHOOK_URL` both unset), it
   returns immediately and nothing is queued.
4. `build_evidence_event()` builds an `EvidenceEvent` from the receipt. It
   assigns a new random `event_id` (UUID4) and calls `assert_phi_safe()`.
5. If Drata is configured (`HERMES_DRATA_CCT_URL` set), `enqueue_event()`
   runs `assert_phi_safe()` again and inserts the serialized event into the
   local outbox as `PENDING`. This is a local SQLite write with no network
   I/O. If the write fails, the error is logged and the request continues.
6. The gateway returns its response to the client. For a `BLOCK` decision the
   upstream AI provider is never contacted.
7. FastAPI runs the background task `flush_outbox(workspace_id)` after the
   response has been sent. If `HERMES_DRATA_CCT_URL` is unset the flush does
   nothing.
8. The flush atomically claims up to 50 due rows for that workspace (status
   `PENDING`, or `PROCESSING` with an expired lease), moves them to
   `PROCESSING`, and increments `attempt_count`.
9. For each claimed row, `DrataConnector.send_evidence()`:
   - refuses without a network call if the URL is not `https://`
     (`insecure_url_refused`) or if `assert_phi_safe()` fails
     (`phi_safety_check_failed`);
   - builds the `{"data": {...}}` payload from the event;
   - POSTs it with the Bearer token and `X-Idempotency-Key: {event_id}`,
     retrying inline on 5xx and network errors (see §11).
10. The flush records the outcome: `EXPORTED` (with `exported_at`) on 2xx,
    back to `PENDING` with a later `next_attempt_at` on a transient failure,
    or `DEAD_LETTER` on a permanent failure or the final allowed attempt.

## 6. Configuration

Drata export is configured by environment variables only.

| Variable | Purpose |
|---|---|
| `HERMES_DRATA_CCT_URL` | Full CCT POST URL. Must be `https://`. Unset = Drata export disabled. |
| `HERMES_DRATA_API_KEY` | Bearer token sent in the `Authorization` header. |

The connection ID and resource ID are embedded in the URL; Hermes does not
discover, create, or validate them. Both must be obtained from the Drata UI.
The URL pattern used in this repository's examples is:

```bash
HERMES_DRATA_CCT_URL=https://public-api.drata.com/public/v2/custom-connections/{connectionId}/resources/{resourceId}/records
HERMES_DRATA_API_KEY=your-drata-api-key
```

Whether this is the correct URL structure for every Drata tenant is UNKNOWN
(see [`DRATA_VALIDATION.md`](./DRATA_VALIDATION.md), Questions for Drata).

Behavior of partial configuration:

| `HERMES_DRATA_CCT_URL` | `HERMES_DRATA_API_KEY` | Result |
|---|---|---|
| unset | any | Drata export disabled; nothing queued |
| set, not `https://` | any | Events are queued; every send is refused (`insecure_url_refused`) and moved to `DEAD_LETTER` |
| set, `https://` | unset | Events are queued and POSTed **without** an `Authorization` header; the connection check reports `CONFIG_INVALID` |
| set, `https://` | set | Events are queued and POSTed with the Bearer token |

**Per-workspace Drata configuration is not implemented.** One deployment has
one `HERMES_DRATA_CCT_URL`; evidence from every workspace on that deployment
is sent to the same Drata connection and resource. Each record carries
`workspace_id`.

## 7. Authentication

What the code proves:

- A **static Bearer token**: `Authorization: Bearer {HERMES_DRATA_API_KEY}`.
- The header is added only when `HERMES_DRATA_API_KEY` is set.
- **No OAuth.** No token exchange, **no refresh**, no expiry handling.
- The token is never logged, never stored in the outbox, and is removed from
  stored error messages by `sanitize_error()`.

Whether Drata requires any additional authentication, headers, or scopes is
**UNKNOWN**.

## 8. Connection testing

The only connection test is an **offline structural check**:
`DrataConnector.test_connection()`, backed by `check_drata_config()` in
`hermes/drata_state.py`. It makes no network call.

| State | When |
|---|---|
| `NOT_CONFIGURED` | `HERMES_DRATA_CCT_URL` is not set |
| `CONFIG_INVALID` | URL is malformed (including surrounding whitespace or an invalid port), is not `https://`, or `HERMES_DRATA_API_KEY` is not set |
| `CONFIGURED` | URL is a well-formed `https://` URL and the API key is present |

A CONFIGURED result proves only that the URL is well-formed
and https. It does not prove Drata accepts these credentials.

Additional facts:

- `live_validated` is `false` on every result.
- `test_connection(live=True)` returns `UNSUPPORTED`: no verified read-only
  Drata endpoint is known.
- `CONNECTION_SUCCESS` and `CONNECTION_FAILED` are reserved and never returned.
- `send_test_evidence()` returns `UNSUPPORTED` without a network call, because
  posting to the CCT URL would write a record into a real Drata tenant and no
  sandbox endpoint is known.

Where the result is surfaced (none of these contact Drata):

| Surface | Behavior |
|---|---|
| `GET /v1/integrations/drata/status` (Hermes API, `org_admin` / `operator`) | `configured`, `connection_state`, `live_validated: false`, `transport: "CCT"`, `partner_connection: false`, and the caller workspace's outbox counts, `last_exported_at`, and sanitized `last_error` |
| `POST /api/v1/drata/config` | HTTP 501 `not_implemented`, with `state`, `reason`, and `live_validated` from `test_connection()`; stores nothing |
| Dashboard "Check Drata Status" button | Calls the status endpoint |

## 9. Evidence schema

Request sent by `DrataConnector.send_evidence()`:

```http
POST {HERMES_DRATA_CCT_URL}
Content-Type: application/json
User-Agent: hermes-gateway-drata-cct/1.0
Authorization: Bearer {HERMES_DRATA_API_KEY}
X-Idempotency-Key: {event_id}
```

The body is `{"data": {...}}` containing exactly these 23 keys, built by
`DrataConnector.build_drata_record()` from `EvidenceEvent` fields:

| Drata record key | Source `EvidenceEvent` field | Notes |
|---|---|---|
| `id` | `event_id` | Same value as `event_id` |
| `timestamp` | `timestamp` | Receipt `issued_at` (ISO 8601 UTC) |
| `transaction_id` | `transaction_id` | Gateway transaction id |
| `receipt_id` | `receipt_id` | V2 receipt id |
| `event_id` | `event_id` | UUID4, unique per event |
| `event_type` | `event_type` | Always `gateway_enforcement` |
| `source` | `source` | Always `hermes-gateway` |
| `workspace_id` | `workspace_id` | Hermes workspace id |
| `gateway_decision` | `decision` | `ALLOW`, `REDACT`, or `BLOCK` |
| `upstream_contacted` | `upstream_contacted` | Boolean; from receipt `forwarded` |
| `upstream_provider` | `upstream_provider` | e.g. `openai`, `azure_openai`, `anthropic` |
| `endpoint_path` | `endpoint_path` | e.g. `/v1/chat/completions` |
| `phi_categories_detected` | `phi_categories_detected` | Sorted, de-duplicated category names only (e.g. `HIPAA_SSN`) |
| `phi_categories_redacted` | `phi_categories_redacted` | Sorted, de-duplicated category names only |
| `policy_id` | `policy_id` | |
| `policy_version` | `policy_version` | |
| `policy_digest` | `policy_digest` | |
| `receipt_digest` | `receipt_digest` | |
| `prev_receipt_digest` | `prev_receipt_digest` | `null` for the first receipt in a chain |
| `gateway_sequence` | `gateway_sequence` | Integer |
| `failure_class` | `failure_class` | `null` when no failure |
| `gateway_version` | `gateway_version` | |
| `signature_algorithm` | `signature_algorithm` | Always `EdDSA` |

`EvidenceEvent` fields that are **not** in the Drata record: `cose_sign1_hex`,
`detector_states`, `content_types_inspected`, `content_types_not_inspected`,
`all_detectors_clean`, `upstream_status`. See
[`DRATA_DATA_BOUNDARY.md`](./DRATA_DATA_BOUNDARY.md).

Whether Drata accepts, stores, or displays these keys as sent is UNKNOWN.

## 10. Idempotency

As implemented:

- `event_id` is a UUID4 assigned once, when `build_evidence_event()` runs.
  A new gateway request always produces a new `event_id`.
- `event_id` is the outbox primary key. Inserting the same `event_id` twice
  raises `DuplicateEventError`; the gateway logs it and still returns its
  response.
- Every HTTP attempt for a row — inline retries and later flush retries —
  sends the same `event_id` as `X-Idempotency-Key` and in the body (`id` and
  `event_id`). A retry never builds a new event.
- A row in `EXPORTED` is never claimed again, so Hermes itself does not
  re-send evidence that Drata acknowledged with a 2xx.

Whether Drata honors `X-Idempotency-Key` (or deduplicates on the `id` field)
is **UNKNOWN**. If a 2xx response is lost in transit (for example, a timeout
after Drata persisted the record), the retry could create a duplicate record
in Drata.

## 11. Retry behavior

There are two layers.

**Inline, per send attempt** (`_post_json()` in `gateway/evidence_export/exporters.py`):

- 2 inline retries (`MAX_RETRIES = 2`), so up to 3 HTTP requests per send.
- Retried: HTTP 5xx, network errors and timeouts (`URLError`), and any other
  exception raised during the request.
- Not retried inline: any HTTP 4xx, including 429.
- Sleep between inline attempts: 0.25s, then 0.5s.
- Timeout: 3 seconds per HTTP request.

**Between flushes** (`gateway/evidence_export/outbox.py`):

- Each flush makes one `send_evidence()` call per due row.
- A row is attempted at most `MAX_OUTBOX_ATTEMPTS = 8` times in total.
- After a transient failure, the next attempt is scheduled with exponential
  backoff: `30s × 2^(attempt − 1)`, capped at 1 hour (30s, 60s, 120s, 240s,
  480s, 960s, 1920s).
- The 8th failed attempt moves the row to `DEAD_LETTER`.

Worst case for one event: 8 flush attempts × 3 HTTP requests = 24 POSTs, all
carrying the same `X-Idempotency-Key`.

## 12. Failure behavior

| Class | Errors | Outcome |
|---|---|---|
| Transient | HTTP 5xx, HTTP 429, network error or timeout, exporter exception, malformed exporter result | Row returns to `PENDING` with a backoff `next_attempt_at`; `DEAD_LETTER` once 8 attempts are used |
| Permanent | HTTP 4xx other than 429, `phi_safety_check_failed`, `insecure_url_refused`, `not_configured`, unparsable stored payload (`malformed_outbox_payload`) | `DEAD_LETTER` immediately |

`DEAD_LETTER`:

- Rows are never retried and never deleted; they remain for operator review.
- There is **no auto-requeue** and no API to list, inspect, or requeue
  individual rows. The status endpoint exposes only a count. Operators
  inspect `evidence_outbox.db` directly.
- `last_error` stores a sanitized message (URLs, hosts, bearer/basic tokens,
  key=value secrets, long tokens, the configured Drata URL and key, and
  PHI-shaped values removed; max 200 characters).

A flush that crashes mid-send leaves rows in `PROCESSING`. After the 300s
lease expires, the next flush reclaims them; a reclaimed row that has already
used all 8 attempts is moved to `DEAD_LETTER` with `max_attempts_exceeded`.

## 13. Outbox

- Storage: table `evidence_outbox` in `{HERMES_DATA_DIR}/evidence_outbox.db`
  (stdlib `sqlite3`). One file per deployment; every row carries
  `workspace_id`.
- Columns: `event_id` (primary key), `workspace_id`, `created_at`,
  `evidence_payload` (full `EvidenceEvent.serialize()`), `attempt_count`,
  `next_attempt_at` (retry time, or lease expiry while `PROCESSING`),
  `status`, `last_error`, `exported_at`.
- States: `PENDING`, `PROCESSING`, `EXPORTED`, `DEAD_LETTER`. (`FAILED` is not
  used.)
- `evidence_payload` is the full event, including fields not sent to Drata
  (such as `cose_sign1_hex` and `detector_states`). It is metadata only;
  `assert_phi_safe()` runs before insert.
- Claiming is atomic (`BEGIN IMMEDIATE`); a flush processes at most 50 rows.
- `exported_at` is set only when Drata returns 2xx. Rows exported before this
  column existed keep `NULL`; they are not backfilled.

**Scheduler gap:** there is no periodic scheduler. The outbox is flushed only
by a background task scheduled after a gateway request, and only for that
request's workspace. Queued or retry-scheduled events for an **idle
workspace** wait until that workspace sends its next gateway request, or
until an operator calls `flush_outbox()` manually. Backoff times are
therefore earliest-retry times, not guaranteed retry times.

## 14. Enforcement independence guarantee

- The Drata network call runs only in `flush_outbox()`, which the gateway
  schedules as a FastAPI background task. Starlette runs background tasks
  **after the gateway response has been sent**.
- The only Drata-related work on the request path is a local SQLite insert
  (`enqueue_event()`), wrapped so that any failure is logged and the response
  is returned unchanged.
- Therefore a Drata outage, slow response, 4xx, or 5xx cannot change an
  enforcement decision, delay the gateway response, or cause a blocked
  request to reach the upstream AI provider.

Covered by `tests/test_drata_demo.py`
(`test_step6_drata_503_leaves_enforcement_unaffected`,
`test_gateway_http_block_unaffected_by_drata_503`) and
`tests/test_gateway_evidence_export.py` (`test_outbox_enforcement_returns_response_when_drata_down`,
`test_outbox_block_stays_block_when_drata_down`,
`test_outbox_event_written_before_any_drata_network_call`,
`test_outbox_write_failure_still_returns_gateway_response`).

This guarantee covers the gateway Drata path only. The inline webhook
exporter (`HERMES_WEBHOOK_URL`) runs before the response and is not covered
here.

## 15. Current limitations

From [`docs/CURRENT_LIMITATIONS.md`](../CURRENT_LIMITATIONS.md) (Integrations):

- **Gateway evidence export** — optional webhook and Drata CCT exporters via
  `gateway/evidence_export/`. Best-effort post-decision export; exporter
  outage does not affect enforcement.
- **Live Drata gateway integration** — Drata adapter implemented and
  contract-tested; live tenant validation pending. Hermes sends metadata-only
  records wrapped in `{"data": {...}}`; never raw PHI.
- **Canonical Drata connector** — `DrataConnector` in
  `gateway/evidence_export/drata_connector.py`. `send_test_evidence()` returns
  `UNSUPPORTED` without any network call. `test_connection()` is an offline
  structural check only (URL set, `https://`, API key present → `CONFIGURED`;
  otherwise `NOT_CONFIGURED` or `CONFIG_INVALID`); `live_validated` is always
  `false` and live connection validation is `UNSUPPORTED`. `send_evidence()`
  refuses non-`https://` CCT URLs.
- **`/v1/scrub` Drata export (legacy)** — separate V1 path via
  `dispatch_drata_cct()` in `hermes/webhooks.py`, kept for backward
  compatibility. It sends a different, flat payload shape than the canonical
  connector, with no retries and no idempotency key.

Also true of the current code, not yet listed in `CURRENT_LIMITATIONS.md`:

- **No live validation.** No real Drata tenant has accepted a Hermes request.
  Payload shape, URL structure, authentication scheme, and idempotency
  behavior are all UNKNOWN on the Drata side.
- **Idempotency on Drata's side is UNKNOWN.** A retry after a lost 2xx could
  create a duplicate Drata record.
- **No periodic outbox scheduler.** Idle workspaces do not flush (see §13).
- **No DEAD_LETTER tooling.** No API to list, inspect, or requeue individual
  rows; no auto-requeue.
- **Single global Drata configuration.** No per-workspace Drata URL or key;
  all workspaces on a deployment export to the same Drata connection and
  resource. Parent workspaces are not aggregated with their child workspaces
  in the status endpoint.
- **Missing API key is not blocked at send time.** With a valid URL and no
  `HERMES_DRATA_API_KEY`, events are POSTed without an `Authorization`
  header (the structural check reports `CONFIG_INVALID`).
- **429 is not retried inline**; it is retried only at the next flush.
- **No live connection test and no test-evidence send** (`UNSUPPORTED`).
- **`POST /api/v1/drata/config` returns HTTP 501.** Drata cannot be
  configured from the dashboard or API.
- **Legacy `/v1/scrub` path has weaker safeguards**: no `assert_phi_safe()`,
  no `https://` enforcement, no outbox, no retry, no idempotency key.
- **Pre-migration `exported_at` values are `NULL`** and are not backfilled.
- **No Drata control mappings.** Hermes does not map evidence to any Drata
  control or test.

## 16. Future Partner Connection path

> **FUTURE / NOT IMPLEMENTED.** Nothing in this section exists in the
> repository. It is not a roadmap commitment.

Hermes Relay does not implement a Drata Partner Connection. What Drata
requires to begin or complete a Partner Connection is **UNKNOWN** and is
listed as an open question in
[`DRATA_VALIDATION.md`](./DRATA_VALIDATION.md).

Capabilities that do not exist today and would be evaluated only once Drata's
requirements are known:

- Live validation against a real Drata tenant (prerequisite for anything
  below).
- Per-workspace Drata configuration, so each child workspace can export
  to its own Drata tenant.
- Whatever authentication model Drata specifies for partner integrations.
  Hermes does not assume OAuth or any other scheme until Drata confirms it.
- Any Drata-defined control or test mapping, only if Drata provides the
  identifiers.

Until then, the supported model is the CCT POST described in this document.
