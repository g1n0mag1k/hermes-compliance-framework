# Hermes Relay — Drata Validation Status

## Validation levels

| Level | Definition |
|---|---|
| CONTRACT-TESTED | Hermes behavior verified against deterministic mocks. Payload shape, PHI exclusion, idempotency, retry, enforcement independence all proven. |
| LIVE-VALIDATED | A real Drata tenant returned a successful response. **NOT yet achieved.** |
| PARTNER-APPROVED | Drata has reviewed and approved the integration model. **NOT yet achieved.** |
| PARTNER-CONNECTION | Drata native partner integration model. **NOT implemented.** |

**Current status: CONTRACT-TESTED only.**

"Proven" at the CONTRACT-TESTED level means proven about what **Hermes**
does: the shape of the payload Hermes sends, what it excludes, which headers
it sets, and how it retries. It says nothing about how Drata responds.

---

## WHAT CONTRACT-TESTED MEANS

### Proven (against mocks)

From the deterministic demo harness, `tests/test_drata_demo.py`. It replaces
`urllib.request.urlopen` with an in-process mock Drata server, blocks all
real socket connections, and uses a fake `.invalid` URL and a fake key.

| Demo step | What it proves |
|---|---|
| 1. PHI detection and block | A request containing `Patient John Smith, SSN 123-45-6789` is `BLOCK`ed under a block policy; `HIPAA_SSN` is detected; the upstream AI provider is not contacted; a signed V2 receipt is persisted and its signature verifies. |
| 2. Evidence event is PHI-safe | The `EvidenceEvent` and the Drata record built from it contain no PHI values and no forbidden fields; they carry `BLOCK`, `upstream_contacted: false`, and the matching `receipt_id` / `receipt_digest`. |
| 3. Outbox enqueue before Drata call | The event is written to the local outbox as `PENDING` before any Drata request; the outbox row and the raw database file contain no PHI or credentials. |
| 4. Mock Drata acceptance | One flush sends one POST whose body is exactly `{"data": {...}}`, with `X-Idempotency-Key` equal to `event_id` and an `Authorization` header present; on 2xx the row becomes `EXPORTED`. The body contains no PHI or credentials. |
| 5. Idempotency | Re-enqueueing the same `event_id` is rejected; a later flush sends nothing for an `EXPORTED` row. |
| 6. Drata failure leaves enforcement unaffected | A second request is `BLOCK`ed and returned before any Drata call; a mock 503 leaves the row `PENDING` with `attempt_count` 1, `last_error` `HTTP 503`, and a future `next_attempt_at`; stored receipts are unchanged and upstream is never contacted. |
| 7. Retry reuses the same event_id | No retry fires before `next_attempt_at`; the retry at `next_attempt_at` sends the same `event_id` in the header and body, no new event is built, and the row becomes `EXPORTED`. |
| HTTP-level check | Through the real gateway HTTP route, a PHI request returns 403 `phi_detected` while the mock Drata returns 503; the background flush runs after the response and records `HTTP 503`. |

Also covered by contract tests in `tests/test_gateway_evidence_export.py`:

- Bearer header, `User-Agent`, `X-Idempotency-Key`, and 3s timeout on the wire
- 2 inline retries on 5xx; no inline retry on 4xx
- Refusal of non-`https://` URLs and PHI-unsafe events with no network call
- Structural connection states (`NOT_CONFIGURED` / `CONFIG_INVALID` /
  `CONFIGURED`), `live_validated` always `false`, and `UNSUPPORTED` for live
  checks and test-evidence sends
- Outbox backoff, `MAX_OUTBOX_ATTEMPTS`, permanent-4xx dead-lettering,
  no retry of `DEAD_LETTER` rows, expired-lease reclaim, per-workspace flush
  scope, and `exported_at` recorded only on success
- No credentials in logs, reasons, or stored `last_error`

### NOT proven (requires live validation)

- That Drata accepts the `{"data": {...}}` payload shape and these 23 keys
- That the configured URL structure is correct for a real Drata tenant
- That a static Bearer token is the correct authentication scheme, and that
  a Drata API key has sufficient permissions
- That Drata honors `X-Idempotency-Key` (or deduplicates on `id`), so that a
  retry after a lost 2xx does not create a duplicate record
- That a 2xx from Drata means the record is persisted and visible
- How Drata responds to errors (which 4xx/5xx codes, rate limits, 429 usage)
- That records appear in the Drata UI, and how they are displayed
- Anything about the legacy `/v1/scrub` flat payload in a real tenant
- Any mapping of Hermes evidence to Drata controls or tests

---

## PATH TO LIVE VALIDATION

Steps to move from CONTRACT-TESTED to LIVE-VALIDATED. **REQUIRED** means
Hermes must do this step. **UNKNOWN** means the step depends on Drata
behavior that has not been verified.

| # | Step | Label |
|---|---|---|
| 1 | Obtain a Drata tenant and CCT URL (connection ID and resource ID from the Drata UI) | REQUIRED; URL structure UNKNOWN |
| 2 | Set `HERMES_DRATA_CCT_URL` and `HERMES_DRATA_API_KEY`; confirm `GET /v1/integrations/drata/status` reports `CONFIGURED` | REQUIRED |
| 3 | Run the gateway and send a test request through `/gateway/{provider}/...` | REQUIRED |
| 4 | Confirm the record appears in the Drata CCT dashboard | REQUIRED; Drata-side display UNKNOWN |
| 5 | Confirm the idempotency key prevents duplicates on retry | UNKNOWN (depends on whether Drata honors `X-Idempotency-Key`) |
| 6 | Record the result and commit it | REQUIRED |

Notes for running these steps:

- Use a Drata tenant that is safe for test records. Every POST to the CCT URL
  writes a real record; Hermes has no sandbox mode.
- In step 3, confirm through the status endpoint that `events_exported`
  increased and `events_dead_letter` did not.
- Step 5 needs a controlled duplicate: send the same `event_id` twice (for
  example by re-POSTing the recorded body with the same
  `X-Idempotency-Key`) and check whether Drata stores one record or two.
  Hermes does not provide a tool for this today.
- Step 6 should record the date, the Drata response codes observed, whether
  duplicates occurred, and any payload changes Drata required. Until that
  record is committed, the status remains CONTRACT-TESTED.

---

## QUESTIONS FOR DRATA

1. Does Drata accept the `{"data": {...}}` CCT payload shape?
2. Does Drata honor `X-Idempotency-Key` to prevent duplicate records?
3. Is Bearer token the correct authentication scheme?
4. What is the correct URL structure for the CCT endpoint?
5. Does a 2xx response guarantee the record is persisted in Drata?
6. What retry behavior does Drata recommend on its side?
7. What is the path to a Partner Connection, and what does Drata require to
   begin that process?
