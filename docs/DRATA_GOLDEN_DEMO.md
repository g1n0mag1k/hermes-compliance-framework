# Hermes Relay — Drata Golden Demo

**Status: CONTRACT-TESTED | NOT LIVE-VALIDATED | NOT PARTNER-APPROVED | NOT A PARTNER CONNECTION**

> This demo uses a deterministic in-process mock. It makes no
> network calls and uses no real Drata credentials.
> LIVE DRATA STATUS: NOT VALIDATED.

Every command in this document was run, and every output block is output
captured from that run (commit `038ed64`, Python 3.12.3, pytest 9.1.1).
Timings will differ between machines.

---

## Overview

The demo harness is `tests/test_drata_demo.py`. It drives one PHI-bearing
request through the gateway enforcement pipeline and follows the resulting
evidence through the local outbox to a mock Drata endpoint.

**What it proves:** what Hermes does. A PHI request is blocked. It gets a
signed receipt. A metadata-only `EvidenceEvent` is written to the local
outbox before any Drata call. The evidence is POSTed as `{"data": {...}}`
with `X-Idempotency-Key: {event_id}`. Duplicates are rejected. A Drata 503
does not change enforcement. A retry reuses the original `event_id`.

**What it does not prove:** anything about how a real Drata tenant behaves.
See [What This Does Not Prove](#what-this-does-not-prove).

### How the mock works

- **Mock Drata:** `MockDrataServer` is installed in place of
  `urllib.request.urlopen`, the transport `DrataConnector` uses. It records
  each POST's method, headers, and body. It stores only whether an
  `Authorization` header was present, never its value. It returns the status
  set on `mock.status` (200, or 503 for the failure step).
- **Mock AI provider:** the gateway's upstream client uses an
  `httpx.MockTransport`. Every request that reaches it is recorded. For a
  `BLOCK` decision that list must stay empty.
- **No network:** an autouse fixture replaces `socket.create_connection`,
  `socket.socket.connect`, and `socket.socket.connect_ex`, and fails the
  test if a real connection is attempted.
- **Fake configuration:** `HERMES_DRATA_CCT_URL=https://drata-mock.invalid/demo/records`
  (`.invalid` is reserved by RFC 2606 and cannot resolve) and
  `HERMES_DRATA_API_KEY=demo-fake-key-not-a-real-credential`. They are set
  by the fixture, not by the operator.
- **Isolation:** workspace data, the receipt chain, and the outbox
  database live in pytest's `tmp_path`. Inline retry sleeps are disabled.

### The BLOCK scenario

Workspace policy `DRATA_DEMO_BLOCK` (version `1.0.0`): `text_action`,
`binary_action`, `on_detector_error`, and `on_parse_error` are all `BLOCK`.
The approved providers are `openai`, `azure_openai`, and `anthropic`.

The request goes to provider `openai`, `POST /v1/chat/completions`, with
`Content-Type: application/json`. The body is:

```json
{"model": "gpt-4o", "messages": [{"role": "user", "content": "Patient John Smith, SSN 123-45-6789"}]}
```

### How the steps are structured

The seven steps are cumulative. `test_stepN_*` runs steps 1 through N in
order on a fresh isolated environment, so each isolated command also
re-checks every earlier step.

---

## Prerequisites

Run from the repository root.

**REQUIRED** — Python 3.12 virtualenv:

```bash
python3.12 -m venv .venv
```

**OPTIONAL** — only if the previous command fails with
`ensurepip is not available` (Debian/Ubuntu images without `python3.12-venv`):

```bash
sudo apt-get update && sudo apt-get install -y python3.12-venv
python3.12 -m venv .venv
```

**REQUIRED** — runtime and dev/test dependencies:

```bash
.venv/bin/pip install -r requirements.txt -r requirements-dev.txt -q
```

**REQUIRED** — spaCy English model used by the PHI classifier:

```bash
.venv/bin/python -m spacy download en_core_web_sm
```

**OPTIONAL** — confirm test collection:

```bash
.venv/bin/python -m pytest --collect-only -q 2>&1 | tail -3
```

Output captured:

```
-- Docs: https://docs.pytest.org/en/stable/how-to/capture-warnings.html
703 tests collected in 2.09s
```

**Not required:** `HERMES_API_KEY`, `HERMES_SIGNING_KEY`, `HERMES_VAULT_KEY`,
`HERMES_DRATA_CCT_URL`, `HERMES_DRATA_API_KEY`, or any Drata account. The
demo was verified in a fresh clone with no `HERMES_*` variables set. Without
`HERMES_SIGNING_KEY` and `HERMES_VAULT_KEY`, Hermes uses insecure dev keys
and emits the `UserWarning`s shown in the output below. That is expected for
a demo and must not be done in production.

---

## Running the Full Demo

```bash
.venv/bin/python -m pytest tests/test_drata_demo.py -v
```

Output captured (this is what to show in the meeting):

```
============================= test session starts ==============================
platform linux -- Python 3.12.3, pytest-9.1.1, pluggy-1.6.0 -- /workspace/.venv/bin/python
cachedir: .pytest_cache
rootdir: /workspace
configfile: pytest.ini
plugins: cov-6.0.0, anyio-4.15.1
collecting ... collected 9 items

tests/test_drata_demo.py::test_step1_phi_detection_and_block PASSED      [ 11%]
tests/test_drata_demo.py::test_step2_evidence_event_is_phi_safe PASSED   [ 22%]
tests/test_drata_demo.py::test_step3_outbox_enqueue_before_drata_call PASSED [ 33%]
tests/test_drata_demo.py::test_step4_mock_drata_acceptance PASSED        [ 44%]
tests/test_drata_demo.py::test_step5_idempotency_duplicate_rejected_no_resend PASSED [ 55%]
tests/test_drata_demo.py::test_step6_drata_503_leaves_enforcement_unaffected PASSED [ 66%]
tests/test_drata_demo.py::test_step7_retry_reuses_original_event_id PASSED [ 77%]
tests/test_drata_demo.py::test_drata_demo_full_flow_in_order PASSED      [ 88%]
tests/test_drata_demo.py::test_gateway_http_block_unaffected_by_drata_503 PASSED [100%]

=============================== warnings summary ===============================
.venv/lib/python3.12/site-packages/fastapi/testclient.py:1
  /workspace/.venv/lib/python3.12/site-packages/fastapi/testclient.py:1: StarletteDeprecationWarning: Using `httpx` with `starlette.testclient` is deprecated; install `httpx2` instead.
    from starlette.testclient import TestClient as TestClient  # noqa

hermes/vault.py:62
  /workspace/hermes/vault.py:62: UserWarning: HERMES_VAULT_KEY not set — using insecure dev key. Set HERMES_VAULT_KEY to a 64-char hex string before production.
    VAULT_KEY: bytes = _load_vault_key()

gateway/app.py:50
  /workspace/gateway/app.py:50: DeprecationWarning: 
          on_event is deprecated, use lifespan event handlers instead.
  
          Read more about it in the
          [FastAPI docs for Lifespan Events](https://fastapi.tiangolo.com/advanced/events/).
          
    @app.on_event("startup")

.venv/lib/python3.12/site-packages/fastapi/applications.py:4681
  /workspace/.venv/lib/python3.12/site-packages/fastapi/applications.py:4681: DeprecationWarning: 
          on_event is deprecated, use lifespan event handlers instead.
  
          Read more about it in the
          [FastAPI docs for Lifespan Events](https://fastapi.tiangolo.com/advanced/events/).
          
    return self.router.on_event(event_type)  # ty: ignore[deprecated]

tests/test_drata_demo.py::test_step1_phi_detection_and_block
  /workspace/hermes/attestation.py:59: UserWarning: HERMES_SIGNING_KEY not set — using insecure dev key. Set HERMES_SIGNING_KEY to a hex string before production.
    SIGNING_KEY: bytes = _load_signing_key()

-- Docs: https://docs.pytest.org/en/stable/how-to/capture-warnings.html
======================== 9 passed, 5 warnings in 2.44s =========================
```

The 5 warnings are dependency deprecation notices and the dev-key warnings
described in [Prerequisites](#prerequisites). None of them are test failures.

Besides the seven steps, the file has two more tests:

- `test_drata_demo_full_flow_in_order` runs all seven steps in one
  environment. It then checks that exactly two evidence events were built
  and the upstream AI provider was never contacted.
- `test_gateway_http_block_unaffected_by_drata_503` sends the same PHI
  request through the real HTTP route `/gateway/openai/v1/chat/completions`
  while mock Drata returns 503. The response is HTTP 403 with error code
  `phi_detected`, and the body contains no PHI. The stored receipt is
  `BLOCK` with `forwarded: false`. The background flush then runs after the
  response and records `HTTP 503` on a still-`PENDING` outbox row.

---

## Step-by-Step Walkthrough

Each isolated command prints the same session header and warnings summary as
the full run. The warnings are identical except that the
`HERMES_SIGNING_KEY` warning names the test being run. The header and
warnings are shown once, for Step 1, and marked as omitted for Steps 2–7.

### Step 1 — PHI detection and block

**Proves:** a PHI-bearing prompt is blocked before it reaches the AI
provider, and the decision is recorded in a signed, verifiable receipt.

```bash
.venv/bin/python -m pytest tests/test_drata_demo.py::test_step1_phi_detection_and_block -v
```

Output captured:

```
============================= test session starts ==============================
platform linux -- Python 3.12.3, pytest-9.1.1, pluggy-1.6.0 -- /workspace/.venv/bin/python
cachedir: .pytest_cache
rootdir: /workspace
configfile: pytest.ini
plugins: cov-6.0.0, anyio-4.15.1
collecting ... collected 1 item

tests/test_drata_demo.py::test_step1_phi_detection_and_block PASSED      [100%]

=============================== warnings summary ===============================
.venv/lib/python3.12/site-packages/fastapi/testclient.py:1
  /workspace/.venv/lib/python3.12/site-packages/fastapi/testclient.py:1: StarletteDeprecationWarning: Using `httpx` with `starlette.testclient` is deprecated; install `httpx2` instead.
    from starlette.testclient import TestClient as TestClient  # noqa

hermes/vault.py:62
  /workspace/hermes/vault.py:62: UserWarning: HERMES_VAULT_KEY not set — using insecure dev key. Set HERMES_VAULT_KEY to a 64-char hex string before production.
    VAULT_KEY: bytes = _load_vault_key()

gateway/app.py:50
  /workspace/gateway/app.py:50: DeprecationWarning: 
          on_event is deprecated, use lifespan event handlers instead.
  
          Read more about it in the
          [FastAPI docs for Lifespan Events](https://fastapi.tiangolo.com/advanced/events/).
          
    @app.on_event("startup")

.venv/lib/python3.12/site-packages/fastapi/applications.py:4681
  /workspace/.venv/lib/python3.12/site-packages/fastapi/applications.py:4681: DeprecationWarning: 
          on_event is deprecated, use lifespan event handlers instead.
  
          Read more about it in the
          [FastAPI docs for Lifespan Events](https://fastapi.tiangolo.com/advanced/events/).
          
    return self.router.on_event(event_type)  # ty: ignore[deprecated]

tests/test_drata_demo.py::test_step1_phi_detection_and_block
  /workspace/hermes/attestation.py:59: UserWarning: HERMES_SIGNING_KEY not set — using insecure dev key. Set HERMES_SIGNING_KEY to a hex string before production.
    SIGNING_KEY: bytes = _load_signing_key()

-- Docs: https://docs.pytest.org/en/stable/how-to/capture-warnings.html
======================== 1 passed, 5 warnings in 2.17s =========================
```

**What the assertions mean:**

- The gateway decision is `BLOCK`, and the receipt payload also records
  `BLOCK`.
- `HIPAA_SSN` is among the detected PHI categories.
- The receipt records `forwarded: false`, there is no upstream response, and
  the mock AI provider received zero requests.
- The receipt was persisted (`receipt_persistence_failed` is false) and can
  be read back from the workspace chain as `BLOCK`.
- The receipt's COSE_Sign1 signature verifies against the gateway's public
  key.

### Step 2 — Evidence event is PHI-safe

**Proves:** the evidence Hermes builds for Drata describes the decision
without containing the PHI that caused it.

```bash
.venv/bin/python -m pytest tests/test_drata_demo.py::test_step2_evidence_event_is_phi_safe -v
```

Output captured (header and warnings summary omitted; identical to Step 1):

```
tests/test_drata_demo.py::test_step2_evidence_event_is_phi_safe PASSED   [100%]
======================== 1 passed, 5 warnings in 2.28s =========================
```

**What the assertions mean:**

- Exactly one `EvidenceEvent` was built for the request.
- Neither the serialized event nor the Drata record built from it contains
  `John Smith`, `John`, `Smith`, `123-45-6789`, the full prompt, or a
  standalone `SSN` label. They also contain nothing from the (never-called)
  upstream response.
- The event has no field whose name is on the forbidden-field list, and
  `assert_phi_safe()` passes.
- The event and the Drata record carry `BLOCK`, `upstream_contacted` is
  false, and `HIPAA_SSN` appears as a category name.
- `receipt_id` and `receipt_digest` match the signed receipt from Step 1,
  and the event has an `event_id`.

### Step 3 — Outbox enqueue before any Drata call

**Proves:** evidence is written to local storage first. Drata is not on the
request path.

```bash
.venv/bin/python -m pytest tests/test_drata_demo.py::test_step3_outbox_enqueue_before_drata_call -v
```

Output captured (header and warnings summary omitted; identical to Step 1):

```
tests/test_drata_demo.py::test_step3_outbox_enqueue_before_drata_call PASSED [100%]
======================== 1 passed, 5 warnings in 2.31s =========================
```

**What the assertions mean:**

- When the event was enqueued, mock Drata had received zero requests, and it
  still has zero.
- The workspace has exactly one outbox row: same `event_id`, status
  `PENDING`, `attempt_count` 0, no `last_error`.
- The stored payload deserializes back to exactly the same `EvidenceEvent`.
- Neither the outbox row nor the raw bytes of the SQLite outbox file contain
  any PHI value, the fake API key, the fake URL or host, or the word
  `Bearer`.

### Step 4 — Mock Drata acceptance

**Proves:** the exact request Hermes sends to the Drata CCT URL, and that a
2xx marks the evidence as exported.

```bash
.venv/bin/python -m pytest tests/test_drata_demo.py::test_step4_mock_drata_acceptance -v
```

Output captured (header and warnings summary omitted; identical to Step 1):

```
tests/test_drata_demo.py::test_step4_mock_drata_acceptance PASSED        [100%]
======================== 1 passed, 5 warnings in 2.23s =========================
```

**What the assertions mean:**

- One flush with mock Drata returning 200 reports 1 exported, 0 retries, and
  0 dead-lettered. The row becomes `EXPORTED`.
- Mock Drata received exactly one `POST`.
- The body's only top-level key is `data`. `data.event_id` is the event's
  `event_id`, `data.gateway_decision` is `BLOCK`, and
  `data.upstream_contacted` is false.
- The `X-Idempotency-Key` header equals the `event_id`.
- An `Authorization` header was sent. The mock never stored its value.
- The raw body, and everything the mock recorded, contain no PHI and no
  credential material.

### Step 5 — Idempotency

**Proves:** Hermes does not queue or send the same evidence twice.

```bash
.venv/bin/python -m pytest tests/test_drata_demo.py::test_step5_idempotency_duplicate_rejected_no_resend -v
```

Output captured (header and warnings summary omitted; identical to Step 1):

```
tests/test_drata_demo.py::test_step5_idempotency_duplicate_rejected_no_resend PASSED [100%]
======================== 1 passed, 5 warnings in 2.33s =========================
```

**What the assertions mean:**

- Enqueueing the same event again raises `DuplicateEventError`.
- A flush one day later exports nothing, retries nothing, and dead-letters
  nothing.
- Mock Drata still has exactly one request.
- The outbox still holds exactly one row, still `EXPORTED`.

### Step 6 — Drata failure leaves enforcement unaffected

**Proves:** a Drata outage cannot change or delay an enforcement decision.

```bash
.venv/bin/python -m pytest tests/test_drata_demo.py::test_step6_drata_503_leaves_enforcement_unaffected -v
```

Output captured (header and warnings summary omitted; identical to Step 1):

```
tests/test_drata_demo.py::test_step6_drata_503_leaves_enforcement_unaffected PASSED [100%]
======================== 1 passed, 5 warnings in 2.58s =========================
```

**What the assertions mean:**

- A second identical PHI request is `BLOCK`ed, and the gateway result is
  complete before mock Drata receives anything for it.
- The second request gets its own `event_id`, different from the first, and
  its row is `PENDING` with `attempt_count` 0.
- With mock Drata returning 503, a flush reports 0 exported, 1 retry
  scheduled, and 0 dead-lettered.
- The row stays `PENDING` with `attempt_count` 1, `last_error` `HTTP 503`,
  and a `next_attempt_at` later than the flush time.
- Every failed attempt carried the second event's `event_id` as
  `X-Idempotency-Key`.
- Both stored receipts still read `BLOCK` with `forwarded: false`. The first
  row is still `EXPORTED`, and the mock AI provider received zero requests.

### Step 7 — Retry reuses the same event_id

**Proves:** a retry re-sends the original evidence. It never builds a new
event.

```bash
.venv/bin/python -m pytest tests/test_drata_demo.py::test_step7_retry_reuses_original_event_id -v
```

Output captured (header and warnings summary omitted; identical to Step 1):

```
tests/test_drata_demo.py::test_step7_retry_reuses_original_event_id PASSED [100%]
======================== 1 passed, 5 warnings in 6.33s =========================
```

**What the assertions mean:**

- A flush one second before `next_attempt_at` exports nothing and sends
  nothing, so the retry does not fire early.
- A flush at `next_attempt_at`, with mock Drata back to 200, exports 1 row.
  The row becomes `EXPORTED` with `attempt_count` 2.
- Exactly one new request was sent. Its `X-Idempotency-Key` and
  `data.event_id` both equal the second event's original `event_id`, and its
  body contains no PHI.
- Still only two events exist, so no new event was built for the retry.
- Both outbox rows are `EXPORTED`, and the set of idempotency keys Drata saw
  is exactly the two event IDs.

---

## What This Proves

Against a deterministic mock, with no network access:

- A request containing a patient name and SSN is blocked under a block
  policy, and the AI provider is never contacted.
- The block is recorded in a persisted, signed V2 receipt whose signature
  verifies.
- The evidence sent toward Drata is metadata only. It holds category names
  such as `HIPAA_SSN`, the decision, and receipt identifiers. It never holds
  the PHI values themselves.
- Evidence is written to a local outbox before any Drata call. The outbox
  contains no PHI and no Drata credentials.
- Hermes sends evidence as `POST {"data": {...}}` with
  `X-Idempotency-Key: {event_id}` and a Bearer `Authorization` header. The
  body contains no credentials.
- The same event cannot be queued twice. Evidence already exported is never
  re-sent by Hermes.
- A Drata 503 does not change or delay a `BLOCK`. The response is returned
  first, and the failure is recorded and scheduled for retry.
- Retries wait until their scheduled time and reuse the original `event_id`
  in both the header and the body.

## What This Does Not Prove

These require live Drata validation:

- That a real Drata tenant accepts the `{"data": {...}}` payload shape and
  its 23 keys.
- That the `HERMES_DRATA_CCT_URL` structure is correct for a real Drata
  tenant.
- That a static Bearer token is the correct authentication scheme, or that a
  given Drata API key has sufficient permissions.
- That Drata honors `X-Idempotency-Key` (or deduplicates on `id`). A retry
  after a lost 2xx could create a duplicate record in Drata.
- That a 2xx from Drata means the record is persisted and visible.
- How Drata responds to errors, rate limits, or 429s.
- That records appear in the Drata UI, and how they are displayed.
- Any mapping of Hermes evidence to Drata controls or tests.
- The legacy /v1/scrub path is not covered by this demo. It sends
  a different flat payload to the same Drata URL with no PHI check,
  no idempotency key, and no retry.

This demo also does not cover the periodic outbox scheduler (none exists),
per-workspace Drata configuration (not implemented), OAuth (not
implemented), or a Partner Connection (not implemented). See
[`integrations/DRATA.md`](./integrations/DRATA.md) §15.

## Next Steps to Live Validation

Follow [`integrations/DRATA_VALIDATION.md`](./integrations/DRATA_VALIDATION.md)
§PATH TO LIVE VALIDATION. Until that result is recorded and committed, the
status remains CONTRACT-TESTED.

LIVE DRATA STATUS: NOT VALIDATED.
