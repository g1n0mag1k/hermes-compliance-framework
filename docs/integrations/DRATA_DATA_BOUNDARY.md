# Hermes Relay — Drata Data Boundary

This document lists exactly what Hermes Relay sends to Drata and what it does
not. It is derived from `gateway/evidence_export/event.py` (`EvidenceEvent`)
and `gateway/evidence_export/drata_connector.py` (`build_drata_record()`),
plus the legacy `/v1/scrub` path in `hermes/webhooks.py`.

Status: CONTRACT-TESTED against mocks only. See
[`DRATA_VALIDATION.md`](./DRATA_VALIDATION.md).

---

## SENT TO DRATA

### Gateway evidence (canonical path, `DrataConnector`)

One HTTPS POST per gateway enforcement decision to `HERMES_DRATA_CCT_URL`.

**Headers**

| Header | Value |
|---|---|
| `Content-Type` | `application/json` |
| `User-Agent` | `hermes-gateway-drata-cct/1.0` |
| `Authorization` | `Bearer {HERMES_DRATA_API_KEY}` (only when the key is set) |
| `X-Idempotency-Key` | `event_id` |

**Body:** `{"data": {...}}` with exactly these 23 keys. The left column is the
key Drata receives; the right column is the `EvidenceEvent` field in
`gateway/evidence_export/event.py` it is copied from.

| Key sent to Drata | `EvidenceEvent` field |
|---|---|
| `id` | `event_id` |
| `timestamp` | `timestamp` |
| `transaction_id` | `transaction_id` |
| `receipt_id` | `receipt_id` |
| `event_id` | `event_id` |
| `event_type` | `event_type` |
| `source` | `source` |
| `workspace_id` | `workspace_id` |
| `gateway_decision` | `decision` |
| `upstream_contacted` | `upstream_contacted` |
| `upstream_provider` | `upstream_provider` |
| `endpoint_path` | `endpoint_path` |
| `phi_categories_detected` | `phi_categories_detected` |
| `phi_categories_redacted` | `phi_categories_redacted` |
| `policy_id` | `policy_id` |
| `policy_version` | `policy_version` |
| `policy_digest` | `policy_digest` |
| `receipt_digest` | `receipt_digest` |
| `prev_receipt_digest` | `prev_receipt_digest` |
| `gateway_sequence` | `gateway_sequence` |
| `failure_class` | `failure_class` |
| `gateway_version` | `gateway_version` |
| `signature_algorithm` | `signature_algorithm` |

Notes:

- `phi_categories_detected` / `phi_categories_redacted` contain category
  names only (for example `HIPAA_SSN`), never the detected values.
- `prev_receipt_digest` and `failure_class` are sent as JSON `null` when they
  have no value.
- `endpoint_path` is the provider API path from the gateway route (for
  example `/v1/chat/completions`). The query string is a separate request
  field and is not part of it. The path can include provider resource
  identifiers that appear in supported routes, such as an Azure deployment
  name (`/openai/deployments/...`) or an OpenAI thread ID (`/v1/threads/...`).
- `workspace_id` identifies the Hermes workspace. Because Drata configuration
  is global, records from all workspaces on a deployment go to the same
  Drata connection and resource.

### Legacy `/v1/scrub` path (`dispatch_drata_cct()`)

When `HERMES_DRATA_CCT_URL` is set, `/v1/scrub` and `/v1/trial-scan` also POST
a flat JSON object (no `data` wrapper) to the same URL, built from the V1
`ComplianceReceipt`:

`timestamp`, `transaction_id`, `receipt_id`, `zero_phi_egress_confirmed`,
`phi_classes_detected`, `phi_classes_redacted`, `count_detected`,
`count_redacted`, `compliance_frameworks`, `chain_position`, `receipt_hash`,
`declared_scope`, `evidence_incomplete_categories`, `issuer`, `source`.

Headers: `Content-Type: application/json`,
`User-Agent: hermes-relay-drata-cct/1.0`, and
`Authorization: Bearer {HERMES_DRATA_API_KEY}` when the key is set. No
idempotency key.

This path contains PHI class names and per-class counts, not PHI values. It
is **not** protected by `assert_phi_safe()` (see below) and does not refuse
non-`https://` URLs.

---

## NOT SENT TO DRATA

Hermes does not send any of the following to Drata on either path:

- Patient names, SSNs, MRNs, emails, phone numbers, or any other detected PHI
  value
- Raw prompts or completions
- Raw request or response bodies
- Detector snippets or redacted text
- `cose_sign1_hex` (the full COSE_Sign1 cryptographic envelope; Drata
  receives `receipt_digest` and `prev_receipt_digest` only)
- `detector_states`
- `content_types_inspected` / `content_types_not_inspected`
- `all_detectors_clean`
- API keys, provider credentials, signing keys, vault keys (the Drata API key
  appears only in the `Authorization` header)
- `upstream_status`

`cose_sign1_hex`, `detector_states`, `content_types_inspected`,
`content_types_not_inspected`, `all_detectors_clean`, and `upstream_status`
are fields of `EvidenceEvent` that `build_drata_record()` deliberately does
not copy. They remain in two places outside Drata:

- the local outbox row (`evidence_payload` in `evidence_outbox.db`), which
  stores the full serialized `EvidenceEvent`;
- the optional webhook exporter (`HERMES_WEBHOOK_URL`), which posts the full
  `EvidenceEvent`.

---

## HOW THE BOUNDARY IS ENFORCED

### 1. Construction: a fixed field mapping

- `EvidenceEvent` is a Pydantic model with `extra="forbid"`, so no field
  outside its declared schema can be added.
- It is built by `build_evidence_event()` from the signed V2 receipt payload,
  which contains decision metadata and category names, not request content.
- The Drata body is built field-by-field by
  `DrataConnector.build_drata_record()`. Only the 23 keys listed above are
  copied; there is no pass-through of arbitrary fields.

### 2. Check: `assert_phi_safe()` in `gateway/evidence_export/event.py`

`EvidenceEvent.assert_phi_safe()` serializes the **entire** event (a superset
of the Drata record, including `cose_sign1_hex` and `detector_states`) and
raises `ValueError` if either check fails.

**Five regex patterns** (`_PHI_FORBIDDEN_PATTERNS`), matched anywhere in the
serialized JSON:

| # | Pattern | Intended to catch |
|---|---|---|
| 1 | `\b\d{3}-\d{2}-\d{4}\b` | SSN in `123-45-6789` form |
| 2 | `\bMRN\s*\d+\b` (case-insensitive) | `MRN` followed by digits |
| 3 | `\bPatient\s+[A-Z][a-z]+\s+[A-Z][a-z]+\b` | `Patient First Last` |
| 4 | `\b\d{3}-\d{3}-\d{4}\b` | US phone in `555-123-4567` form |
| 5 | `\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z\|a-z]{2,}\b` | Email address |

**Forbidden field names** (`_FORBIDDEN_FIELD_NAMES`). The check fails if any
of these appears as a quoted JSON string (`"name"`) anywhere in the
serialized event:

`raw_request_body`, `raw_response_body`, `request_body`, `response_body`,
`prompt`, `completion`, `source_text`, `redacted_text`, `detector_snippet`,
`payload`, `content`, `messages`.

**Where it runs** on the gateway path:

| Call site | On failure |
|---|---|
| `build_evidence_event()` | Event is not built; export is skipped and logged |
| `enqueue_event()` (before the outbox insert) | Nothing is written to the outbox |
| `DrataConnector.send_evidence()` (before the POST) | No network call; `phi_safety_check_failed`, row moved to `DEAD_LETTER` |
| `dispatch_evidence_export()` (inline exporters) | Export skipped |

The legacy `/v1/scrub` path (`dispatch_drata_cct()`) does not call
`assert_phi_safe()`.

### Limits of the check

`assert_phi_safe()` is a **heuristic, not a formal proof** that no PHI is
present. It matches a small set of representative formats. It would not, for
example, catch a name without the `Patient` prefix, a date of birth, an
address, an SSN or phone number written without dashes, or a medical record
number without the `MRN` label. The primary safeguard is the construction in
§1: the event is built only from receipt metadata, never from request or
response content. The regex check is a defense-in-depth tripwire on top of
that.

### Tests

The boundary is tested by:

- `tests/test_drata_demo.py` — `test_step2_evidence_event_is_phi_safe`
  (the event and the Drata record for a real `Patient John Smith, SSN
  123-45-6789` gateway request contain no PHI values and no forbidden fields),
  `test_step3_outbox_enqueue_before_drata_call` (the outbox row and the raw
  database file contain no PHI or credentials), and
  `test_step4_mock_drata_acceptance` (the POST body sent to the mock contains
  no PHI or credentials).
- `tests/test_gateway_evidence_export.py` —
  `test_evidence_event_rejects_phi_in_serialized_payload`,
  `test_evidence_event_rejects_forbidden_body_fields`,
  `test_drata_payload_contains_no_phi_with_real_gateway_request`,
  `test_drata_connector_refuses_phi_unsafe_event_without_network`,
  `test_outbox_rows_contain_no_phi`, `test_outbox_refuses_phi_unsafe_event`,
  `test_outbox_last_error_contains_no_credentials`, and
  `test_sanitize_error_strips_urls_hosts_and_credentials`.

These tests run against mocks. They prove what Hermes sends; they do not
prove how Drata stores or displays it.
