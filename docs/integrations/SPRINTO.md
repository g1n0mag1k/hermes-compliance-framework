# Hermes Relay — Sprinto Integration

**Status: ARCHITECTURE CORRECT | CONTRACT-TESTABLE | NOT LIVE-VALIDATED**

This document describes the Sprinto Open Evidence Ingestion path implemented
in `hermes/webhooks.py`. The multipart shape and auth model are confirmed from
Sprinto partner documentation. Live acceptance against a real Sprinto tenant
has **not** been demonstrated.

---

## Overview

`dispatch_sprinto_evidence()` POSTs a Hermes compliance receipt as custom
evidence to Sprinto's REST Open Evidence Ingestion API. It is **not** GraphQL.
An earlier GraphQL mutation against `app.sprinto.com/dev-api/graphql` was
incorrect and has been removed.

## Endpoint

```
POST {HERMES_SPRINTO_BASE_URL}/api/v1/workflow-checks/{workflowCheckPk}/evidence
```

| Piece | Value |
|---|---|
| Default base URL | `https://app.sprinto.com` |
| Path | `/api/v1/workflow-checks/{HERMES_SPRINTO_WORKFLOW_CHECK_PK}/evidence` |
| Method | `POST` |
| Content-Type | `multipart/form-data` |

`workflowCheckPk` is a Sprinto-internal identifier discovered by paginating
their workflow checks API (or taken from the Sprinto dashboard). Store it as
`HERMES_SPRINTO_WORKFLOW_CHECK_PK`. Confirm the correct PK on the partner call
before production use.

## Authentication

```
Authorization: Bearer <HERMES_SPRINTO_API_KEY>
```

Do **not** use an `api-key` header. The Bearer token comes from Sprinto API
settings.

## Multipart body

Two parts:

### Part 1 — field name `data` (`application/json`)

```json
{
  "status": "PASS" | "FAIL",
  "timestamp": "<ISO 8601 UTC>",
  "evaluation_scope": "hermes-relay-phi-canary-test"
}
```

- `status` is `"PASS"` when `receipt.zero_pii_egress_confirmed` is true,
  otherwise `"FAIL"`.
- `timestamp` is `receipt.issued_at`.

### Part 2 — field name `file` (`application/pdf`, optional)

The Hermes signed PDF evidence report (binary), when provided as `pdf_bytes`.
Filename sent: `hermes_evidence.pdf`.

## Environment variables

| Variable | Required | Purpose |
|---|---|---|
| `HERMES_SPRINTO_API_KEY` | yes | Bearer token from Sprinto API settings |
| `HERMES_SPRINTO_WORKFLOW_CHECK_PK` | yes | Workflow check PK for the evidence path |
| `HERMES_SPRINTO_BASE_URL` | no | Default `https://app.sprinto.com` |

If either required variable is unset, `dispatch_sprinto_evidence()` is a no-op
and returns `False` (no network call).

## Code

- Function: `dispatch_sprinto_evidence()` in `hermes/webhooks.py`
- Contract tests: `tests/test_webhooks.py` (multipart Content-Type, Bearer
  auth, PASS/FAIL status, missing-config no-op)

## Honest state

- Multipart shape and Bearer auth: confirmed from Sprinto partner docs.
- Live tenant POST acceptance: **UNKNOWN / NOT LIVE-VALIDATED**.
- Correct `workflowCheckPk` for a given control: must be confirmed on the
  partner call.
- Never claim a live Sprinto partner connection unless a real tenant has
  returned a successful response and that result is committed.
