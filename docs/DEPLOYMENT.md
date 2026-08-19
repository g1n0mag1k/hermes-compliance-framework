# Hermes Relay — Deployment Guide

This document covers running Hermes Relay's FastAPI service (`hermes/api.py`)
in development and production, plus how to read and verify what it produces.

---

## 1. Prerequisites

- Python 3.12+ (the project targets 3.12.3 — see `.python-version`)
- `pip` and the packages in `requirements.txt`
- The local spaCy model `en_core_web_sm` (downloaded separately — see below;
  not a pip dependency because it's a data package, not a library)
- Docker, optional — only needed if you're deploying via container rather
  than running the Python process directly

Hermes has a hard compliance invariant: **the PHI classification model must
be local.** `hermes/classifier.py` refuses to start (raises at import time)
if `en_core_web_sm` isn't installed — there is no fallback to a remote model,
by design, since that would mean sending payload text off-box before it's
been scrubbed.

---

## 2. Environment Variables

| Variable | Required? | Description |
|---|---|---|
| `HERMES_API_KEY` | **Required in production.** No default — every `/v1/scrub` and `/v1/review` call is rejected with 401 without a matching `X-API-Key` header. | Shared-secret tenant key for API authentication. |
| `HERMES_SIGNING_KEY` | **Required in production.** Hex string (any length that decodes to valid bytes). | HMAC-SHA256 key used to sign every attestation receipt and review receipt. Without it in production, the process refuses to start (`RuntimeError`). In development, an insecure fixed key is used and a warning is printed — receipts signed with it are **not** valid evidence and will not match a differently-keyed instance. |
| `HERMES_VAULT_KEY` | **Required in production.** Must be exactly 64 hex characters (32 bytes) — used directly as an AES-256-GCM key. | Encryption key for `hermes/vault.py`'s token vault. Same fail-fast behavior as `HERMES_SIGNING_KEY`: required and validated for length in production, insecure dev default with a warning otherwise. |
| `HERMES_ENV` | Optional. `development` (default) or `production`. | Switches the fail-fast behavior above. Setting this to `production` without also setting `HERMES_SIGNING_KEY` and `HERMES_VAULT_KEY` will crash the process on startup — that's intentional, not a bug. |
| `HERMES_DB_PATH` | Optional. Default: `hermes_chain.db` in the working directory. | Path to the SQLite database backing the attestation chain. The chain reloads from this file on every process start, so this is what makes receipts survive a restart — pointing two processes at the same path means they share one chain. |

Generate a signing/vault key locally with:

```bash
python -c "import secrets; print(secrets.token_hex(32))"
```

(32 bytes → 64 hex characters, valid for both `HERMES_SIGNING_KEY` and the
length-constrained `HERMES_VAULT_KEY`.)

---

## 3. Docker Deployment

```bash
docker build -t hermes-relay .
docker run -d \
  -e HERMES_API_KEY=<your-key> \
  -e HERMES_SIGNING_KEY=<64-hex-chars> \
  -e HERMES_VAULT_KEY=<64-hex-chars> \
  -e HERMES_ENV=production \
  -e HERMES_DB_PATH=/data/hermes_chain.db \
  -v hermes_data:/data \
  -p 8000:8000 \
  --name hermes-relay \
  hermes-relay
```

The `-v hermes_data:/data` volume mount matters for persistence: without it,
`HERMES_DB_PATH` points inside the container's writable layer, and the chain
is lost when the container is removed (not just stopped — removed). Mount a
named volume or bind mount for any deployment where the chain needs to
outlive the container.

The image runs as a non-root user (`hermes`, uid 10001) and exposes port
8000. A `HEALTHCHECK` is baked in (`GET /health` every 30s).

---

## 4. Direct Python Deployment

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python -m spacy download en_core_web_sm

export HERMES_API_KEY=<your-key>
export HERMES_SIGNING_KEY=<64-hex-chars>
export HERMES_VAULT_KEY=<64-hex-chars>
export HERMES_ENV=production
export HERMES_DB_PATH=/var/lib/hermes/hermes_chain.db

uvicorn hermes.api:app --host 0.0.0.0 --port 8000
```

Run behind a process supervisor (systemd, supervisord, etc.) in production —
`uvicorn` alone doesn't restart itself on crash.

---

## 5. Sample Request — `/v1/scrub`

```bash
curl -X POST http://localhost:8000/v1/scrub \
  -H "X-API-Key: <your-key>" \
  -H "Content-Type: application/json" \
  -d '{"payload": "Patient John Smith, SSN 234-56-7891, contact john@example.com"}'
```

Returns `clean_text`, the per-flag `audit_log`, and a full `compliance_receipt`
(see §7 below for what each field means).

---

## 6. Sample Request — `/v1/review`

```bash
curl -X POST http://localhost:8000/v1/review \
  -H "X-API-Key: <your-key>" \
  -H "Content-Type: application/json" \
  -d '{
    "transaction_id": "txn_api_abc123",
    "reviewed_by": "kiki.stein@example.com",
    "decision": "overridden",
    "override_reason": "False positive — not actually PHI."
  }'
```

`transaction_id` must match a transaction that already has a
`ComplianceReceipt` in the chain (i.e. a prior `/v1/scrub` call) — reviewing
an unknown transaction returns 404. `decision` must be exactly one of
`"accepted"`, `"overridden"`, or `"escalated"` — anything else returns 400.
`override_reason` is optional and typically used with `"overridden"` or
`"escalated"`.

The response is a `HumanReviewReceipt`, chained into the same
`AttestationChain` as the original scan — see §7.

---

## 7. How to Read an Attestation Receipt

A `/v1/scrub` response's `compliance_receipt` has these fields:

| Field | Meaning |
|---|---|
| `receipt_id` | Unique ID for this receipt (`rcpt_<transaction_id>_<position>`). |
| `transaction_id` | ID of the scrub call this receipt documents. |
| `issued_at` | UTC timestamp the receipt was signed. |
| `issuer` | Fixed string identifying the Hermes Relay version that issued it. |
| `compliance_frameworks` | Frameworks this receipt is evidence for (currently `["HIPAA", "PCI-DSS"]`). |
| `pii_classes_detected` / `pii_classes_redacted` | Which PHI/PCI classes were found / redacted, as class-name lists. |
| `count_detected` / `count_redacted` | Per-class **occurrence counts** — e.g. `{"HIPAA_SSN": 2}`. This is what actually proves nothing leaked: two matching class-name lists can still hide a partial redaction (2 detected, 1 redacted) that a class-set comparison alone would miss. `zero_pii_egress_confirmed` is computed from these, not from the class lists. |
| `payload_char_count_in` / `payload_char_count_out` / `chars_removed` | Size accounting for the scrub. |
| `zero_pii_egress_confirmed` | See §8. |
| `zero_pii_egress_scope_note` | See §8. |
| `downstream_target` | Where the scrubbed payload was forwarded, if applicable (proxy use case); `null` for direct `/v1/scrub` calls. |
| `previous_receipt_hash` | The prior chain item's hash — this is the actual chain link. |
| `receipt_hash` | This receipt's own HMAC-SHA256 signature, covering every other field. |
| `chain_position` | Zero-indexed position in the attestation chain. |
| `declared_scope` | CFR citations for every category Hermes actively checks (13 of 18 HIPAA Safe Harbor categories — see §10). |
| `evidence_incomplete_categories` | CFR citations for categories **not** checked. Absence of a flag here is not evidence of absence — this list exists specifically so that distinction is machine-readable. |
| `detectors_executed` | Per-category tri-state status: `"ran_clean"` (executed, nothing wrong), `"ran_error"` (executed, threw an exception, caught), or `"not_run"`. A silently-failed detector is never indistinguishable from a clean scan. |

A `/v1/review` response (`HumanReviewReceipt`) has:

| Field | Meaning |
|---|---|
| `review_id` | Unique ID for this review event. |
| `transaction_id` | Which scrub transaction this review covers. |
| `reviewed_by` | Who made the decision (free-text identifier — email, username, etc.). |
| `issued_at` | UTC timestamp of the review. |
| `decision` | `"accepted"`, `"overridden"`, or `"escalated"`. |
| `override_reason` | Free-text explanation; `null` unless supplied. |
| `original_receipt_hash` | The `receipt_hash` of the `ComplianceReceipt` being reviewed, captured at review time. Included in the signed content, so editing this field after the fact invalidates `review_receipt_hash`. |
| `previous_receipt_hash` / `review_receipt_hash` / `chain_position` | Same chain-linkage mechanics as a `ComplianceReceipt` — a review receipt is a first-class item in the same hash chain, not a side record. |

---

## 8. `zero_pii_egress_confirmed` — What It Means and Its Scope Note

`zero_pii_egress_confirmed: true` means: for every PHI/PCI class *within
declared scope*, the number of instances detected equals the number
redacted (`count_detected == count_redacted`, field-for-field). It is
**not** a claim that the payload contains no PHI of any kind.

The accompanying `zero_pii_egress_scope_note` field states this explicitly
on every receipt: *"Confirmed within declared_scope only.
evidence_incomplete_categories were not checked."* Categories in
`evidence_incomplete_categories` (currently: certificate/license numbers,
device identifiers, biometric identifiers, full-face photographs, and the
Safe Harbor catch-all "other unique identifiers") are not scanned at all —
a clean receipt says nothing about them, by design, rather than silently
implying they were checked and passed.

Read `zero_pii_egress_confirmed: true` as: *"every category we checked
came back with detected count equal to redacted count."* Not as: *"this
payload is HIPAA-compliant"* or *"this payload contains no PHI."*

---

## 9. Chain Verification

Every `AttestationChain` instance exposes `verify_chain() -> bool`, which
checks three invariants across every item (compliance receipts and review
receipts alike):

1. Every item's stored hash matches a fresh HMAC-SHA256 computed over its
   own content — proves nothing in that item was edited after signing.
2. Every item's `previous_receipt_hash` matches the prior item's hash —
   proves nothing was reordered or deleted.
3. `chain_position` values are strictly sequential with no gaps — closes
   the "delete a receipt and re-sign the survivors" attack that invariant 1
   alone doesn't catch.

From Python:

```python
from hermes.attestation import ATTESTATION_CHAIN
assert ATTESTATION_CHAIN.verify_chain()
```

There is no HTTP endpoint for this today — it's an internal/operational
check, run it from a Python shell or a script with access to the same
`HERMES_DB_PATH` the running service uses. `export_chain()` returns the
full chain as a list of dicts if you need to inspect or archive it.

**Caveat confirmed while writing this doc:** `verify_chain()` recomputes
every signature using whatever `HERMES_SIGNING_KEY` is set in *its own*
process's environment. Running the verification script above with a
different `HERMES_SIGNING_KEY` than the one the live server used will
report `False` on a perfectly intact chain — that's a key mismatch, not
chain corruption. Always export the exact same `HERMES_SIGNING_KEY` before
running an out-of-process `verify_chain()` check.

---

## 10. Known Architectural Limits

Hermes Relay makes narrow, explicit claims by design — see
[`docs/SCOPE_BOUNDARY.md`](./SCOPE_BOUNDARY.md) for the full list, including:

- 13 of 18 HIPAA Safe Harbor identifier categories are covered; 5 are not
  (certificate/license numbers, device identifiers, biometric identifiers,
  full-face photographs, and the "other unique identifiers" catch-all).
- Quasi-identifier combinations (e.g. gender + birth date + ZIP) are not
  detected — each identifier is redacted in isolation.
- The NER model (`en_core_web_sm`) is a general-purpose English model, not
  trained on clinical text — lower recall on clinical names and rare
  diagnoses than a clinical-specific model would have.
- Indirect/contextual identifiers (rare diagnoses, unusual occupations,
  narrative family references) are out of scope entirely.

As of this deployment guide, chain persistence (this document's §2/§3) and
the human-review event type (§6/§7) close two of the four gaps identified
in the most recent adversarial audit — span-level transformation lineage
and signing-key rotation continuity remain open and are tracked as roadmap
items, not implemented here.
