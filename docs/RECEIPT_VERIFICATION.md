# Receipt Verification

Customers can independently verify Hermes Gateway V2 receipts without reading Python source.

## Prerequisites

1. The COSE_Sign1 receipt bytes (hex from SQLite or API response `receipt_digest` lookup).
2. The published **public key PEM** from the gateway key manifest (derived from the persistent keystore in production).

## Quick verify (CLI)

```bash
# Save receipt COSE bytes to a file (example from gateway SQLite cose_sign1_hex)
echo "<hex>" | xxd -r -p > receipt.cose

# Export public key from keystore ceremony / key manifest
hermes-verify receipt receipt.cose --public-key gateway-public.pem
```

Output:

```
VALID
signature_valid: True
receipt_digest_valid: True
...
decision: BLOCK
forwarded: False
policy_digest: ...
```

Or JSON:

```bash
hermes-verify receipt receipt.cose --public-key gateway-public.pem --json
```

Exit codes: `0` = VALID, `1` = INVALID, `2` = malformed input.

## What is verified

| Claim | Meaning |
|---|---|
| `signature_valid` | Ed25519 COSE signature matches published public key |
| `receipt_digest_valid` | Payload digest matches unprotected header |
| `chain_link_valid` | Prior digest field present (full chain needs prior receipts) |
| `workspace_id` | Tenant isolation identifier |
| `upstream_provider` | openai / azure_openai / anthropic |
| `decision` | ALLOW / REDACT / BLOCK |
| `forwarded` | Whether an upstream HTTP request was attempted/completed |
| `policy_id` / `policy_version` / `policy_digest` | Policy traceability |

PHI values are **never** included in gateway receipts — only category names and counts.

## Chain verification

For ordered receipt sequences, use the Python API (library) or export receipts from `gateway_receipts` SQLite table and verify with `verify_receipt_chain()` in `hermes/receipts/v2/verifier.py`.

## Limitations

- V1 HMAC scrub receipts use a separate verification path (`/v1/scrub` attestation chain).
- External anchoring (WORM, TSA, SCITT) is not connected in the current release.
