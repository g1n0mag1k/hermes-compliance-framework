# Receipt Verification

Customers can independently verify Hermes Gateway V2 receipts without reading Python source.

## Prerequisites

1. The COSE_Sign1 receipt bytes as `.cose` files.
2. The published **public key PEM** of the gateway's persistent keystore.

In the Docker deployment both come from the operator commands in
`docs/DEPLOYMENT.md` §6 and §12:

```bash
# Public key (once, after keystore-init)
docker compose run --rm --no-deps -T hermes-gateway hermes-relay keystore-public-key > gateway-public.pem

# All receipts of one workspace, as ordered .cose files
docker compose exec -T hermes-gateway hermes-relay export-receipts --workspace <workspace_id> --out /app/exports/<name>
docker compose cp hermes-gateway:/app/exports/<name> ./<name>
```

## Quick verify (CLI)

```bash
hermes-verify receipt <name>/<file>.cose --public-key gateway-public.pem
```

`hermes-verify` is installed in the `hermes-relay:1.0.0` image. It can run
isolated from the deployment:
`docker run --rm --network none -v "$PWD:/r:ro" hermes-relay:1.0.0 hermes-verify receipt /r/<name>/<file>.cose --public-key /r/gateway-public.pem`.

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

Verify a whole exported chain. The command checks each signature, the
digest links, a gap-free `gateway_sequence` from 0, and one workspace:

```bash
hermes-verify chain <name>/ --public-key gateway-public.pem --workspace-id <workspace_id>
```

It prints `VALID` or `INVALID`, the receipt count, and the set of
`signer_key_ids`. With a persistent keystore that set is a single key ID.
Exit codes are the same as for `receipt`. The library equivalent is
`verify_receipt_chain()` in `hermes/receipts/v2/verifier.py`.

## Limitations

- V1 HMAC scrub receipts use a separate verification path (`/v1/scrub` attestation chain).
- External anchoring (WORM, TSA, SCITT) is not connected in the current release.
