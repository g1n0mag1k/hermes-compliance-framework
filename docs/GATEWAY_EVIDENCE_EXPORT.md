# Gateway Evidence Export — Design Note

## Current state

| Path | Evidence | Drata CCT |
|---|---|---|
| `/v1/scrub` | V1 HMAC attestation chain | `dispatch_drata_cct()` wired in `hermes/api.py` |
| Gateway (`/gateway/*`) | V2 COSE_Sign1 receipts in SQLite | **Not wired** |

## Recommended architecture (future)

```
Gateway decision
    → signed V2 receipt (local SQLite)
    → generic EvidenceEvent abstraction
    → optional exporters:
        - webhook (HERMES_WEBHOOK_URL)
        - Drata CCT
        - SIEM / GRC
```

## Why not implement Drata-only now

- Hard-coding Drata in the gateway couples enforcement to one GRC vendor.
- `/v1/scrub` and gateway receipts use different formats (V1 vs V2).
- Design-partner priority is correct enforcement + verifiable local receipts.

## Minimal next implementation (P1 backlog)

1. Define `EvidenceEvent` dataclass (workspace, decision, receipt_digest, policy_digest, timestamp, provider).
2. Emit after successful `issue_gateway_receipt()` persistence.
3. Pluggable `EvidenceExporter` protocol with webhook adapter first.
4. Optional Drata adapter reusing `dispatch_drata_cct` payload mapping.

## Documentation correction

Do **not** claim gateway decisions automatically sync to Drata until the above is implemented and tested.
