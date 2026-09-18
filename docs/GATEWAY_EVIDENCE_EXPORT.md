# Gateway Evidence Export

## Architecture

```
Gateway enforcement decision
    → V2 COSE_Sign1 receipt (local SQLite)
    → EvidenceEvent (metadata-only contract)
    → optional exporters (best-effort, post-decision):
        - WebhookExporter (HERMES_WEBHOOK_URL)
        - DrataExporter (HERMES_DRATA_CCT_URL)
```

Export runs **after** receipt persistence inside `issue_gateway_receipt()`. Exporter failure never changes the enforcement decision.

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

## Configuration

Unset exporter URLs = no-op for that exporter. Gateway enforcement works without any exporter configured.

```bash
# Optional gateway evidence export (same vars as /v1/scrub)
HERMES_WEBHOOK_URL=https://your-siem.example/webhook
HERMES_DRATA_CCT_URL=https://api.drata.com/public/custom-connection/YOUR_ID/data
HERMES_DRATA_API_KEY=your-drata-api-key
```

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

- Live Drata connectivity verified only via mock/contract tests in CI
- No immutable external storage (WORM/TSA/SCITT)
- No streaming enforcement evidence
- SQLite receipt storage remains mutable local filesystem
