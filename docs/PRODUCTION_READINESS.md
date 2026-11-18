# Production Readiness Checklist

Hermes Relay is **not production-ready** as of 2026-11-18 (status re-confirmed; checklist last substantively updated 2026-09-18). This checklist tracks gates required before any claim of production readiness.

An independent code-level audit on 2026-11-18 found gaps this checklist does not yet track as items. As of the same day, one of them has since been closed: the reversible redaction vault is now wired into production via `/v1/scrub-reversible` + `/v1/vault/retrieve` (org_admin-gated, with its own tamper-evident per-workspace access log — see `README.md` "Reversible redaction" and `docs/MULTI_TENANCY.md`), but it is not yet assigned a pricing/plan tier and has had no partner-facing validation. Still open: the Drata integration remains contract-tested only, with no live tenant validation; and there is no partner-specific integration or sandbox environment for a compliance-automation partner program (e.g. Secureframe). Treat this checklist's `[x]` marks as "implemented and tested," not as "ready to pitch to a partner program" — see the partner-readiness gap audit for that question.

```
[x] BLOCK policy implemented (HIPAA_PRODUCTION_BLOCK)
[x] BLOCK policy is explicit and production-configurable (HERMES_GATEWAY_POLICY=HIPAA_PRODUCTION_BLOCK)
[x] PHI detection occurs before upstream forwarding
[x] BLOCK decision prevents upstream request
[x] upstream request count tested == 0 (tests/security/test_phi_never_egresses.py)
[x] detector failure fails closed
[x] parser failure fails closed
[x] policy failure fails closed
[x] unsupported content fails closed
[x] production gateway signing keys required (HERMES_GATEWAY_KEYSTORE_*)
[x] persistent gateway signing identity across restart (tests/test_cryptographic_evidence_lifecycle.py)
[x] receipt integrity verified (hermes-verify / V2 verifier)
[x] receipt records forwarded=false for BLOCK
[x] gateway evidence export implemented (EvidenceEvent + webhook/Drata exporters — see GATEWAY_EVIDENCE_EXPORT.md)
[x] upstream failure semantics documented (502 + receipt with forwarded=true)
[x] bypass paths reviewed (see DOCUMENTATION_AUDIT.md)
[x] security regression suite passes
[x] full pytest suite passes (864 passed, 17 strict xfail documenting known findings; 532 as of 2026-09-18, floor is 836 per CURSORRULES.md/AGENTS.md)
[x] documentation matches implementation
[x] reversible redaction wired into production (/v1/scrub-reversible, /v1/vault/retrieve), org_admin-gated, tamper-evident per-workspace access log (2026-11-18)
[ ] reversible redaction assigned a pricing/plan tier (currently available to any org_admin-role workspace regardless of plan)
[ ] customer claims reviewed (see PRODUCT_CAPABILITY_MATRIX.md)
```

## Controlled design-partner readiness

For a **Controlled Design-Partner Deployment**, use:

- `HERMES_ENV=production`
- `HERMES_GATEWAY_POLICY=HIPAA_PRODUCTION_BLOCK`
- Persistent gateway keystore (`HERMES_GATEWAY_KEYSTORE_PATH` + `HERMES_GATEWAY_KEYSTORE_PASSPHRASE`)
- Route all supported AI traffic through the Hermes Gateway (ports 8788)

See `docs/DESIGN_PARTNER_DEPLOYMENT.md`.
