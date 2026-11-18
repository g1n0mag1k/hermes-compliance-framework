# Production Readiness Checklist

Hermes Relay is **not production-ready** as of 2026-11-18 (status re-confirmed; checklist last substantively updated 2026-09-18). This checklist tracks gates required before any claim of production readiness.

An independent code-level audit on 2026-11-18 found gaps this checklist does not yet track as items: the reversible redaction vault is still not called from any production code path (see `README.md` "Reversible (roadmap)" and `hermes/vault.py`); the Drata integration remains contract-tested only, with no live tenant validation; and there is no partner-specific integration or sandbox environment for a compliance-automation partner program (e.g. Secureframe). Treat this checklist's `[x]` marks as "implemented and tested," not as "ready to pitch to a partner program" — see the partner-readiness gap audit for that question.

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
[x] full pytest suite passes (849 passed, 17 strict xfail documenting known findings; 532 as of 2026-09-18, floor is 836 per CURSORRULES.md/AGENTS.md)
[x] documentation matches implementation
[ ] customer claims reviewed (see PRODUCT_CAPABILITY_MATRIX.md)
```

## Controlled design-partner readiness

For a **Controlled Design-Partner Deployment**, use:

- `HERMES_ENV=production`
- `HERMES_GATEWAY_POLICY=HIPAA_PRODUCTION_BLOCK`
- Persistent gateway keystore (`HERMES_GATEWAY_KEYSTORE_PATH` + `HERMES_GATEWAY_KEYSTORE_PASSPHRASE`)
- Route all supported AI traffic through the Hermes Gateway (ports 8788)

See `docs/DESIGN_PARTNER_DEPLOYMENT.md`.
