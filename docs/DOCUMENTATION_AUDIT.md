# Documentation Audit — 2026-09-18

Code is source of truth. Contradictions found and corrections applied.

## Contradictions found

| Topic | Was claimed | Actual behavior | Action |
|---|---|---|---|
| Gateway vs scrub Drata | MSP guide implies all evidence → Drata | Only `/v1/scrub` calls `dispatch_drata_cct()` | Added `GATEWAY_EVIDENCE_EXPORT.md`; qualified MSP guide scope |
| Default enforcement | README/implied "blocking" | `HIPAA_STRICT.text_action=REDACT` | Documented BLOCK vs REDACT; added `HIPAA_PRODUCTION_BLOCK` |
| Fail-closed scope | "Fail-closed gateway" globally | Upstream transport failures occur after forward | Documented PRE-FORWARD vs UPSTREAM TRANSPORT in `CURRENT_LIMITATIONS.md` |
| Gateway signing | Silent ephemeral key | Ephemeral in dev only | Production requires keystore; updated SECURITY.md |
| Single-tenant vs multi-tenant | README "single-tenant today" | Workspace isolation + registry | Clarified in `CURRENT_LIMITATIONS.md` |
| Immutable audit log | BENCHMARK.md wording | SQLite mutable | Changed to "hash-chained" / "tamper-evident" language in matrix |
| Production readiness | Landing "audit-ready" | Design-partner scope only | Added `PRODUCTION_READINESS.md` — NOT production-ready |
| Supported providers | README "Ollama" proxy | Gateway: 3 providers only | README gateway section to list gateway providers separately |
| Streaming | None explicit | Not implemented | Documented in limitations |

## Bypass path review

| Path | Classification |
|---|---|
| `/gateway/{provider}/...` with approved provider | PROTECTED |
| Direct OpenAI/Azure/Anthropic URLs | NOT PROTECTED (by design — routing requirement) |
| `/v1/scrub` | SEPARATE PATH (scrub API, not inline gateway) |
| `hermes/proxy.py` legacy proxy | DEPRECATED / separate from gateway |
| Unknown provider / invalid path | INTENTIONALLY BLOCKED (400/403) |
| Binary content-type | INTENTIONALLY BLOCKED (policy binary_action) |

## Files updated in this audit

- `README.md` — gateway positioning, REDACT vs BLOCK
- `SECURITY.md` — gateway keystore requirement
- `docs/DEPLOYMENT.md` — gateway env vars
- `docs/MSP_INTEGRATION.md` — Drata scope qualified
- `docs/DEMO_SCRIPT_15MIN.md` — aligned demo flow
- `landing/components/Solution.tsx` — already uses "tamper-evident" (OK)

## Remaining follow-ups

- Update `CURSORRULES.md` test count (502) when next editing that file
- Notion workspace sync (see agent report)
