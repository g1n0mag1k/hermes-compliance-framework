# Product Capability Matrix

Machine-readable product truth. Status values: VERIFIED | PARTIALLY VERIFIED | NOT VERIFIED | NOT IMPLEMENTED.

| Capability | Status | Evidence | Tests | Limitations | Customer Claim | Last Verified | Owner | Required Engineering |
|---|---|---|---|---|---|---|---|---|
| Gateway runtime interception | VERIFIED | `gateway/pipeline.py` | `tests/test_gateway_e2e.py` | Requires routing through gateway | "Runtime inspection for traffic routed through Hermes Gateway" | 2026-09-18 | Engineering | — |
| JSON/text request inspection | VERIFIED | `gateway/inspector.py` | `tests/test_gateway.py` | Binary not inspected | "Inspects JSON/text before forward" | 2026-09-18 | Engineering | — |
| Recursive tool argument inspection | VERIFIED | `gateway/inspector.py` | `tests/test_gateway.py` | Streaming not covered | "Inspects nested tool arguments" | 2026-09-18 | Engineering | — |
| PHI detection (16/18 Safe Harbor text scope) | VERIFIED | `hermes/classifier.py` | `tests/test_classifier.py` | P/Q reference-only; English NER | "Detects PHI within documented scope" | 2026-09-18 | Engineering | — |
| REDACT policy (default HIPAA_STRICT) | VERIFIED | `gateway/policy.py` | `tests/test_gateway.py` | Default is REDACT not BLOCK | "Configurable redaction" | 2026-09-18 | Engineering | — |
| BLOCK policy (HIPAA_PRODUCTION_BLOCK) | VERIFIED | `gateway/policy.py` | `tests/security/test_phi_never_egresses.py` | Must be explicitly configured | "Can block detected PHI per policy" | 2026-09-18 | Engineering | — |
| Fail-closed detector/parse/binary | VERIFIED | `gateway/pipeline.py` | Security suite | Response detector fails after forward | "Fail-closed for defined gateway failure classes" | 2026-09-18 | Engineering | — |
| OpenAI / Azure / Anthropic paths | VERIFIED | `gateway/providers.py` | `tests/test_gateway_e2e.py` | Three providers only | "Supports OpenAI, Azure OpenAI, Anthropic" | 2026-09-18 | Engineering | — |
| V2 signed gateway receipts | VERIFIED | `gateway/evidence.py` | `tests/v2/test_verifier.py` | SQLite mutable storage | "Cryptographically verifiable, tamper-evident receipts" | 2026-09-18 | Engineering | — |
| Receipt hash chaining | VERIFIED | `gateway/evidence.py` | `tests/test_cryptographic_evidence_lifecycle.py` | Local DB only | "Hash-chained enforcement receipts" | 2026-09-18 | Engineering | — |
| Persistent production signing key | VERIFIED | `gateway/evidence.py` | `tests/test_gateway_failures.py` | Keystore required in production | "Persistent signing identity in production" | 2026-09-18 | Engineering | — |
| Upstream failure handling | VERIFIED | `gateway/pipeline.py` | `tests/test_gateway_failures.py` | forwarded=true on transport failure | "Controlled upstream error responses" | 2026-09-18 | Engineering | — |
| Receipt persistence failure semantics | VERIFIED | `gateway/evidence.py` | `tests/test_gateway_failures.py` | May occur after upstream forward | "Evidence persistence failures return 503" | 2026-09-18 | Engineering | — |
| Gateway evidence export (EvidenceEvent) | VERIFIED | `gateway/evidence_export/` | `tests/test_gateway_evidence_export.py` | Metadata-only; best-effort post-decision | "Structured enforcement evidence exportable to downstream systems" | 2026-09-18 | Engineering | — |
| Gateway Drata CCT export | PARTIALLY VERIFIED | `gateway/evidence_export/exporters.py` | `tests/test_gateway_evidence_export.py` | Drata v2 `{"data":{...}}` contract mock only; live Drata tenant not verified in CI | "Can export gateway evidence to Drata CCT when configured" | 2026-09-18 | Engineering | Live Drata validation |
| Gateway webhook export | VERIFIED | `gateway/evidence_export/exporters.py` | `tests/test_gateway_evidence_export.py` | Requires HERMES_WEBHOOK_URL | "Generic JSON webhook export for gateway evidence" | 2026-09-18 | Engineering | — |
| Streaming enforcement | NOT IMPLEMENTED | — | — | Not inspected live | Do not claim | 2026-09-18 | Engineering | Streaming parser |
| Universal AI provider proxy | NOT IMPLEMENTED | — | — | 3 providers | Do not claim | 2026-09-18 | Engineering | Provider registry |
| External receipt anchoring | NOT IMPLEMENTED | `hermes/receipts/v2/anchoring.py` stubs | — | Mock only | Do not claim immutable external log | 2026-09-18 | Engineering | TSA/WORM integration |
