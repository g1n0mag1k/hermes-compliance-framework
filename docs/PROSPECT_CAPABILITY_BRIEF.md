# Hermes Relay — Prospect Capability Brief

**Audience:** MSP, MSSP, healthcare AI vendor, AI governance consultant, healthcare technology company  
**Status:** Controlled design-partner ready (2026-09-18)  
**Contact:** andrew@hermesrelay.dev · hermesrelay.dev

---

## 1. Problem

Healthcare organizations route employee and application prompts to cloud AI providers (OpenAI, Azure OpenAI, Anthropic). When PHI appears in those prompts, it can leave the covered entity's control with no cryptographic proof of what was sent, blocked, or redacted. Traditional DLP often inspects after egress. Auditors ask: *prove PHI never reached the provider for this request.*

---

## 2. What Hermes does

Hermes Relay is a **runtime AI gateway** for traffic routed through Hermes. It performs **pre-transmission PHI inspection**, applies a configurable **redaction or blocking** policy, and issues **cryptographically verifiable gateway receipts** with **metadata-only compliance evidence**.

Hermes does **not** claim HIPAA compliance, universal PHI blocking, or protection against gateway bypass.

---

## 3. Architecture

```
Application (customer network)
    → Hermes Gateway (:8788)
        → recursive JSON/text inspection
        → policy decision (ALLOW / REDACT / BLOCK)
        → optional upstream forward
        → V2 COSE/Ed25519 receipt (SQLite, per workspace)
        → optional metadata-only export (webhook / Drata CCT)
    → OpenAI | Azure OpenAI | Anthropic
```

Legacy path: Hermes Relay API (`:8787`) `/v1/scrub` for batch scrubbing — separate from inline gateway enforcement.

All PHI detection runs locally (spaCy, Presidio, regex). No PHI is sent to Hermes infrastructure for classification.

---

## 4. Supported providers

| Provider | Gateway path prefix |
|---|---|
| OpenAI | `/gateway/openai/...` |
| Azure OpenAI | `/gateway/azure_openai/...` |
| Anthropic | `/gateway/anthropic/...` |

No generic AI proxy. Direct provider calls bypass Hermes by design.

---

## 5. PHI detection scope

- **16 of 18** HIPAA Safe Harbor identifier categories in documented **text** scope
- Categories P (biometric) and Q (full-face photos): **reference_only** for binary artifacts
- English-language NER (`en_core_web_sm`)
- Recursive inspection: messages, nested JSON, tool arguments, query parameters, URL paths

Hermes does **not** claim complete Safe Harbor de-identification or "detects all PHI."

---

## 6. BLOCK vs REDACT behavior

| Policy | PHI detected | Upstream |
|---|---|---|
| `HIPAA_STRICT` (default dev) | REDACT → typed placeholders | Sanitized body forwarded |
| `HIPAA_PRODUCTION_BLOCK` | BLOCK → HTTP 403 | **Zero upstream HTTP requests** |
| Detector / parse / binary failure | BLOCK (fail-closed) | **Zero upstream HTTP requests** |

**Security invariant (tested):** If decision == BLOCK (pre-forward), `upstream.request_count == 0` and receipt `forwarded == false`.

---

## 7. Cryptographic receipts

Each gateway decision produces a **V2 COSE_Sign1** receipt:

- Ed25519 signature (persistent keystore required in production)
- Hash-chained per workspace (`prev_receipt_digest`)
- Metadata only: decision, policy digest, PHI **category names** (not values), `forwarded` flag

Independent verification: `hermes-verify receipt <file.cose> --public-key gateway-public.pem`

---

## 8. Security invariants

| Invariant | Verified by |
|---|---|
| BLOCK → no upstream contact | `tests/security/test_phi_never_egresses.py` (18 tests) |
| Export failure → enforcement unchanged | `tests/test_gateway_evidence_export.py` |
| EvidenceEvent → no raw bodies / PHI values | Schema + serialization guards |
| Production → persistent signing keystore | `tests/test_gateway_failures.py` |
| Fail-closed on detector/parse/binary/policy errors | Gateway pipeline + security suite |

Export runs **after** enforcement decision. Exporter outage cannot turn BLOCK into ALLOW.

---

## 9. Deployment model

**Controlled design-partner profile:**

```bash
HERMES_ENV=production
HERMES_GATEWAY_POLICY=HIPAA_PRODUCTION_BLOCK
HERMES_GATEWAY_KEYSTORE_PATH=/secure/gateway.keystore
HERMES_GATEWAY_KEYSTORE_PASSPHRASE=<strong-passphrase>
# Provider credentials: HERMES_OPENAI_API_KEY, etc.
```

Route application SDK base URL to `http://<hermes-host>:8788/gateway/<provider>/...`

See `docs/DESIGN_PARTNER_DEPLOYMENT.md` for topology, rollback, and monitoring.

---

## 10. Current limitations

- **Routing requirement:** Only traffic through Hermes is protected
- **No streaming/SSE** field-by-field enforcement
- **Binary/multimodal** content blocked, not parsed
- **SQLite** receipt storage — not WORM/immutable
- **No external anchoring** (TSA/SCITT) connected
- **Three providers only**
- **Drata:** adapter implemented and contract-tested; **live tenant validation pending**
- **Upstream transport failures** after forward: receipt shows `forwarded=true`; Hermes cannot retroactively guarantee zero bytes transmitted

Full list: `docs/CURRENT_LIMITATIONS.md`

---

## 11. Design-partner engagement scope

**Included in 30-day assurance sprint / 90-day pilot:**

- Personal deployment on one client environment
- Gateway routing for one defined AI workflow (OpenAI, Azure, or Anthropic)
- BLOCK or REDACT policy configuration
- Receipt verification walkthrough
- Optional webhook or Drata CCT export setup (live Drata validated together)

**Explicitly out of scope for this milestone:**

- Live Drata tenant (unless validated during onboarding)
- Streaming enforcement, HA cluster, enterprise billing
- Universal provider support, WORM/TSA, gateway bypass prevention

**Demo:** `.venv/bin/python gateway/demo.py` — four scenarios with visible upstream request counts (synthetic data only).

**Tests:** 532 automated tests; 18 PHI egress security invariant tests (executed 2026-09-18).
