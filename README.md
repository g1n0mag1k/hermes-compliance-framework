# Hermes — PHI Compliance Infrastructure

**Deterministic, zero-egress PHI/PII detection with cryptographically verifiable compliance evidence.**

Hermes Relay is a runtime AI gateway that inspects AI requests for PHI before they reach supported AI providers (OpenAI, Azure OpenAI, Anthropic), applies deterministic **redaction or blocking** policies, and generates cryptographically verifiable enforcement receipts.

Built for HIPAA-covered entities, their business associates, and the MSPs that serve them.

hermesrelay.dev

---

## Claims & Limits

**Coverage.** The classifier detects 16 of 18 HIPAA Safe Harbor identifier
categories in text. Biometric identifiers (P) and full-face photographs (Q)
are reference-only: filenames and references are flagged, but binary content
is not analyzed.

**Sink scope.** The `/v1/scrub` response path makes no outbound network calls.
Webhooks and Drata CCT dispatch run as background tasks **after** the response.
The `/api/v1/sentry/config` endpoint stores DSN configuration but does not
currently probe Sentry — treat it as reserved for a future release.
`canary-action` validates canaries against a local scrub probe shaped like
Sentry events; it does not transmit to Sentry.

**Signing per receipt type.**
- `/v1/scrub` V1 receipts: HMAC-SHA256 (shared signing key)
- Gateway V2 enforcement receipts: Ed25519 / COSE_Sign1 (public-key verifiable)
- `/v1/telemetry/receipt`: HMAC-SHA256
- Canary audit JSON: HMAC-SHA256
- PDF report: unsigned; displays the embedded `receipt_hash`

**Time source.** All receipts use the host or CI runner clock
(`datetime.now(UTC)`). RFC 3161 timestamp authority support exists in
`hermes/receipts/v2/anchoring.py` but is not wired to the per-request
receipt issue path on `main`.

**What `zero_pii_egress_confirmed` means.** `true` when all triggered
detector flags were redacted and no occurrence gaps remain in `clean_text`
within the declared scope. It is a redaction-parity check — not a live
egress observation of Sentry, webhooks, stdout, or any other sink.

---

## The Problem

When OCR investigates a business associate, they do not ask whether you had a scrubbing tool. They ask you to produce the evidence — exactly what was found, under which regulation, by which method, in an unbroken chain from scan to audit.

Cloud-based competitors detect PHI. None of them can prove what they did with it. Their ML models are black boxes. Their architecture makes honest attestation impossible.

---

## What Hermes Produces

Every scan generates a **Compliance Evidence Record** — a structured audit artifact with hash-chained compliance receipts that documents:

- Which **PHI identifiers** were found, across **16 of 18** HIPAA Safe Harbor categories covered today
- Which detection method fired for each hit (spaCy NER / Presidio / regex / Luhn checksum)
- What action was taken (redaction to typed placeholders)
- The cryptographic link between compliance receipts via HMAC-SHA256 attestation chain
- Per-flag CFR citations in the audit log (`45 CFR §164.514(b)(2)(i)` letter per detection type)
- Per-detector tri-state execution status (`ran_clean` / `ran_error` / `not_run`) — a silently failed detector is never indistinguishable from a clean scan

This record is what your OCR investigator reads.

---

## Architecture

**Zero-egress.** Hermes runs entirely inside the customer environment. PHI is not stored or retained. The scrubbing pipeline runs locally; post-policy payloads may be forwarded to configured downstream providers after redaction.

**Deterministic.** Rule-based hybrid engine: spaCy NER + Presidio + regex + Luhn checksum. Every classification decision is explainable to the token level. No ML black box. No confidence score an auditor cannot verify.

**Hash-chained.** Every `/v1/scrub` call, `/v1/review` event, and gateway enforcement decision issues a compliance receipt cryptographically linked to prior receipts. V1 scrub receipts use HMAC-SHA256; gateway receipts use V2 COSE_Sign1 signatures. Chains persist in SQLite and are independently verifiable.

**Gateway enforcement.** Traffic routed through the Hermes Gateway (`:8788`) is inspected before forward. Default dev policy (`HIPAA_STRICT`) **redacts** detected PHI; production design-partner profile (`HIPAA_PRODUCTION_BLOCK`) **blocks** detected PHI with zero upstream bytes on BLOCK decisions.

**Reversible (roadmap).** A token vault module exists (AES-256-GCM) for typed placeholders with key-controlled restoration. Integration with the scrub pipeline is in active development — current redactions use static placeholders (`[REDACTED_SSN]`, `[REDACTED_PAN]`, etc.).

**Multi-tenant.** One deployment serves a parent organization and its child workspaces — an MSP and its clients, a health system and its facilities, a vendor and its customers — as isolated workspaces: each has its own API key, its own attestation chain signed with its own derived key, its own vault key, its own gateway policy and its own AI provider credentials (encrypted at rest). Role-based access (`org_admin`, `operator`, `viewer`) and a parent→child management boundary are enforced on every endpoint. Gateway V2 receipts still share one deployment signing key and Drata export is still global — see [docs/MULTI_TENANCY.md](docs/MULTI_TENANCY.md) for exactly what is and is not isolated.

---

## Compliance Coverage

Hermes covers **16 of 18** HIPAA Safe Harbor identifier categories today.  
Detection is not exhaustive — partial coverage is intentional and documented in every attestation receipt via `declared_scope` and `evidence_incomplete_categories` fields.

**Active today — 16 of 18 Safe Harbor categories**

| CFR Citation | Category | Detection Method |
|---|---|---|
| 45 CFR §164.514(b)(2)(i)(A) | Names | spaCy NER |
| 45 CFR §164.514(b)(2)(i)(B) | Geographic subdivisions | Presidio |
| 45 CFR §164.514(b)(2)(i)(C) | Dates | spaCy NER |
| 45 CFR §164.514(b)(2)(i)(D) | Telephone numbers | Presidio |
| 45 CFR §164.514(b)(2)(i)(E) | Fax numbers | regex |
| 45 CFR §164.514(b)(2)(i)(F) | Email addresses | Presidio |
| 45 CFR §164.514(b)(2)(i)(G) | Social security numbers | regex |
| 45 CFR §164.514(b)(2)(i)(H) | Medical record numbers | regex |
| 45 CFR §164.514(b)(2)(i)(I) | Health plan beneficiary numbers | regex |
| 45 CFR §164.514(b)(2)(i)(J) | Account numbers | regex |
| 45 CFR §164.514(b)(2)(i)(K) | Certificate/license numbers | regex+checksum |
| 45 CFR §164.514(b)(2)(i)(L) | Vehicle identifiers/VINs | regex |
| 45 CFR §164.514(b)(2)(i)(M) | Device identifiers | regex+checksum |
| 45 CFR §164.514(b)(2)(i)(N) | Web URLs | Presidio |
| 45 CFR §164.514(b)(2)(i)(O) | IP addresses | Presidio |
| 45 CFR §164.514(b)(2)(i)(R) | Other unique identifiers | regex |
| — | PCI payment card numbers | regex + Luhn checksum (not a Safe Harbor category) |

**Reference only — 2 of 18 Safe Harbor categories**

| CFR Citation | Category |
|---|---|
| 45 CFR §164.514(b)(2)(i)(P) | Biometric identifiers |
| 45 CFR §164.514(b)(2)(i)(Q) | Full face photographs |

Text references to these categories are detected (`reference_only`). Binary content (actual biometric files, image files) cannot be inspected by a text pipeline.

Every attestation receipt embeds `declared_scope` (the 16 covered CFR citations) and `evidence_incomplete_categories` (the 2 reference-only categories) so the boundary of evidence is machine-readable. "Scanned and found nothing" and "never in scope" are always distinguishable.

**Additional detections (not Safe Harbor categories)**
- GPS coordinates / latitude-longitude (regex)
- Ages over 89 (regex — Safe Harbor requires aggregation of ages 90+)
- Base64-encoded PHI (decode-and-rescan pass)
- PHI embedded in URL paths (path expansion pass)
- Organization names (spaCy NER ORG)

---

## Key Artifacts

**Compliance Evidence Record (CER)**  
Per-scan evidence artifact. Contains classification flags, per-flag occurrence counts, CFR citations, detection method per category, `zero_pii_egress_confirmed` status, HMAC-SHA256 receipt hash, chain position, and the declared scope boundary. Structured for OCR audit response and legal review.

**Human Review Receipt**  
When a scan result is reviewed by a person, a `HumanReviewReceipt` is issued and chained into the same attestation chain as the original scan — tamper-evident proof that a control was looked at by a human, not just that the automated scan ran. Supports `accepted`, `overridden`, and `escalated` decisions.

**BA Technical Safeguard Verification Report (BAVR)** *(documentation concept — not a shipped automated generator)*  
Annual written verification of technical safeguards for covered entity clients. Designed to support annual BA verification workflows under proposed 2026 HIPAA Security Rule updates. Only producible by a zero-egress architecture — cloud-ML vendors cannot make this attestation honestly.

**Cyber Insurance Underwriting Attestation Package (CUAP)** *(documentation concept — not a shipped automated generator)*  
Machine-generated evidence mapped to Coalition, At-Bay, and Travelers underwriting control categories. Provides tamper-evident evidence records supporting PHI-handling attestation reviews.

---

## Tech Stack

- Python 3.12 / FastAPI / uvicorn
- spaCy `en_core_web_sm` NER (local — no external API calls)
- Microsoft Presidio AnalyzerEngine (local)
- HMAC-SHA256 attestation chain — SQLite persistence
- AES-256-GCM token vault (vault.py — roadmap integration)
- ReportLab PDF evidence report generation
- AI enforcement gateway (OpenAI, Azure OpenAI, Anthropic)
- Legacy scrub proxy paths (OpenAI, Anthropic, Ollama — separate from gateway)
- Generic JSON webhook dispatcher (compatible with any HTTP JSON webhook receiver; native Splunk HEC event formatting not currently implemented)
- Docker Compose (image built locally from this repository)
- Render (API + Streamlit demo) / Netlify (landing page)

---

## CLI entry points

Two commands are installed by `pip install -e .` (or `make install-dev`):

| Command | Entry point | Purpose |
|---------|------------|---------|
| `hermes-relay` | `hermes.cli:main` | Start the Hermes API, run canary checks, manage workspaces |
| `hermes-verify` | `hermes.receipts.v2.cli:main` | Verify a V2 signed receipt off-line |

```bash
# Start the API server
hermes-relay serve

# Verify a V2 receipt
hermes-verify path/to/receipt.cose --public-key public.pem

# Run a one-shot canary check
hermes-relay canary
```

See `AGENTS.md` and `docs/DEPLOYMENT.md` for full CLI reference and environment variables.

---

## Deployment

Hermes is designed for on-premise or private cloud deployment inside the customer environment.

**The sensitive workload never runs on Sui-Generis infrastructure.**

Supported install: Docker Compose, built from this repository. Follow
[`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md).

For pilot program inquiries:

andrew@hermesrelay.dev  
hermesrelay.dev

---

## Legal

Built and maintained by Sui-Generis  
Rocky Top, Tennessee  

This software is intended for deployment by HIPAA-covered entities, business associates, or qualified IT providers acting on their behalf. A Business Associate Agreement is required prior to production deployment.
