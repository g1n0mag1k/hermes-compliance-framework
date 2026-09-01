# Hermes — PHI Compliance Infrastructure

**Deterministic, zero-egress PHI/PII/PCI scrubbing  
with cryptographic compliance evidence records.**

Built for MSPs serving HIPAA-covered entities.

hermesrelay.dev

---

## The Problem

When OCR investigates a business associate, they do not ask whether you had a scrubbing tool. They ask you to produce the evidence — exactly what was found, under which regulation, by which method, in an unbroken chain from scan to audit.

Cloud-based competitors detect PHI. None of them can prove what they did with it. Their ML models are black boxes. Their architecture makes honest attestation impossible.

---

## What Hermes Produces

Every scan generates a **Compliance Evidence Record** — a structured audit artifact with hash-chained compliance receipts that documents:

- Which **PHI identifiers** were found, across **13 of 18** HIPAA Safe Harbor categories covered today
- Which detection method fired for each hit (spaCy NER / Presidio / regex / Luhn checksum)
- What action was taken (redaction to typed placeholders)
- The cryptographic link between compliance receipts via HMAC-SHA256 attestation chain
- Per-flag CFR citations in the audit log (`45 CFR §164.514(b)(2)(i)` letter per detection type)
- Per-detector tri-state execution status (`ran_clean` / `ran_error` / `not_run`) — a silently failed detector is never indistinguishable from a clean scan

This record is what your OCR investigator reads. No other tool in this category produces it at the zero-egress layer.

---

## Architecture

**Zero-egress.** Hermes runs entirely inside the customer environment. PHI never transits external infrastructure — making compliance attestations technically accurate, not aspirational.

**Deterministic.** Rule-based hybrid engine: spaCy NER + Presidio + regex + Luhn checksum. Every classification decision is explainable to the token level. No ML black box. No confidence score an auditor cannot verify.

**Hash-chained.** Every `/v1/scrub` call and every `/v1/review` human review event issues a compliance receipt cryptographically linked to the prior receipt via HMAC-SHA256. The chain is persisted in SQLite and independently verifiable — no Hermes dependency required to prove integrity.

**Reversible (roadmap).** A token vault module exists (AES-256-GCM) for typed placeholders with key-controlled restoration. Integration with the scrub pipeline is in active development — current redactions use static placeholders (`[REDACTED_SSN]`, `[REDACTED_PAN]`, etc.).

**Single-tenant today.** One deployment per customer environment. Multi-tenant RBAC and per-tenant audit isolation are on the roadmap.

---

## Compliance Coverage

Hermes covers **13 of 18** HIPAA Safe Harbor identifier categories today.  
Detection is not exhaustive — partial coverage is intentional and documented in every attestation receipt via `declared_scope` and `evidence_incomplete_categories` fields.

**Active today — 13 of 18 Safe Harbor categories**

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
| 45 CFR §164.514(b)(2)(i)(L) | Vehicle identifiers / VINs | regex |
| 45 CFR §164.514(b)(2)(i)(N) | Web URLs | Presidio |
| 45 CFR §164.514(b)(2)(i)(O) | IP addresses | Presidio |
| — | PCI payment card numbers | regex + Luhn checksum (not a Safe Harbor category) |

**Not yet covered — 5 of 18 Safe Harbor categories**

| CFR Citation | Category |
|---|---|
| 45 CFR §164.514(b)(2)(i)(K) | Certificate / license numbers |
| 45 CFR §164.514(b)(2)(i)(M) | Device identifiers / serial numbers |
| 45 CFR §164.514(b)(2)(i)(P) | Biometric identifiers |
| 45 CFR §164.514(b)(2)(i)(Q) | Full face photographs |
| 45 CFR §164.514(b)(2)(i)(R) | Other unique identifiers |

Every attestation receipt embeds `declared_scope` (the 13 covered CFR citations) and `evidence_incomplete_categories` (the 5 not covered) so the boundary of evidence is machine-readable. "Scanned and found nothing" and "never in scope" are always distinguishable.

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

**BA Technical Safeguard Verification Report (BAVR)**  
Annual written verification of technical safeguards for covered entity clients. Satisfies the proposed 2026 HIPAA Security Rule BA verification mandate. Only producible by a zero-egress architecture — cloud-ML vendors cannot make this attestation honestly.

**Cyber Insurance Underwriting Attestation Package (CUAP)**  
Machine-generated evidence mapped to Coalition, At-Bay, and Travelers underwriting control categories. Prevents policy rescission on PHI-handling attestations.

---

## Tech Stack

- Python 3.12 / FastAPI / uvicorn
- spaCy `en_core_web_sm` NER (local — no external API calls)
- Microsoft Presidio AnalyzerEngine (local)
- HMAC-SHA256 attestation chain — SQLite persistence
- AES-256-GCM token vault (vault.py — roadmap integration)
- ReportLab PDF evidence report generation
- Zero-trust LLM proxy (OpenAI, Anthropic, Ollama)
- Generic JSON webhook dispatcher (Splunk HEC, SIEM, DLP)
- Docker / GHCR
- Render (API + Streamlit demo) / Netlify (landing page)

---

## Deployment

Hermes is designed for on-premise or private cloud deployment inside the customer environment.

**The sensitive workload never runs on Sui-Generis LLC infrastructure.**

For deployment documentation and pilot program inquiries:  
andrew@hermesrelay.dev  
hermesrelay.dev

---

## Legal

Built and maintained by Sui-Generis LLC  
Rocky Top, Tennessee  
UEI: YK4VNG1STBA1

This software is intended for deployment by qualified MSPs serving HIPAA-covered entities. A Business Associate Agreement is required prior to production deployment.
