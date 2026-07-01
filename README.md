# Hermes — PHI Compliance Infrastructure

**Deterministic, zero-egress PHI/PII/PCI scrubbing 
with cryptographic compliance evidence records.**

Built for MSPs serving HIPAA-covered entities.

hermesrelay.dev

---

## The Problem

When OCR investigates a business associate, they do 
not ask whether you had a scrubbing tool. They ask 
you to produce the evidence — exactly what was found, 
under which regulation, by which method, in an 
unbroken chain from scan to audit.

Cloud-based competitors detect PHI. None of them 
can prove what they did with it. Their ML models 
are black boxes. Their architecture makes honest 
attestation impossible.

---

## What Hermes Produces

Every scan generates a **Compliance Evidence Record** — 
a structured audit artifact with hash-chained compliance 
receipts in LLM proxy mode (expanding to all endpoints) 
that documents:

- Which **core PHI identifiers** were found today: SSN 
  (regex), payment card numbers (regex + Luhn), and 
  PERSON / DATE / ORG entities (spaCy `en_core_web_sm` NER)
- Safe Harbor coverage across all 18 HIPAA identifier 
  categories is **actively expanding** — not complete
- Which detection method fired 
  (spaCy NER / regex / Luhn checksum)
- What action was taken 
  (redaction to typed placeholders)
- The cryptographic link between compliance receipts 
  in the attestation chain (proxy mode today)

Per-token CFR citations are on the roadmap. The audit 
log records classification flags and counts today.

This record is what your OCR investigator reads. 
No other tool in this category produces it at 
the zero-egress layer.

---

## Architecture

**Zero-egress.** Hermes runs entirely inside the 
customer environment. PHI never transits external 
infrastructure — making compliance attestations 
technically accurate, not aspirational.

**Deterministic.** Rule-based hybrid engine: 
spaCy NER + regex + Luhn checksum. Every 
classification decision is explainable to the 
token level. No ML black box. No confidence 
score an auditor cannot verify.

**Hash-chained.** Compliance receipts issued in LLM 
proxy mode are cryptographically linked to the previous 
receipt via HMAC-SHA256. The chain is independently 
verifiable — no Hermes dependency required to prove 
integrity. `/v1/scrub` returns structured audit flags 
today; full hash-chaining is expanding to all endpoints.

**Reversible (roadmap).** A token vault module exists 
for typed placeholders with key-controlled restoration. 
Integration with the scrub pipeline is in active 
development — current redactions use static placeholders 
(`[REDACTED_SSN]`, `[REDACTED_PAN]`, etc.).

**Single-tenant today.** One deployment per customer 
environment. Multi-tenant RBAC and per-tenant audit 
isolation are on the roadmap.

---

## Compliance Coverage

**Active today**
- SSN detection (regex) and PCI PAN detection 
  (regex + Luhn checksum)
- PERSON, DATE, and ORG entity redaction via 
  spaCy `en_core_web_sm` NER
- Zero-egress local execution (HIPAA Security Rule 
  technical safeguard alignment)

**Safe Harbor-aligned — building toward full coverage**
- HIPAA Safe Harbor de-identification 
  45 CFR §164.514(b) — core identifiers today; 
  remaining Safe Harbor categories in active development
- HIPAA Security Rule technical safeguards 
  45 CFR §164.312
- PCI DSS — Luhn-validated card number detection

**Roadmap**
- Full 18-category Safe Harbor identifier coverage
- Per-token CFR citations
- DSCSA pharmaceutical supply chain 
  21 CFR Part 11 / EPCIS 1.2
- ALCOA+ data integrity principles (formal attestation)

---

## Key Artifacts

**Compliance Evidence Record (CER)**
Per-scan evidence artifact with classification flags 
and counts. CFR citations and full Safe Harbor 
category coverage are actively expanding. Structured 
for OCR audit response and legal review.

**BA Technical Safeguard Verification Report (BAVR)**
Annual written verification of technical safeguards 
for covered entity clients. Satisfies the proposed 
2026 HIPAA Security Rule BA verification mandate. 
Only producible by a zero-egress architecture — 
cloud-ML vendors cannot make this attestation 
honestly.

**Cyber Insurance Underwriting Attestation 
Package (CUAP)**
Machine-generated evidence mapped to Coalition, 
At-Bay, and Travelers underwriting control 
categories. Prevents policy rescission on 
PHI-handling attestations.

---

## Tech Stack

- Python 3.12 / FastAPI
- spaCy NER (local, no external API calls)
- SHA-256 / HMAC-SHA256 attestation chain (proxy mode; expanding)
- Docker / GHCR
- Deployed via zero-egress on-premise or 
  private cloud

---

## Deployment

Hermes is designed for on-premise or 
private cloud deployment inside the 
customer environment.

**The sensitive workload never runs on 
Sui-Generis LLC infrastructure.**

For deployment documentation and pilot 
program inquiries:
andrew@hermesrelay.dev
hermesrelay.dev

---

## Legal

Built and maintained by Sui-Generis LLC  
Rocky Top, Tennessee  
UEI: YK4VNG1STBA1

This software is intended for deployment 
by qualified MSPs serving HIPAA-covered 
entities. A Business Associate Agreement 
is required prior to production deployment.
