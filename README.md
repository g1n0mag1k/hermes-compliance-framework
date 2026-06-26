# Hermes — PHI Compliance Infrastructure

**Deterministic, zero-egress PHI/PII/PCI scrubbing 
with SHA-256 hash-chained compliance evidence records.**

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
a per-token, CFR-cited, SHA-256 hash-chained artifact 
that documents:

- Which of the 18 HIPAA Safe Harbor identifiers 
  was found (45 CFR §164.514(b)(2)(i))
- Which detection method fired 
  (spaCy NER / regex / Luhn checksum)
- What action was taken 
  (reversible redaction / permanent redaction)
- The cryptographic link to every prior record 
  in the audit chain

This record is what your OCR investigator reads. 
No other tool produces it.

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

**Hash-chained.** Every scrubbing event is 
cryptographically linked to the previous one 
via SHA-256. The chain is independently 
verifiable with any SHA-256 implementation — 
no Hermes dependency required to prove integrity.

**Reversible.** Redacted tokens are replaced 
with typed placeholders and restorable via 
key-controlled restoration. PHI can be 
recovered by authorized parties without 
re-processing the original document.

**Multi-tenant.** Auditor isolation per tenant. 
Different audit views per role. MSP and covered 
entity see only what they are authorized to see.

---

## Compliance Coverage

- HIPAA Safe Harbor de-identification 
  45 CFR §164.514(b)
- HIPAA Security Rule technical safeguards 
  45 CFR §164.312
- DSCSA pharmaceutical supply chain 
  21 CFR Part 11 / EPCIS 1.2
- PCI DSS — Luhn-validated card number detection
- ALCOA+ data integrity principles

---

## Key Artifacts

**Compliance Evidence Record (CER)**
Per-scan, per-token, CFR-cited evidence artifact. 
Structured for OCR audit response and legal review.

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
- SHA-256 hash chain (stdlib, no dependencies)
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
