# Hermes Relay — Evidence Scope Boundary

**Version:** 1.0
**CFR Reference:** 45 CFR §164.514(b)(2)(i)
**Last Updated:** 2026-08-18

---

## What This Document Is

Every Hermes attestation receipt includes two fields that make the boundary
of evidence explicit:

- `declared_scope` — CFR citations for every category Hermes actively checks
- `evidence_incomplete_categories` — CFR citations for categories not yet covered

This document explains what those fields mean, what Hermes does and does not
claim, and how to interpret a receipt correctly.

---

## The Core Distinction

A clean attestation receipt means one of two things:

1. **Scanned and found nothing** — the category is in scope, Hermes checked,
   no matching identifiers were detected in this payload.

2. **Never in scope** — the category is listed in `evidence_incomplete_categories`.
   Hermes did not check for it. Absence of a flag is not evidence of absence.

These two states are not equivalent. `evidence_incomplete_categories` exists
precisely to make this distinction machine-readable and auditor-verifiable.

---

## Coverage Table

| CFR | Category | Status | Method |
|-----|----------|--------|--------|
| §164.514(b)(2)(i)(A) | Names | Covered | spaCy NER |
| §164.514(b)(2)(i)(B) | Geographic subdivisions | Covered | Presidio |
| §164.514(b)(2)(i)(C) | Dates | Covered | spaCy NER |
| §164.514(b)(2)(i)(D) | Telephone numbers | Covered | Presidio |
| §164.514(b)(2)(i)(E) | Fax numbers | Covered | Regex |
| §164.514(b)(2)(i)(F) | Email addresses | Covered | Presidio |
| §164.514(b)(2)(i)(G) | Social security numbers | Covered | Regex |
| §164.514(b)(2)(i)(H) | Medical record numbers | Covered | Regex |
| §164.514(b)(2)(i)(I) | Health plan beneficiary numbers | Covered | Regex |
| §164.514(b)(2)(i)(J) | Account numbers | Covered | Regex |
| §164.514(b)(2)(i)(K) | Certificate/license numbers | Not covered | Too variable by issuing authority |
| §164.514(b)(2)(i)(L) | Vehicle identifiers/VINs | Covered | Regex |
| §164.514(b)(2)(i)(M) | Device identifiers/serial numbers | Not covered | Too broad without manufacturer context |
| §164.514(b)(2)(i)(N) | Web URLs | Covered | Presidio |
| §164.514(b)(2)(i)(O) | IP addresses | Covered | Presidio |
| §164.514(b)(2)(i)(P) | Biometric identifiers | Not covered | Not a text/regex problem |
| §164.514(b)(2)(i)(Q) | Full face photographs | Not covered | Not a text/regex problem |
| §164.514(b)(2)(i)(R) | Other unique identifiers | Not covered | Catch-all requiring human judgment |

**Coverage: 13 of 18 Safe Harbor identifier categories.**

---

## What Hermes Does Not Claim

- Hermes does NOT claim certified HIPAA Safe Harbor de-identification.
- Hermes does NOT claim propagation closure -- it does not prove that all
  possible PHI egress paths are mechanically blocked.
- Hermes does NOT claim perfect recall within covered categories.

## What Hermes Does Claim

- Every payload is scanned against all 13 covered categories on every call.
- Every redaction decision is recorded in a CFR-cited, SHA-256 hash-chained,
  cryptographically signed attestation receipt.
- The receipt is tamper-evident -- verify_chain() checks signature integrity,
  previous-hash links, and sequential chain positions.
- declared_scope and evidence_incomplete_categories are included in the
  signed receipt content, so the boundary of evidence is itself tamper-evident.

---

## Recommended Use

Treat Hermes as a strong, auditable first layer for PHI reduction in AI
pipelines. For complete Safe Harbor de-identification, combine Hermes with:

- Human review of high-stakes payloads
- Domain-specific controls for uncovered categories (K, M, P, Q, R)
- Your own risk assessment per 45 CFR 164.514(b)(1) expert determination

---

This document is maintained alongside hermes/classifier.py. When coverage
changes, both DECLARED_SCOPE in the classifier and this document must be
updated together.
