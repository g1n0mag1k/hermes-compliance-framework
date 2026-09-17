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

---

## Known Architectural Limitations

These are gaps that exist beyond the uncovered CFR categories above.
They are documented here so the boundary of evidence is fully explicit.

### 1. Quasi-identifier combinations

Hermes redacts each identifier in isolation. It has no cross-field awareness.
A payload containing 'female patient, born 1962, ZIP 37931' may pass clean
even though that combination re-identifies a large fraction of individuals.
The combination of gender, birth date, and postal code re-identifies between
63-87% of the US population. The receipt cannot represent this risk.
This is an architectural limitation of token-level redaction, not a bug.
Mitigation: treat Hermes as a first layer and apply linkage-scenario analysis
for high-sensitivity payloads.

### 2. NER model not trained on clinical text

Hermes uses spaCy en_core_web_sm — a general English model, not a clinical
NER model. Clinical names, rare diseases, hospital codes, and physician names
in clinical context will have lower recall than a model trained on i2b2/n2c2
de-identification datasets. The upgrade path is scispaCy or a fine-tuned
clinical NER model. This affects categories A (names), C (dates), and B
(geographic subdivisions) in clinical free-text.

### 3. Indirect identifiers not in scope

A de-identified note may satisfy all 18 Safe Harbor categories while still
being uniquely re-identifiable from context — rare diagnoses, unusual
occupations, narrative events, family relationships, or combinations of
quasi-identifiers. Hermes makes no claim about indirect identifiers.
The receipt field zero_pii_egress_confirmed: true means no direct identifiers
in declared scope were detected — not that re-identification is impossible.

### 4. Age over 89 (added in v1.1.0)

Safe Harbor requires ages over 89 be aggregated into a single 90+ category.
REGEX_AGE_OVER_89 handles common English patterns (94 years old, age 91,
92-year-old, aged 90). Unusual formats or non-English age expressions may
not be caught. The regex catches ages 90-199 — values above 120 are
clinically implausible but are redacted to avoid false negatives.

### 5. Profession/occupation quasi-identifiers (Gap 12)

"The only cardiac surgeon in Knoxville" passes clean. Profession combined
with specialty and geography is highly re-identifying for rare specialties
in small markets. Hermes has no occupation/profession detector. This is not
a HIPAA Safe Harbor category but is an indirect identifier that can survive
token-level redaction.

### 6. Family member PHI (Gap 13)

Safe Harbor applies to identifiers of the individual OR relatives, employers,
or household members. spaCy will catch names and addresses of family members
mentioned in text, but narrative references like "patient's daughter is a
nurse at Vanderbilt" pass clean. The family relationship context is not
detected.

### 7. Attestation chain is in-memory only (Gap 14)

ATTESTATION_CHAIN is a module-level singleton. Every API restart wipes it.
verify_chain() always returns True on a fresh start. An auditor asking for
30 days of receipts gets nothing. Chain persistence to disk or a database
is a deployment requirement not yet implemented.

### 8. Non-Western name recall (Gap 15)

spaCy en_core_web_sm is trained predominantly on English news text with
Western names. Names like "Nguyen Van An", "Mohammed Al-Rashid", or
"Priya Krishnamurthy" have significantly lower recall than "John Smith".
For MSPs serving diverse patient populations this is a real coverage gap.
The upgrade path is a multilingual NER model or scispaCy.

### 9. Single-threaded pipeline under concurrent load (Gap 16)

_PIPELINE_LOCK is a single threading lock shared across spaCy and Presidio.
Every scrub request waits for the lock. Under concurrent load this becomes
a throughput bottleneck. Not a PHI gap but a deployment constraint that
should be disclosed to customers expecting high-volume concurrent use.
