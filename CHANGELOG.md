# Changelog

All notable changes to Hermes Relay are documented here. Format is loosely based on [Keep a Changelog](https://keepachangelog.com/).

This project is pre-1.0 and under active solo development. Entries prioritize accuracy over polish — including honest notes on what was previously overclaimed and corrected.

## [Unreleased]

### Fixed
- Corrected a double-counting bug in the audit trail: Presidio's `EMAIL_ADDRESS` and `URL` recognizers both fire on email addresses (the URL recognizer matches the domain portion, e.g. `email.com` inside `patient@email.com`). Redaction was already correct (single `[REDACTED_EMAIL]`), but `flags_triggered` incorrectly counted both `HIPAA_PHI_EMAIL` and `HIPAA_PHI_URL` for one identifier. Fixed via `_merge_flag_sets()` — nested `HIPAA_PHI_URL` spans fully contained within a `HIPAA_PHI_EMAIL` span are suppressed from the count. Added regression tests: `test_email_domain_url_not_double_counted`, `test_standalone_url_still_detected`.

### Added
- Integrated Microsoft Presidio (`presidio-analyzer`, `presidio-anonymizer`, MIT licensed) as an additional detection layer alongside existing regex and spaCy NER logic.
- New detection categories via Presidio: phone numbers, email addresses, URLs, IP addresses, US bank account numbers, and geographic locations/addresses.
- `CFR_CITATION_MAP` — maps each detection flag to its specific 45 CFR §164.514(b)(2)(i) Safe Harbor identifier letter. Citations are now attached to every entry in the audit log's `flags_triggered` output, not just implied by category name.
- `_merge_overlapping_spans()` — resolves overlapping detections between spaCy and Presidio so overlapping PHI is redacted exactly once, with all contributing flags preserved (subject to the email/URL suppression fix above).
- `FlagEntry` schema (`{count, cfr_citation}`) replacing the previous plain integer count in `flags_triggered`.
- 9 new tests covering phone, email, URL, IP detection, combined multi-PHI payloads, and span overlap resolution.

### Changed
- **Coverage: 3 of 18 → 8 of 18 HIPAA Safe Harbor identifier categories** now actively detected (names, dates, SSN, phone, email, URL, IP, address). Remaining 10 categories (fax, MRN, health plan beneficiary numbers, account numbers, certificate/license numbers, vehicle identifiers, device identifiers, biometric identifiers, full-face photos) remain on the roadmap and are documented as such.
- `spacy` pinned to `3.8.13` (down from `>=3.8.14`) — required by `presidio-analyzer==2.2.363`'s dependency constraints.
- `hermes/proxy.py` and `tests/test_api.py` updated to consume the new `FlagEntry` schema.

### Corrected — Landing Page & Documentation Accuracy Pass
Prior to this pass, several claims across the landing page, `README.md`, `BENCHMARK.md`, and `INVESTOR_TECH_BRIEF.md` implied more complete Safe Harbor coverage and audit trail completeness than the codebase actually delivered. All of the following were corrected to state actual coverage rather than aspirational coverage:

- **`landing/components/Problem.tsx`** — "proves Safe Harbor compliance was actively maintained" → "documents Safe Harbor-aligned de-identification — with core identifier coverage today and full Safe Harbor coverage actively expanding."
- **`landing/components/CTA.tsx`** — "HIPAA Safe Harbor 45 CFR §164.514(b)" → "Safe Harbor-aligned — building toward 45 CFR §164.514(b)"; "full compliance evidence record output from day one" → "hash-chained audit evidence record from day one."
- **`landing/components/Solution.tsx`** — corrected implied full per-token CFR coverage to accurately describe regex + spaCy + Presidio detecting core identifiers, coverage expanding.
- **`landing/components/Integrations.tsx`** — corrected "PHI is scrubbed locally first... no PHI in transit" (implied complete) to "Core PHI identifiers are scrubbed locally first... per-category coverage expanding."
- **`landing/components/AuditChain.tsx`** — relabeled "Live audit chain output" → "Sample audit chain output"; added explicit "Illustrative output — not live product data" disclaimer; removed an undetected `PHONE_NUMBER` block from the sample chain (phone detection did not exist yet at the time of this specific fix, later added same session); corrected "Every PHI decision... every CFR citation" headline to "Every scrubbing decision. Hash-chained. Audit-ready."
- **`landing/components/Hero.tsx`** — added "Illustrative output — sample audit stream" label above the ticker; corrected "Chain integrity verified" to "Illustrative chain — tamper-evident format shown for demo purposes."
- **Fabricated legal citation removed:** `landing/components/Problem.tsx` previously cited a non-existent court case ("Travelers v. ICS"). Removed and replaced with verified OCR enforcement data (7 resolution agreements against business associates in 2025 — the highest total since 2013, per BakerHostetler's 2025 annual enforcement report).
- **`README.md`** — "Which of the 18 HIPAA Safe Harbor identifiers was found" (implied complete) → explicit statement of active-today categories vs. roadmap categories. Reversible redaction, multi-tenant isolation, and SHA-256 hash-chaining on every scrub were reclassified from "shipped" to "roadmap" / "proxy mode only" to match actual implementation state.
- **`BENCHMARK.md`** — removed unqualified "100%" detection accuracy claims; added explicit scope note that benchmark figures reflect a 17-case SSN/PAN-only synthetic corpus, not a validated production benchmark. Reversible redaction and hash-chain capabilities marked as roadmap / proxy-mode-only rather than shipped.
- **`INVESTOR_TECH_BRIEF.md`** — corrected architecture diagram and data-flow description (SHA-256 chain is HMAC-based and proxy-mode-only today, not "every scrub"); corrected HIPAA identifier coverage table to list actual active categories vs. explicit not-yet-detected list; added limitations rows for the unwired reversible vault and proxy-only hash chain.

### Verified (independent audit, not self-reported)
- Full backend audit conducted via Cursor agent + manual verification: confirmed via direct code read, live probes, and test execution which claims were `BUILT AND VERIFIED`, `PARTIALLY BUILT`, or `NOT BUILT` as of 2026-07-01, prior to the Presidio integration above.
- Regulatory research independently verified via Perplexity Deep Research against primary sources (45 CFR §164.514(b)(2)(i), OCR guidance, peer-reviewed de-identification tool evaluations) — confirmed that partial Safe Harbor coverage does not meet the Safe Harbor de-identification standard, and that no automated system can honestly claim 100% detection. This finding directly informed the corrections above and the phased Presidio integration approach.

## Known Issues / Not Yet Implemented (as of this release)
- `hermes/auditor.py` and `hermes/agent.py` are placeholder files — no logic implemented.
- CER (Compliance Evidence Record), BAVR (Business Associate Technical Safeguard Verification Report), and CUAP (Cyber Insurance Underwriting Attestation Package) are named/designed artifacts with no generator implementation yet.
- Hash-chained attestation (`AttestationChain` in `hermes/attestation.py`) is only wired into `hermes/proxy.py` (LLM proxy mode). The primary `/v1/scrub` endpoint returns per-request audit flags but does not yet write into the hash chain.
- Reversible redaction vault (`hermes/vault.py`) is implemented but not called from the active scrub pipeline.
- No multi-tenant isolation — single shared `HERMES_API_KEY` per deployment.
- `HERMES_SIGNING_KEY` and `HERMES_VAULT_KEY` fall back to hardcoded development values if not set — must be explicitly configured before any pilot/production deployment (see `SECURITY.md`).
- 10 of 18 HIPAA Safe Harbor identifier categories remain undetected: fax numbers, medical record numbers, health plan beneficiary numbers, account numbers, certificate/license numbers, vehicle identifiers, device identifiers, biometric identifiers, full-face photographs, and geographic subdivisions below the address level in some cases.

---

## Earlier Milestones (undated / pre-changelog)

- Initial `hermes/classifier.py` implementation: SSN detection (regex), PCI PAN detection (regex + Luhn checksum validation), PERSON/DATE/ORG entity detection via spaCy `en_core_web_sm`.
- `hermes/attestation.py`: HMAC-SHA256 signed `ComplianceReceipt` chain with previous-receipt-hash linking and chain verification.
- `hermes/vault.py`: XOR-encrypted reversible redaction token vault with per-transaction purge.
- `hermes/api.py`: FastAPI app with `/health` and `/v1/scrub` endpoints, API key authentication.
- `hermes/proxy.py`: Zero-trust LLM proxy supporting OpenAI, Anthropic, Ollama, and custom targets — deep-scrubs JSON payloads before forwarding upstream.
- Landing page (Next.js 15 / Tailwind CSS v4) built and deployed to hermesrelay.dev, including Hero, Problem, Solution, AuditChain, Architecture, Differentiators, Integrations, and Pilot CTA sections.
- Docker deployment: multi-stage build, non-root user, spaCy model baked into image at build time, health check configured.
