# Changelog

All notable changes to Hermes Relay are documented here. Format is loosely based on [Keep a Changelog](https://keepachangelog.com/).

This project is pre-1.0 and under active solo development. Entries prioritize accuracy over polish — including honest notes on what was previously overclaimed and corrected.

## [Unreleased]

### Added — Multi-tenancy
- Per-workspace HMAC signing keys for V1 attestation chains and per-workspace vault keys, derived from `HERMES_SIGNING_KEY` / `HERMES_VAULT_KEY` (`hermes/tenant_keys.py`). Same value → different vault token per workspace.
- Key-scheme record (`chain_meta` / `vault_meta`) so existing workspace chains and vaults keep their original key and historical receipts keep verifying; new ones use per-workspace keys.
- Per-workspace gateway policy (`GET/PUT/DELETE /v1/workspaces/{id}/policy`), read by the gateway on every request — no restart. Fails closed (503) if the policy store is unreadable.
- Per-workspace AI provider credentials, AES-256-GCM encrypted at rest (`GET/PUT/DELETE /v1/workspaces/{id}/provider-credentials/{provider}`), wired into the gateway pipeline with fallback to the deployment env keys. Azure endpoints restricted to Azure hosts.
- `GET /v1/workspaces/{id}/chain-integrity` for a parent workspace to verify each child chain.
- Optional `role` on `POST /v1/workspaces`.
- Neutral role names `org_admin`, `operator`, `viewer`. The earlier names `msp_admin`, `msp_tech`, `client_readonly` remain accepted everywhere (API, canary router, dashboard) and stored roles are not rewritten. New workspaces default to `org_admin`.
- `docs/MULTI_TENANCY.md`; 59 tests in `tests/test_multi_tenant.py`.

### Changed — Multi-tenancy
- Role checks on core endpoints: `/v1/scrub`, `/v1/review`, `/v1/trial-scan`, `/api/v1/evaluate` require `org_admin` or `operator`; listing workspaces and rotating keys require `org_admin`. `viewer` keeps status and history.
- `require_role` now accepts the legacy `HERMES_API_KEY` (previously it rejected it with 401).
- A client workspace cannot change its own policy or AI credentials; its parent workspace does.

### Fixed — Multi-tenancy
- Workspace IDs with a trailing newline were accepted (`re.match` + `$`); now `fullmatch`. Removed the corresponding strict xfail.
- `POST /v1/workspaces` accepted a `parent_workspace_id` that did not exist, so whoever later registered that ID inherited access. Now rejected, as are grandchildren.
- `default` workspace ID reserved for the legacy single-tenant key.
- Pinned `preshed==3.0.12`: 3.0.14 crashes spaCy 3.8.16 model loading, which broke fresh installs and Docker builds.
- `/v1/telemetry/canary-audit` returned 500 for every registered workspace key (it called `.get()` on a `Workspace` object and only recognised roles `admin`/`auditor`, which the workspace model never issues). It now accepts `org_admin`/`operator` (and legacy names) and rejects `viewer`.
- Buyer-facing copy (README, landing page, API/CLI titles, package metadata, pitch one-pager, deployment and integration docs) no longer frames Hermes as MSP-only: it is described as built for HIPAA-covered entities, their business associates, and the MSPs that serve them.
- `scripts/install_workspaces.py` now refuses to overwrite existing files (it restored an old snapshot of 8 core files and committed with `git add -A`).

### Known Limitations

- **Vanta full-state push** (`dispatch_vanta_custom_resource` in `hermes/webhooks.py`):
  Vanta's PUT endpoint is full-state — it replaces the entire resource set for a
  `resourceId`. The current implementation pushes only the single receipt passed in,
  so every call silently removes all prior receipts from Vanta's view. This is safe
  while no live Vanta customers exist but must be fixed before production use. The
  fix requires the function to accept `receipts: list` and query the full attestation
  chain before every PUT. Will be addressed when a Vanta integration is activated.

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
- `spacy` pinned to `3.8.16`, `presidio-analyzer` pinned to `2.2.364`.
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
- Categories P (Biometric identifiers) and Q (Full face photographs) are `reference_only`: text references to these categories are detected and flagged, but the binary content of actual biometric or image files cannot be inspected by a text pipeline. This is a structural limitation of the text-based architecture, not a gap to be closed by a regex.
- `hermes/vault.py` reversible redaction vault: implemented and wired to `/v1/scrub` via `scrub_payload_reversible()`, but not the default scrub path. The default `/v1/scrub` uses irreversible static placeholders.
- `HERMES_SIGNING_KEY` and `HERMES_VAULT_KEY` fall back to hardcoded development values if not set — must be explicitly configured before any pilot or production deployment (see `SECURITY.md`).
- No multi-tenant RBAC — workspace isolation is implemented but all workspaces share the same deployed instance.
- `HIPAA_PHI_BANK_NUMBER` (detected by Presidio's US_BANK_NUMBER recognizer) appears in receipts but has no entry in `DECLARED_SCOPE` — CFR citation is null in those receipt entries.

---

## Earlier Milestones (undated / pre-changelog)

- Initial `hermes/classifier.py` implementation: SSN detection (regex), PCI PAN detection (regex + Luhn checksum validation), PERSON/DATE/ORG entity detection via spaCy `en_core_web_sm`.
- `hermes/attestation.py`: HMAC-SHA256 signed `ComplianceReceipt` chain with previous-receipt-hash linking and chain verification.
- `hermes/vault.py`: XOR-encrypted reversible redaction token vault with per-transaction purge.
- `hermes/api.py`: FastAPI app with `/health` and `/v1/scrub` endpoints, API key authentication.
- `hermes/proxy.py`: Zero-trust LLM proxy supporting OpenAI, Anthropic, Ollama, and custom targets — deep-scrubs JSON payloads before forwarding upstream.
- Landing page (Next.js 15 / Tailwind CSS v4) built and deployed to hermesrelay.dev, including Hero, Problem, Solution, AuditChain, Architecture, Differentiators, Integrations, and Pilot CTA sections.
- Docker deployment: multi-stage build, non-root user, spaCy model baked into image at build time, health check configured.

## Pre-Call Engineering Fixes — 2026-09-23

1. `render.yaml` — production signing enforced.
2. `docker-compose.yml` + `Caddyfile` — port `8787` aligned.
3. `README.md` — zero-egress scope, BAVR/CUAP, and Splunk HEC claims corrected.
4. `SOW_template.md` — `/v1/attest` endpoint and Splunk HEC claims fixed.
5. `MSP_INTEGRATION.md` — Drata plan requirement and CCT overclaims corrected.
6. `SECURITY.md` — ecdsa advisory documented with the production-path diligence statement.
7. `SECURITY.md` — all eight GHSA suppressions documented with resolution status.
8. `SECURITY.md` — PSA plaintext credential issue documented with a remediation path.
