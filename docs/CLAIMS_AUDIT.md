# Claims audit (code-backed)

**Repository:** `hermes-compliance-framework` (this workspace)  
**Related repo audited via clone (not in workspace):** `g1n0mag1k/hermes-canary-action` → `/tmp/hermes-canary-action`  
**Audit date:** 2026-10-21  
**Method:** Read-only code and docs review; no runtime behavior changes.

---

## 1. SIGNING (by receipt type)

| Receipt type | Algorithm / envelope | What is signed | Key source | Evidence |
|--------------|---------------------|----------------|------------|----------|
| Relay **`/v1/scrub` compliance receipts** (`ComplianceReceipt`) | **HMAC-SHA256** → hex digest stored in `receipt_hash` | Canonical JSON of immutable fields (`json.dumps(..., sort_keys=True, separators=(",", ":"))`) excluding mutable chain fields and the hash itself | `HERMES_SIGNING_KEY` (hex → bytes); dev fallback SHA256(`hermes-dev-signing-key-not-for-production`) when unset and `HERMES_ENV` ≠ `production` | `hermes/attestation.py` L35–58, L245–253, L314–346 |
| Relay **`/v1/review` human review receipts** (`HumanReviewReceipt`) | **HMAC-SHA256** (same as compliance) | Same canonical JSON scheme | Same `HERMES_SIGNING_KEY` / dev fallback | `hermes/attestation.py` L105–120, L245–253 |
| **Gateway V2 enforcement receipts** (COSE) | **COSE_Sign1**; default signer **Ed25519 (EdDSA, COSE alg -8)**; optional **ES256 (COSE alg -7)** via `SoftwareSignerES256` | RFC 8785 canonical payload bytes inside COSE_Sign1; Sig_Structure passed to signer | Non-prod: ephemeral `SoftwareSignerEd25519.generate()`; prod: `HERMES_GATEWAY_KEYSTORE_PATH` + `HERMES_GATEWAY_KEYSTORE_PASSPHRASE` → encrypted keystore (`gateway/evidence.py` L42–68) | `gateway/evidence.py` L196–246; `hermes/receipts/v2/builder.py` L113–146; `hermes/receipts/v2/software_signer.py` L4–7, L69–75 |
| **`/v2/receipts` HTTP COSE API** | **No route found** | N/A | N/A | Repo search: no `/v2/receipts` string in `hermes/` or `gateway/`. V2 COSE bytes are persisted in SQLite and exported via CLI (`hermes-relay export-receipts`, `hermes-verify receipt`). See `docs/RECEIPT_VERIFICATION.md`, `hermes/cli/__init__.py` L205–240 |
| **CI telemetry ingest** (`POST /v1/telemetry/receipt`) | **HMAC-SHA256** over **raw HTTP body** | Entire request body bytes | Workspace **`X-API-Key`** secret (same as tenant API key), header `X-Hermes-Signature-256` | `hermes/telemetry_receipts.py` L34, L102–108, L111–125; `hermes/api.py` L850+ |
| **Canary API JSON audit report** (`hermes/canary_audit.py` / `POST /v1/telemetry/canary-audit`) | **HMAC-SHA256** → `report_signature` | Canonical JSON with `report_signature` zeroed | `HERMES_SIGNING_KEY` (same scheme as attestation; stricter prod rules in canary module) | `hermes/canary_audit.py` L19–25, L79–98, L455–468, L617–620 |
| **Canary-action JSON receipts** (`hermes-canary-action`) | **HMAC-SHA256** → `signature` (+ mirror `hmac_sha256`) | Canonical JSON with `signature` and `hmac_sha256` zeroed | Customer **`SIGNING_KEY`** input (64 hex chars, from `HERMES_SIGNING_KEY` GitHub secret) | `/tmp/hermes-canary-action/entrypoint.py` L439–452, L768–772 |
| **PDF evidence reports** (`generate_evidence_report`) | **Unsigned PDF** | N/A — embeds existing `receipt_hash` / metadata from an already-signed compliance receipt; blank ink signature lines only | N/A | `hermes/report.py` L42–168 (ReportLab build; no HMAC/COSE on PDF bytes) |
| **V2 checkpoints / key manifests** (not per-request scrub receipts) | **COSE_Sign1** (checkpoints); manifest signed via signer protocol | Checkpoint payload; manifest digest | Ceremony / checkpoint keystores (`hermes/receipts/v2/checkpoint.py`, `key_manifest.py`) | `hermes/receipts/v2/checkpoint.py` L169–184; `hermes/receipts/v2/key_manifest.py` L85–105 |

**Note:** V1 chain “signature” is the **`receipt_hash`** field (HMAC hex), not a separate detached signature field (`hermes/attestation.py` L342–346).

---

## 2. TIME SOURCE (by receipt type)

| Receipt type | Timestamp field(s) | Source in code | External TSA / RFC 3161 |
|--------------|-------------------|----------------|-------------------------|
| `/v1/scrub` compliance + review | `issued_at` | `datetime.now(UTC).isoformat()` at issue time | **No** on receipt path |
| Gateway V2 COSE | `_hermes_issued_at` inside signed COSE payload; `ReceiptV2.issued_at`; DB column `created_at` | Builder: `datetime.now(UTC).isoformat()` (`builder.py` L93–103); persist: `datetime.now(UTC).isoformat()` (`gateway/evidence.py` L164) | **No** on gateway receipt path |
| V2 checkpoints (anchoring module) | `issued_at` on checkpoint; optional `TimestampToken.gen_time` | Checkpoint: `datetime.now(UTC)` (`checkpoint.py` L142); TSA: mock uses `datetime.now(UTC)` (`anchoring.py` L246+); real path calls `rfc3161ng.get_timestamp` when installed (`anchoring.py` L269–307) | **Optional** via `timestamp_checkpoint()` only — **not** wired into `/v1/scrub` or gateway per-request receipts (`docs/CURRENT_LIMITATIONS.md` L29) |
| `POST /v1/telemetry/receipt` | Client `timestamp`; server `ingested_at` | Client-supplied string in JSON body; `ingested_at = datetime.now(UTC).isoformat()` on store | **No** |
| Canary API audit report | `issued_at` | `datetime.now(UTC).isoformat()` at start of `run_canary_audit` | **No** |
| Canary-action JSON | `timestamp` | `datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")` in `_build_receipt` | **No**; CI metadata from `GITHUB_*` env vars |
| PDF report | `issued_at` from embedded receipt dict | Copied from source compliance receipt | **No** |

**RFC 3161:** Implemented only in `hermes/receipts/v2/anchoring.py` (`timestamp_checkpoint`, `_real_timestamp` using optional `rfc3161ng`). Default/mock when `HERMES_TSA_URL` unset. **Not invoked** from `gateway/evidence.py` or `hermes/attestation.py`.

---

## 3. SINKS & `zero_pii_egress_confirmed`

### 3.1 What the field checks (Relay `/v1/scrub`)

| Aspect | Behavior | Evidence |
|--------|----------|----------|
| Field name | `zero_pii_egress_confirmed` (do not rename) | `hermes/attestation.py` L79–80, L328–331 |
| Logic | `True` iff `flags_triggered == flags_redacted` **and** `occurrence_gaps` is empty | `hermes/attestation.py` L303–306 |
| `occurrence_gaps` | Post-scrub scan of `clean_text` for surviving direct identifiers in declared scope | `hermes/classifier.py` L758–773, L1091–1106; tests `tests/test_classifier.py` L381–432 |
| Scope note | Fixed string: confirmed within `declared_scope` only; incomplete categories not checked | `hermes/attestation.py` L329–331 |
| **Not checked** | Live monitoring of Sentry, webhooks, stdout, or network sinks; no socket hook at runtime | No egress-sink observer in `classifier.py` / `attestation.py` |

**Interpretation (code-backed):** The field is **redaction parity + post-scrub occurrence verification** within declared scope — **not** proof that no bytes left the host or reached a third party.

### 3.2 Scrub path — network / integrations (compliance-framework)

| Sink | Observed on `/v1/scrub` scan path? | Evidence |
|------|-----------------------------------|----------|
| External TCP during scrub | **Test asserts zero** when integrations env vars set; runtime does not install a global egress blocker | `tests/security/test_scrub_zero_egress.py` L10–48 |
| `HERMES_WEBHOOK_URL` | Dispatched **after** receipt in background tasks on scrub endpoints — not part of `zero_pii_egress_confirmed` computation | `hermes/api.py` L413–414; `hermes/webhooks.py` |
| Drata CCT (Path A) | Same background dispatch pattern | `hermes/api.py` L414 |
| Sentry DSN | Dashboard stub `POST /api/v1/sentry/config` returns `{"status":"updated"}` — **no DSN storage or egress probe in API** | `hermes/api.py` L686–689 |

### 3.3 Canary paths

| Path | Egress sinks / side effects | Sentry |
|------|----------------------------|--------|
| **`hermes/canary_audit.py`** (`run_canary_audit`) | **None** — docstring: no disk/network for raw payload; signed JSON report only | N/A |
| **`hermes-canary-action` `entrypoint.py`** | Local: receipt JSON file, `GITHUB_OUTPUT`, step summary, stdout. Optional **network:** Keygen license POST, GitHub PR comment POST | **`sentry-dsn`:** local DSN regex + local scrub probe only — **no HTTP to Sentry** (`entrypoint.py` L307–336, L351–352) |
| Canary field naming | API canary report uses **`zero_phi_egress_confirmed`** (not `zero_pii_egress_confirmed`) | `hermes/canary_audit.py` L437–438, L570–607 |

Canary-action `zero_phi` equivalent: harness **PASSED** (no synthetic canary leaks) ∧ post-scrub needle check on real payload (`hermes/canary_audit.py` L562–570) — same semantic family as scrub receipts, **not** network sink observation.

### 3.4 Gateway path (related, not `zero_pii_egress_confirmed`)

Gateway uses separate V2 payload fields (`forwarded`, `phi_categories_*`). PHI egress security tests observe **mock upstream** capture, not Sentry (`tests/security/test_phi_never_egresses.py`).

---

## 4. COVERAGE — `DECLARED_SCOPE`

**Authoritative list:** `hermes/classifier.py` L65–86.

**Counts (tests):** 20 entries; statuses only `covered` or `reference_only`; no `not_covered` (`tests/test_safe_harbor_k_m_p_q_r.py` L111–121).

**16 + 2 mapping:**

| Layer | Count | Meaning | Evidence |
|-------|-------|---------|----------|
| HIPAA Safe Harbor **letters exercised in CI telemetry summary** | **16 keys** `A–O` + `R` (excludes **P**, **Q**) | `SAFE_HARBOR_SUMMARY_KEYS` | `hermes/telemetry_receipts.py` L37–40, L55–68 |
| **`reference_only` in `DECLARED_SCOPE`** | **2** | (P) Biometric identifiers, (Q) Full face photographs | `hermes/classifier.py` L83–84 |
| **`covered` rows in `DECLARED_SCOPE`** | **18** | Includes split rows (e.g. org names, bank numbers) under same CFR letters | `hermes/classifier.py` L66–82, L85 |
| **Total `DECLARED_SCOPE` rows** | **20** | 18 × `covered` + 2 × `reference_only` | `tests/test_safe_harbor_k_m_p_q_r.py` L112 |

### `DECLARED_SCOPE` table

| CFR | Category | Flag | Status | Method |
|-----|----------|------|--------|--------|
| 45 CFR §164.514(b)(2)(i)(A) | Names | `HIPAA_PHI_PERSON` | covered | spaCy NER |
| 45 CFR §164.514(b)(2)(i)(A) | Organization names | `HIPAA_PHI_ORG` | covered | spaCy NER |
| 45 CFR §164.514(b)(2)(i)(B) | Geographic subdivisions | `HIPAA_PHI_ADDRESS` | covered | Presidio |
| 45 CFR §164.514(b)(2)(i)(C) | Dates | `HIPAA_PHI_DATE` | covered | spaCy NER |
| 45 CFR §164.514(b)(2)(i)(D) | Telephone numbers | `HIPAA_PHI_PHONE` | covered | Presidio |
| 45 CFR §164.514(b)(2)(i)(E) | Fax numbers | `HIPAA_PHI_FAX` | covered | regex |
| 45 CFR §164.514(b)(2)(i)(F) | Email addresses | `HIPAA_PHI_EMAIL` | covered | Presidio |
| 45 CFR §164.514(b)(2)(i)(G) | Social security numbers | `HIPAA_SSN` | covered | regex |
| 45 CFR §164.514(b)(2)(i)(H) | Medical record numbers | `HIPAA_PHI_MRN` | covered | regex |
| 45 CFR §164.514(b)(2)(i)(I) | Health plan beneficiary numbers | `HIPAA_PHI_HPBN` | covered | regex |
| 45 CFR §164.514(b)(2)(i)(J) | Account numbers | `HIPAA_PHI_ACCOUNT` | covered | regex |
| 45 CFR §164.514(b)(2)(i)(J) | Bank account numbers | `HIPAA_PHI_BANK_NUMBER` | covered | Presidio |
| 45 CFR §164.514(b)(2)(i)(K) | Certificate/license numbers | `HIPAA_PHI_CERT_LICENSE` | covered | regex+checksum |
| 45 CFR §164.514(b)(2)(i)(L) | Vehicle identifiers/VINs | `HIPAA_PHI_VIN` | covered | regex |
| 45 CFR §164.514(b)(2)(i)(M) | Device identifiers | `HIPAA_PHI_DEVICE_ID` | covered | regex+checksum |
| 45 CFR §164.514(b)(2)(i)(N) | Web URLs | `HIPAA_PHI_URL` | covered | Presidio |
| 45 CFR §164.514(b)(2)(i)(O) | IP addresses | `HIPAA_PHI_IP` | covered | Presidio |
| 45 CFR §164.514(b)(2)(i)(P) | Biometric identifiers | `HIPAA_PHI_BIOMETRIC_REF` | **reference_only** | regex+denylist |
| 45 CFR §164.514(b)(2)(i)(Q) | Full face photographs | `HIPAA_PHI_IMAGE_REF` | **reference_only** | regex |
| 45 CFR §164.514(b)(2)(i)(R) | Other unique identifiers | `HIPAA_PHI_UNIQUE_CODE` | covered | regex |

`evidence_incomplete_categories` on V1 receipts lists CFR strings for all non-`covered` entries (`NOT_COVERED_CFRS`, `hermes/classifier.py` L91, `hermes/attestation.py` L298).

---

## 5. PUBLIC CLAIMS — banned phrase scan

**Scope:** `README*`, `docs/`, `docs/commercial/`, `pitch_one_pager.html`, `landing/`, `action.yml` (none in this repo), marketing-adjacent markdown.  
**Also scanned (external clone):** `/tmp/hermes-canary-action/{README.md,action.yml,marketplace-description.md,launch-copy.md,THREAT-MODEL.md}`.

**Surface classification:** **Public** = site, README, commercial/pitch, investor brief, canary marketplace text. **Internal** = Python/tests/backend docs unless listed as customer-facing.

Phrases with **zero hits** in scanned compliance-framework public trees: `containment`, `defensible`, `zero leak`, `HIPAA compliant`, `HIPAA-compliant`, `Safe Harbor compliant`, `tamper-proof`, `third-party verif`, `18/18`, `non-repudiation` (public/marketing only; see internal code hits below).

### Hits (representative table — full `rg` output archived in audit session)

| Phrase | File | Line | Exact snippet (truncated) | Surface |
|--------|------|------|---------------------------|---------|
| court | `CHANGELOG.md` | 34 | Removed fabricated **court** case "Travelers v. ICS" | Internal doc |
| no leak | `hermes/canary_audit.py` | 396 | comment: synthetic token (**no leak**) | Internal code |
| guarantee | `hermes/report.py` | 139, 146 | disclaimer: not a **guarantee** of HIPAA compliance | Internal (PDF generator) |
| guarantee | `landing/components/Hero.tsx` | 57 | CSS comment: **guarantee** the row never wraps | Public (non-claim) |
| guarantee | `docs/integrations/DRATA.md` | 366 | Enforcement independence **guarantee** (Drata path) | Internal doc |
| zero PHI | `docs/hermes-relay-notion-page.html` | 21 | **Zero PHI** egress | Public-ish doc |
| zero PHI | `landing/app/privacy/page.tsx` | 23 | zero-PHI-retention | Public site |
| zero-egress | `README.md` | 3, 38, 108 | **Zero-egress** / zero-egress architecture | Public |
| zero-egress | `landing/**` (multiple) | — | Hero, Solution, CTA, Architecture, Pricing, privacy, security | Public |
| zero-egress | `docs/commercial/*` | — | SOW, BAA, pitch_one_pager | Public/commercial |
| 18 of 18 | `landing/components/Architecture.tsx` | 11 | **18 of 18** Safe Harbor categories | Public |
| 18 of 18 | `landing/components/FAQ.tsx` | 16 | detects **18 of 18** … (with negation of certified de-id) | Public |
| all 18 | `landing/components/Readiness.tsx` | 33 | **all 18** identifier categories | Public |
| all 18 | `docs/SCOPE_BOUNDARY.md` | 127 | de-identified note may satisfy **all 18** (limitation prose) | Internal doc |
| 16 of 18 | `README.md`, `landing/components/AuditChain.tsx`, `landing/components/Solution.tsx`, etc. | — | **16 of 18** coverage wording | Public + docs |
| certified | `landing/components/FAQ.tsx` | 16 | does not claim **certified** Safe Harbor de-identification | Public (disclaimer) |
| certified | `INVESTOR_TECH_BRIEF.md` | 217 | HUBZone-**certified** (entity, not product) | Public-ish |
| de-identif | `landing/components/Problem.tsx` | 31, 37 | **de-identification** method / Safe Harbor-aligned | Public |
| de-identif | `landing/components/AuditChain.tsx` | 56 | not … **de-identification** | Public (disclaimer) |
| HIPAA compliance | `landing/components/FAQ.tsx` | 16 | blanket **HIPAA compliance** (negated) | Public |
| non-repudiation | `hermes/receipts/v2/migration.py` | 7, 43, 58 | V2 bridge **non-repudiation** comments | Internal code |
| guarantee | `hermes-canary-action/THREAT-MODEL.md` | 24 | Zero-PHI-egress **guarantee** | Public (sibling repo) |
| zero PHI | `hermes-canary-action/marketplace-description.md` | 8 | **zero PHI** egress | Public (sibling repo) |
| de-identif | `hermes-canary-action/README.md` | 26 | Safe Harbor **de-identification** method (CFR cite) | Public (sibling repo) |

**`first` / `only`:** Hundreds of benign grammatical matches (e.g. "only after", "first receipt"). Marketing-sensitive examples:

| Phrase | File | Line | Note | Surface |
|--------|------|------|------|---------|
| first | `README.md` | 108 | "Only producible by a zero-egress architecture" (contains **only**) | Public |
| first layer | `landing/components/FAQ.tsx` | 16 | strong **first** layer for PHI reduction | Public |
| Local-First | `docs/hermes-relay-notion-page.html` | 24 | heading **Local-First** | Public-ish |

For a exhaustive **`only`** inventory, run:  
`rg -n '\bonly\b' README.md landing/ docs/commercial/ docs/*.md` (expect 200+ lines; mostly operational/legal, not superlatives).

---

## Audit meta

| Item | Value |
|------|--------|
| Files changed this session | `docs/CLAIMS_AUDIT.md` (new) |
| Product claims removed | **0** (audit only) |
| Product claims added | **0** (audit only) |

---

## Open confirmations for owner (before copy edits)

1. **`/v2/receipts` naming:** Confirm whether this meant gateway **COSE** files (CLI export) vs **`POST /v1/telemetry/receipt`** (HMAC JSON).
2. **Landing inconsistency:** Same site uses both **"16 of 18"** and **"18 of 18"** (Architecture/FAQ vs AuditChain/Solution).
3. **Canary-action marketplace** uses **"zero PHI egress"** and **"guarantee"** in THREAT-MODEL — align with compliance-framework banned-phrase policy?

---

## Resolved (claims cleanup)

| File | Old text | New text | Session |
|------|----------|----------|---------|
| `landing/components/Architecture.tsx` | PHI categories covered: **18 of 18 Safe Harbor categories** … | **16 of 18 HIPAA Safe Harbor identifier categories** … (aligned with `Solution.tsx` / `AuditChain.tsx`) | 5 |
| `landing/components/Architecture.tsx` | Audit record format: **COSE_Sign1 asymmetric-signed** … (relay table) | **HMAC-SHA256-signed, SHA-256 hash-chained JSON compliance receipts** (/v1/scrub, /v1/review); gateway COSE V2 called out separately | 5 |
| `landing/components/Architecture.tsx` | Signing: **Ed25519 / ES256 asymmetric signatures** (relay table) | **HMAC-SHA256 relay attestation chain**; gateway Ed25519 / ES256 noted separately | 5 |
| `landing/components/FAQ.tsx` | detects **18 of 18** … **tamper-evident proof** … cryptographically signed | **16 of 18** … **HMAC-SHA256-signed** … **tamper-evident attestation** | 5 |
| `landing/components/FAQ.tsx` | emits a signed receipt … **tamper-evident proof** that redaction happened | **HMAC-SHA256-signed** receipt … **tamper-evident attestation** | 5 |
| `landing/components/Readiness.tsx` | **all 18 identifier categories** | **16 of 18 identifier categories in direct text scope (P and Q reference-only, disclosed)** | 5 |
| `landing/components/Hero.tsx` | **tamper-evident proof** it happened | **tamper-evident attestation** it happened | 5 |
| `landing/components/Differentiators.tsx` | **tamper-evident proof** it happened | **tamper-evident attestation** it happened | 5 |
