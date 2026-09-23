# Security Policy

Hermes Relay is compliance infrastructure. Security issues are treated as high priority regardless of severity classification.

## Reporting a Vulnerability

If you discover a security vulnerability in Hermes Relay, please report it privately rather than opening a public GitHub issue.

**Contact:** andrew@hermesrelay.dev

Please include:
- A description of the vulnerability and its potential impact
- Steps to reproduce, if applicable
- Any suggested remediation

You can expect an initial response within 48 hours. This is a solo-founder project — response times outside that window will be communicated directly.

## Scope

This policy covers:
- `hermes/` — the core scrubbing, attestation, vault, and proxy modules
- `landing/` — the hermesrelay.dev marketing site (lower severity; no PHI processing occurs here)

Out of scope: third-party dependencies' own disclosed CVEs, unless they are exploitable in the specific way Hermes uses them (see Known Dependency Alerts below).

## Known Dependency Alerts — Review Log

Dependabot and other automated scanners will periodically flag vulnerabilities in third-party dependencies. Each flagged item is reviewed and logged here with a determination, so the review process itself is auditable.

### postcss XSS via unescaped `</style>` (Dependabot alert #3, moderate)

- **Package:** postcss (transitive dependency via `next@15.5.19`)
- **Affected versions:** < 8.5.10
- **Reviewed:** 2026-07-01
- **Determination:** Not exploitable in this codebase. The vulnerability requires user-submitted CSS to be parsed and re-stringified by PostCSS at runtime, then embedded into a page. The `landing/` site is a static Next.js build — PostCSS runs at build time only, compiling fixed Tailwind classes. There is no code path where user input is parsed by PostCSS and echoed into a page.
- **Remediation blocked by:** `next@15.5.19` pins `postcss@8.4.31`; the patched version (`8.5.10`+) conflicts with this pin. Downgrading Next.js to resolve would be a larger regression than the (non-exploitable) vulnerability itself.
- **Resolution plan:** Will be picked up automatically via `npm update` once Next.js releases a version compatible with the patched postcss release. Re-reviewed each time Dependabot re-flags.

## Architecture Notes Relevant to Security Review

- **Zero-egress core:** The `/v1/scrub` endpoint and `hermes/classifier.py` make no external network calls. All PHI detection runs against local models (spaCy `en_core_web_sm`, Microsoft Presidio's `AnalyzerEngine`) inside the deployment environment.
- **Proxy mode network egress:** `hermes/proxy.py` (`ProxyRelay`) is the one component that makes outbound calls, by design — it forwards *already-scrubbed* payloads to an upstream LLM target (OpenAI, Anthropic, Ollama, or a custom endpoint). Unscrubbed PHI is never forwarded; scrubbing happens before the outbound request is constructed.
- **Signing keys:** `HERMES_SIGNING_KEY` (attestation receipts) and `HERMES_VAULT_KEY` (reversible redaction vault) fall back to a hardcoded development key if not set via environment variable. **This fallback is not safe for production deployment.** Both must be set to a securely generated value before any pilot or production use. This is called out explicitly here because it is easy to miss.
- **Gateway signing keys:** Gateway V2 receipts require `HERMES_GATEWAY_KEYSTORE_PATH` and `HERMES_GATEWAY_KEYSTORE_PASSPHRASE` when `HERMES_ENV=production`. Ephemeral Ed25519 keys are generated in development/test only. Restarting without a persistent keystore creates a new signing identity and breaks verification of prior gateway receipts.
- **API authentication:** `/v1/scrub` requires `X-API-Key` matching `HERMES_API_KEY`. Gateway routes require workspace `X-API-Key`. There is currently no rate limiting and no automated key rotation.
- **Workspace isolation:** Multiple workspaces per deployment are supported with per-workspace receipt chains. Deployments remain single-customer-environment (not multi-tenant SaaS).

## Supported Versions

Pre-1.0 solo-founder project. There is currently one actively maintained branch: `main`. No formal LTS or backport policy exists yet.

## Known Dependency Advisories

### PYSEC-2026-1325 — ecdsa 0.19.2
- **Status:** Transitive dependency of pycose==1.1.0. Not used directly by Hermes.
- **Impact:** Hermes receipt signing and verification uses the `cryptography` library (Ed25519/ES256), not `ecdsa`. The vulnerable package is present in the dependency graph but is not exercised by Hermes production signing paths.
- **Verification:** `grep -rn "import ecdsa" hermes/ gateway/` returns zero results.
- **Remediation:** Tracking upstream pycose for a release that removes the ecdsa dependency. No patched version of ecdsa or pycose is currently available.
- **Diligence statement:** ecdsa is a transitive dependency of pycose; Hermes does not use it for receipt signing or verification. Hermes signs and verifies using the `cryptography` library.

### CI Vulnerability Suppressions — GHSA Advisories

The following advisories are suppressed in CI because they affect package versions
older than what Hermes currently pins:

| Advisory | Package | Hermes Version | Status |
|----------|---------|----------------|--------|
| GHSA-f96h-pmfr-66vw | starlette | 1.6.0 | Patched in current version |
| GHSA-jjg7-2v4v-x38h | starlette | 1.6.0 | Patched in current version |
| GHSA-qj8w-rv5x-2v9h | starlette | 1.6.0 | Patched in current version |
| GHSA-74m5-2c7w-9w3x | starlette | 1.6.0 | Patched in current version |
| GHSA-6vqw-3v5j-54x4 | python-multipart | 0.0.32 | Patched in current version |
| GHSA-35jj-vqcf-f2jf | python-multipart | 0.0.32 | Patched in current version |
| GHSA-cp75-3r2x-4qmc | idna | 3.19 | Patched in current version |
| GHSA-h8gr-9994-4x4g | starlette | 1.6.0 | Patched in current version |

These suppressions exist because pip-audit matches advisory IDs to package names
regardless of version. All affected packages are pinned at versions that resolve
the reported issues. Suppressions will be removed once pip-audit correctly
excludes already-patched versions.

### PSA Credentials Stored Plaintext — OPEN

**Location:** gateway/credentials.py — CredentialManager class  
**Status:** Known limitation, not yet remediated  
**Impact:** HaloPSA and ConnectWise PSA API tokens stored as plaintext TEXT in ~/.hermes/psa_credentials.db  
**Scope:** Affects only the PSA canary-drift subsystem, not the core /v1/scrub or gateway PHI-detection path  
**Remediation path:** Encrypt api_token column at rest using HERMES_VAULT_KEY via hermes/vault.py AES-256-GCM before storing; decrypt on retrieval. Scheduled for next engineering sprint.  
**Diligence statement:** PSA credentials are stored in a local SQLite database accessible only within the customer deployment environment. They are not transmitted externally. Encryption at rest is on the roadmap.
