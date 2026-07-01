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
- **API authentication:** `/v1/scrub` requires `X-API-Key` matching `HERMES_API_KEY`. There is currently no rate limiting, no key rotation mechanism, and no multi-tenant key isolation — single shared key per deployment. Multi-tenant isolation is on the roadmap, not yet implemented.

## Supported Versions

Pre-1.0 solo-founder project. There is currently one actively maintained branch: `main`. No formal LTS or backport policy exists yet.
