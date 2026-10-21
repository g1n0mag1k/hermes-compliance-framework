# Hermes Relay — Competitive Benchmark Report

> **Archived 2026-07-01 snapshot (v1.0.0). Detection scope has changed since; see [docs/SCOPE_BOUNDARY.md](docs/SCOPE_BOUNDARY.md). Not a current benchmark.**

_Generated: 2026-07-01 02:02 UTC_

## Methodology
- Synthetic test corpus: 17 cases across SSN, PAN, and combined PHI+PAN
- **Scope note:** rates below measure SSN and PAN detection only on this corpus — not full Safe Harbor coverage
- Adversarial negatives included (invalid SSN ranges, Luhn-failing PANs)
- Hermes run locally on this corpus
- Latency: median of all test case executions
- NER detection (PERSON/DATE/ORG) is not included in this benchmark

## Detection scope at time of snapshot (v1.0.0)

At the time of this snapshot, Hermes v1.0.0 actively detected: **SSN** (regex), **payment card numbers** (regex + Luhn), and **PERSON / DATE / ORG** entities via spaCy `en_core_web_sm`. Phone numbers, email addresses, medical record numbers, addresses, IP addresses, URLs, and other Safe Harbor categories were **not yet detected** in that release — full 18-category coverage was in active development. For **current** detection scope, see [docs/SCOPE_BOUNDARY.md](docs/SCOPE_BOUNDARY.md).

## Hermes measured results (SSN + PAN corpus only)

| Tool | SSN Detection | PAN Detection | p50 Latency | Runs locally | Reversible | Attestation |
|------|--------------|---------------|-------------|--------------|------------|-------------|
| **Hermes Relay v1.0.0** | **100%*** | **100%*** | **2.6ms** | **✅ Yes** | **🔜 Roadmap** | **✅ Proxy mode** |

*\*Hermes SSN/PAN rates are 100% on this 17-case synthetic corpus only — not a claim of universal or full Safe Harbor detection.*

## Hermes capabilities (snapshot context)

| Capability | Hermes | Presidio | AWS | Azure | Nightfall |
|-----------|--------|----------|-----|-------|-----------|
| Reversible redaction (token vault) | 🔜 Roadmap | — | — | — | — |
| Cryptographic compliance receipts  | ✅ Proxy | — | — | — | — |
| Zero-trust LLM proxy mode          | ✅ | — | — | — | — |
| Hash-chained tamper-evident audit log | ✅ Proxy | — | — | — | — |
| Runs locally                       | ✅ | ✅ | — | — | — |
| Open source + self-hostable        | ✅ | ✅ | — | — | — |
| Luhn checksum PAN validation       | ✅ | ✅ | — | — | — |

## Key Finding
> On the SSN/PAN synthetic corpus, Hermes measured **100%** SSN and PAN detection with **~2.6ms** median latency on local execution. Architectural differentiators in active or partial deployment: zero-trust LLM proxy mode, cryptographic compliance receipts (proxy mode), and a token vault for reversible redaction (roadmap). Competitor detection rates and latency were **not measured** in this snapshot.

---
_Hermes Relay — Zero-Trust Compliance Infrastructure for MSPs_
_hermesrelay.dev | andrew@hermesrelay.dev_
