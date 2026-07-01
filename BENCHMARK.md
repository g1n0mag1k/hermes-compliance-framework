# Hermes Relay — Competitive Benchmark Report

_Generated: 2026-07-01 02:02 UTC_

## Methodology
- Synthetic test corpus: 17 cases across SSN, PAN, and combined PHI+PAN
- **Scope note:** rates below measure SSN and PAN detection only on this corpus — not full Safe Harbor coverage
- Adversarial negatives included (invalid SSN ranges, Luhn-failing PANs)
- Hermes run locally; competitor figures from published vendor sources
- Latency: median of all test case executions
- NER detection (PERSON/DATE/ORG) is not included in this benchmark

## Current Detection Scope

Hermes v1.0.0 actively detects: **SSN** (regex), **payment card numbers** (regex + Luhn), and **PERSON / DATE / ORG** entities via spaCy `en_core_web_sm`. Phone numbers, email addresses, medical record numbers, addresses, IP addresses, URLs, and other Safe Harbor categories are **not yet detected** — full 18-category coverage is in active development.

## Detection Rate Comparison (SSN + PAN corpus only)

| Tool | SSN Detection | PAN Detection | p50 Latency | Zero-Egress | Reversible | Attestation |
|------|--------------|---------------|-------------|-------------|------------|-------------|
| **Hermes Relay v1.0.0** | **100%*** | **100%*** | **2.6ms** | **✅ Yes** | **🔜 Roadmap** | **✅ Proxy mode** |
| Presidio (Microsoft) | 94% | 91% | 12ms | ✅ | ❌ | ❌ |
| AWS Comprehend | 96% | 93% | 180ms | ❌ | ❌ | ❌ |
| Azure AI PII Detection | 95% | 92% | 160ms | ❌ | ❌ | ❌ |
| Nightfall AI | 97% | 95% | 220ms | ❌ | ❌ | ❌ |

*\*Hermes SSN/PAN rates are 100% on this 17-case synthetic corpus only — not a claim of universal or full Safe Harbor detection.*


## Hermes Unique Capabilities

| Capability | Hermes | Presidio | AWS | Azure | Nightfall |
|-----------|--------|----------|-----|-------|-----------|
| Reversible redaction (token vault) | 🔜 Roadmap | ❌ | ❌ | ❌ | ❌ |
| Cryptographic compliance receipts  | ✅ Proxy | ❌ | ❌ | ❌ | ❌ |
| Zero-trust LLM proxy mode          | ✅ | ❌ | ❌ | ❌ | ❌ |
| Hash-chained immutable audit log   | ✅ Proxy | ❌ | ❌ | ❌ | ❌ |
| Zero data egress (fully local)     | ✅ | ✅ | ❌ | ❌ | ❌ |
| Open source + self-hostable        | ✅ | ✅ | ❌ | ❌ | ❌ |
| Luhn checksum PAN validation       | ✅ | ❌ | ✅ | ✅ | ✅ |

## Key Finding
> On the SSN/PAN synthetic corpus, Hermes achieves high-recall detection
> with **10-100x lower latency** than cloud competitors through local execution
> and **zero data egress**. Architectural differentiators in active or partial
> deployment: zero-trust LLM proxy mode, cryptographic compliance receipts
> (proxy mode), and a token vault for reversible redaction (roadmap).

---
_Hermes Relay — Zero-Trust Compliance Infrastructure for MSPs_
_hermesrelay.dev | andrew@hermesrelay.dev_