# Hermes Compliance Framework
## Investor Technical Brief — Confidential

**Classification:** NDA-Protected Pre-Investment Material  
**Prepared by:** Sui-Generis LLC · Rocky Top, Tennessee  
**Contact:** andrew@hermesrelay.dev  
**GitHub:** github.com/g1n0mag1k (private repo, NDA + term sheet required for access)

---

## Executive Summary

Hermes is a zero-trust HIPAA/PCI compliance API that intercepts and sanitizes
sensitive data before it enters any AI pipeline. It runs fully on-premises — no
external API calls, no cloud dependency, no data ever leaving the customer's
environment. Target buyers are Managed Service Providers (MSPs), RMM platforms,
and healthcare-adjacent SaaS companies operating AI-assisted workflows on data
subject to HIPAA, PCI-DSS, or state privacy law.

The core problem Hermes solves is structural: AI pipelines are compliance
nightmares by default. Every support ticket, every clinical note, every billing
record that passes through a GPT-4 or Claude API call is a potential HIPAA
breach event. Hermes makes that problem disappear at the infrastructure layer —
before the payload ever leaves the customer's network.

---

## Architecture

```
┌──────────────────────────────────────────────────────────────────────┐
│                        CUSTOMER ENVIRONMENT                          │
│                                                                      │
│   ┌─────────────┐    HTTPS/TLS     ┌──────────────────────────────┐ │
│   │  Client App │ ──────────────► │        Caddy (Reverse Proxy) │ │
│   │  RMM / MSP  │                  │     Auto-TLS / Self-Signed   │ │
│   └─────────────┘                  └──────────────┬───────────────┘ │
│                                                   │                  │
│                                    ┌──────────────▼───────────────┐ │
│                                    │      Hermes API (FastAPI)    │ │
│                                    │      uvicorn · port 8000     │ │
│                                    │      2 replicas · non-root   │ │
│                                    └──────────────┬───────────────┘ │
│                                                   │                  │
│                          ┌────────────────────────┼──────────────┐  │
│                          │                        │              │  │
│               ┌──────────▼──────┐   ┌─────────────▼──────┐      │  │
│               │   Classifier    │   │   Attestation       │      │  │
│               │  spaCy NER +    │   │  HMAC-SHA256 chain  │      │  │
│               │  Regex Patterns │   │  SQLite persistence │      │  │
│               └─────────────────┘   └────────────────────┘      │  │
│                                                                   │  │
│                    tmpfs /tmp · UID 10001 · no internet           │  │
└──────────────────────────────────────────────────────────────────────┘
                              │
                              │  REDACTED PAYLOAD ONLY
                              ▼
                    ┌─────────────────────┐
                    │   AI Pipeline /     │
                    │   LLM API Call      │
                    │  (OpenAI, Claude,   │
                    │   on-prem model)    │
                    └─────────────────────┘
```

**Data flow in plain terms:**
1. Client sends raw text payload to Hermes API (authenticated)
2. Classifier scans for 16 of 18 HIPAA Safe Harbor categories 
   (spaCy NER, Presidio, regex, and checksum-validated patterns); 
   PAN via regex with Luhn validation
3. Sensitive tokens are replaced with typed placeholders 
   (`[REDACTED_SSN]`, `[REDACTED_PAN]`, `[REDACTED_PERSON]`, etc.). 
   Vault implemented (AES-256-GCM); default scrub path uses irreversible 
   placeholders. Reversible scrub available via `scrub_payload_reversible()`.
4. `/v1/scrub` returns structured audit flags and counts, and 
   issues HMAC-SHA256 chained compliance receipts via the 
   attestation module
5. Redacted payload is returned — this is what reaches the AI pipeline
6. No sensitive data ever touches an external network

---

## Security Posture

### Container Hardening
| Control | Implementation |
|---|---|
| Non-root runtime | UID 10001 (`hermes` user) — no root access at runtime |
| Ephemeral temp | `tmpfs` on `/tmp` — no sensitive writes to disk |
| No internet egress | Container runs with no outbound network access |
| Multi-stage build | Build tools stripped from final image |
| Pinned dependencies | All packages pinned to exact versions (`==`) |
| Image integrity | SHA-256 digest verified and logged in audit trail |

### Authentication
- API key auth required on all endpoints except `/health`
- 401 Unauthorized on missing or invalid key — no information leakage
- Keys injected via environment variable (`.env.hermes`) — never committed to git

### Dependency Audit
- `pip-audit` runs on every CI push against direct dependencies
- 8 transitive CVEs in `starlette` (indirect dep) are tracked and acknowledged
- Zero CVEs in any directly pinned package
- CI pipeline blocks on any new direct-dependency finding

---

## Compliance Coverage

### HIPAA (Health Insurance Portability and Accountability Act)

**Current detection scope** — 16 of 18 Safe Harbor categories 
covered per `DECLARED_SCOPE` in `hermes/classifier.py`. Categories 
(P) and (Q) are text-reference only; binary image/biometric content 
is not inspected.

| PHI Category | Detection Method | Status |
|---|---|---|
| Names | spaCy NER | ✅ Active |
| Geographic subdivisions | Presidio | ✅ Active |
| Dates | spaCy NER | ✅ Active |
| Telephone numbers | Presidio | ✅ Active |
| Fax numbers | regex | ✅ Active |
| Email addresses | Presidio | ✅ Active |
| Social security numbers | regex | ✅ Active |
| Medical record numbers | regex | ✅ Active |
| Health plan beneficiary numbers | regex | ✅ Active |
| Account numbers | regex | ✅ Active |
| Certificate/license numbers | regex+checksum | ✅ Active |
| Vehicle identifiers/VINs | regex | ✅ Active |
| Device identifiers | regex+checksum | ✅ Active |
| Web URLs | Presidio | ✅ Active |
| IP addresses | Presidio | ✅ Active |
| Biometric identifiers | regex+denylist | reference_only (text only) |
| Full face photographs | regex | reference_only (text only) |
| Other unique identifiers | regex | ✅ Active |

**Audit flags:** per-category flags (e.g. `HIPAA_SSN`, 
`HIPAA_PHI_PERSON`, `HIPAA_PHI_PHONE`, `HIPAA_PHI_MRN`) logged 
with CFR citations on every detection event.

### PCI-DSS (Payment Card Industry Data Security Standard)
| PAN Pattern | Detection Method | Status |
|---|---|---|
| 13–16 digit card numbers | Regex pattern — Visa/MC/Amex/Discover | ✅ Active |
| All major card networks | Pattern covers Visa/MC/Amex/Discover | ✅ Active |

**Audit flag:** `PCI_PAN=1` logged on every card number detection event.

---

## Audit Trail Methodology

`/v1/scrub` returns a `RedactionAuditLog` with transaction ID, 
character counts, and per-class flag counts, and issues 
tamper-evident compliance receipts chained via HMAC-SHA256:

```
Receipt N:
  receipt_id           : rcpt_{transaction_id}_{position}
  transaction_id       : UUID
  issued_at            : ISO-8601 UTC
  pii_classes_detected : [HIPAA_SSN, PCI_PAN, HIPAA_PHI_PERSON, ...]
  previous_receipt_hash: HMAC chain link
  receipt_hash         : HMAC-SHA256(canonical JSON payload)
```

**Why this matters for compliance:**
- Demonstrates to auditors that the system was operating at a specific moment
- Chain linkage means retroactive receipt modification is cryptographically detectable
- Supports HIPAA audit trail requirements and PCI-DSS Requirement 10 (log monitoring)
- Fully local — no dependency on a third-party SIEM

---

## Known Limitations

| Limitation | Context | Roadmap Response |
|---|---|---|
| Binary content inspection (P/Q) | Biometric identifiers and full-face photographs: text references only; binary image/biometric payloads not inspected | Content-channel inspection for embedded media |
| Single-tenant per deployment | No multi-tenant RBAC yet | Per-tenant API keys + scoped audit logs |
| English-only NER | spaCy `en_core_web_sm` is English | Multi-language model support in v1.1 |
| No streaming support | Single-shot scrub only | Streaming endpoint for LLM proxy mode |

---

## Competitive Analysis — Hermes vs. Enterprise Alternatives

The question every investor will ask: *"Why not just use Microsoft Purview or AWS Macie?"*

| Dimension | Microsoft Purview | AWS Macie | **Hermes** |
|---|---|---|---|
| **Deployment** | Cloud-only | Cloud-only (S3-focused) | **On-premises, air-gapped** |
| **Data residency** | Microsoft cloud | AWS cloud | **Never leaves customer network** |
| **AI pipeline integration** | Not designed for it | Not designed for it | **Purpose-built for LLM pipelines** |
| **MSP / RMM market fit** | Enterprise IT dept | AWS-native teams | **MSP-native, PSA-integrated** |
| **Time to compliance** | Weeks of config | Days + AWS expertise | **Hours — Docker Compose** |
| **Cost model** | $3–10/user/month + storage | Usage-based + S3 costs | **Flat SaaS, predictable** |
| **Minimum viable buyer** | Fortune 500 | AWS-native mid-market | **5-seat MSP** |
| **Audit trail** | Proprietary, cloud-locked | S3 logs, cloud-locked | **Portable, cryptographically chained** |
| **Open-source foundation** | No | No | **MIT — customer can audit the code** |

**The core differentiator:** Purview and Macie solve data classification at rest in a cloud storage layer. Neither product is designed to sanitize payloads in real-time before an AI API call. Hermes operates in the gap between customer data and AI infrastructure — a gap that neither Microsoft nor AWS has a purpose-built product to fill.

---

## Why This Matters Now

The HIPAA enforcement environment around AI is tightening. The OCR's December 2024 HIPAA Security Rule update and FTC AI health data guidance have created a compliance urgency that did not exist 18 months ago. MSPs with healthcare clients are actively looking for a bolt-on compliance layer that works with their existing RMM and PSA tooling — not a rip-and-replace enterprise platform.

Hermes is positioned as the answer to a question MSPs are already asking, ahead of a regulatory tightening cycle that is already underway.

---

## About Sui-Generis LLC

- **Entity:** Sui-Generis — not yet a registered LLC; the owner currently operates as a sole proprietor
- **Location:** Rocky Top, Tennessee (Campbell County — rural Appalachian geography)
- **SAM.gov UEI:** YK4VNG1STBA1
- **HUBZone Status:** Located in a HUBZone-designated area (Campbell County, TN); not certified
- **SEDI Eligibility:** Confirmed — rural Appalachian geography qualifies under InvestTN/SSBCI SEDI priority routing
- **Founder:** Solo technical founder; GMP manufacturing background (3M); systems engineering, cybersecurity, Python/SQL

---

*This document is confidential and intended solely for qualified investors under NDA.  
Source code access is available only following execution of a mutual NDA and receipt of a term sheet.*
