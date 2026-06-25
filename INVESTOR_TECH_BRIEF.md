# Hermes Compliance Framework
## Investor Technical Brief — Confidential

**Classification:** NDA-Protected Pre-Investment Material  
**Prepared by:** Sui-Generis LLC · Rocky Top, Tennessee  
**Contact:** a.rogers@sentinel1.tech  
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
│               │   Classifier    │   │      Auditor        │      │  │
│               │  spaCy NER +    │   │  SHA-256 Chained    │      │  │
│               │  Regex Patterns │   │  Immutable Log      │      │  │
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
2. Classifier identifies PHI/PII/PAN using spaCy NER + regex
3. Sensitive tokens are replaced with typed placeholders (`[REDACTED_SSN]`, `[REDACTED_PAN]`, etc.)
4. Auditor writes an immutable, SHA-256 chained log entry
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
| PHI Category | Detection Method | Status |
|---|---|---|
| SSN (Social Security Number) | Regex: `\d{3}-\d{2}-\d{4}` | ✅ Active |
| Named entities (person names) | spaCy `en_core_web_sm` NER | ✅ Active |
| Addresses | spaCy location NER | ✅ Active |
| Extensible to: DOB, MRN, Phone | Classifier pattern registry | 🔜 Roadmap |

**Audit flag:** `HIPAA_SSN=1` logged on every SSN detection event.

### PCI-DSS (Payment Card Industry Data Security Standard)
| PAN Pattern | Detection Method | Status |
|---|---|---|
| 13–16 digit card numbers | Regex: Luhn-validated pattern | ✅ Active |
| All major card networks | Pattern covers Visa/MC/Amex/Discover | ✅ Active |

**Audit flag:** `PCI_PAN=1` logged on every card number detection event.

---

## Audit Trail Methodology

Every scrub operation produces a tamper-evident log entry. The chain is
implemented as follows:

```
Entry N:
  transaction_id : UUID4
  timestamp      : ISO-8601 UTC
  flags          : { HIPAA_SSN: int, PCI_PAN: int }
  char_count_in  : int
  char_count_out : int
  hash           : SHA-256(previous_hash + current_entry_json)
```

**Why this matters for compliance:**
- Demonstrates to auditors that the system was operating at a specific moment
- Chain linkage means retroactive log modification is cryptographically detectable
- Supports both HIPAA audit trail requirements and PCI-DSS Requirement 10 (log monitoring)
- Fully local — no dependency on a third-party SIEM

---

## Live Demo Instructions

### Prerequisites
- Docker installed (v2+)
- A GitHub account with access to the private repo (provided under NDA)

### Start the stack
```bash
git clone https://github.com/g1n0mag1k/hermes-compliance-framework
cd hermes-compliance-framework
cp .env.hermes.example .env.hermes
# Add your API key to .env.hermes
docker compose up -d
```

### Access the demo UI
Navigate to: `https://[demo-host]` (Caddy handles TLS automatically)

The Streamlit interface provides:
- Free-text input field
- Scrub button — hits `/v1/scrub` endpoint
- Redacted output with highlighted replacements
- Live sidebar: transaction ID, flags triggered, character delta, audit chain

### What to show investors
1. Paste a realistic support ticket containing an SSN and a credit card number
2. Hit Scrub
3. Show the redacted output — `[REDACTED_SSN]` and `[REDACTED_PAN]` in place
4. Expand the sidebar — show `HIPAA_SSN=1`, `PCI_PAN=1`, transaction ID, SHA-256 chain
5. Run a second scrub — show the chain hash change, proving immutability

---

## Known Limitations

| Limitation | Context | Roadmap Response |
|---|---|---|
| English-only NER | spaCy `en_core_web_sm` is English | Multi-language model support in v1.1 |
| Regex-based PAN detection | No Luhn checksum validation yet | Luhn validation in v1.1 |
| PHI category coverage | SSN + NER today; DOB, MRN, phone pending | Classifier pattern registry expansion |
| No streaming support | Single-shot scrub only | Streaming endpoint for LLM proxy mode |
| Audit log is in-memory | Restarts clear the chain | Persistent audit backend (Postgres) |
| Single-tenant per deployment | No multi-tenant RBAC yet | Per-tenant API keys + scoped audit logs |

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

- **Entity:** Sui-Generis LLC (HUBZone-certified)
- **Location:** Rocky Top, Tennessee (Campbell County — rural Appalachian geography)
- **SAM.gov UEI:** YK4VNG1STBA1
- **HUBZone Status:** Designated — Campbell County, TN
- **SEDI Eligibility:** Confirmed — rural Appalachian geography qualifies under InvestTN/SSBCI SEDI priority routing
- **Founder:** Solo technical founder; GMP manufacturing background (3M); systems engineering, cybersecurity, Python/SQL

---

*This document is confidential and intended solely for qualified investors under NDA.  
Source code access is available only following execution of a mutual NDA and receipt of a term sheet.*
