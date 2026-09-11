# Statement of Work
## Hermes Relay — 30-Day Pilot Engagement

**Document type:** Statement of Work (SOW)  
**Product:** Hermes Relay — zero-egress PHI redaction API with hash-chained attestation  
**Provider:** Sui-Generis LLC  
**Provider address:** Rocky Top, Tennessee  
**Provider contact:** Andrew Rogers, Founder — andrew@hermesrelay.dev  
**Provider website:** https://hermesrelay.dev  
**Repository reference:** https://github.com/g1n0mag1k/hermes-compliance-framework  

| Field | Value |
| --- | --- |
| SOW effective date | ________________________ |
| Pilot start date | ________________________ |
| Pilot end date | ________________________ (30 calendar days from pilot start) |
| Client legal name | ________________________ |
| Client address | ________________________ |
| Client primary contact | ________________________ |
| Client email | ________________________ |

This Statement of Work (“SOW”) is entered into by and between **Sui-Generis LLC** (“Provider”) and the client named above (“Client”). This SOW describes the services Provider will perform for the Hermes Relay 30-day pilot and the commercial terms governing that engagement. A Business Associate Agreement (BAA) is available upon request and, when executed, is incorporated by reference for HIPAA-covered deployments.

---

## 1. Scope of Services

Provider will deliver the following services during the pilot period:

### 1.1 Deployment

- Deploy Hermes Relay as a zero-egress PHI redaction service inside Client’s designated environment (Docker, bare metal, or virtual machine), with no PHI transit through Sui-Generis infrastructure.
- Configure runtime, API surface (`/v1/scrub`, `/v1/attest`, `/v1/health` or equivalent shipped endpoints), signing keys, and environment variables required for production-style operation in Client’s infrastructure.
- Confirm that scrubbing and attestation operate with zero external network calls during redaction (zero-egress by design).

### 1.2 Integration Support

- Assist Client in wiring Hermes Relay ahead of AI / LLM or other outbound pipelines via the REST API.
- Support configuration of structured JSON webhook export (optional auth header) for audit events to Client-designated receivers (for example, generic webhook intake or Splunk HEC-compatible endpoints).
- Provide API key setup guidance and integration troubleshooting for payloads Client selects for the pilot.

### 1.3 Audit Chain Setup

- Initialize and verify the SHA-256 hash-chained attestation pipeline in Client’s environment.
- Confirm cryptographically signed receipts for scrubbing decisions, including previous-hash linkage and chain integrity verification.
- Orient Client’s technical contact on how to export, retain, and present attestation receipts for internal audit or OCR-related documentation requests.

Services under this SOW are limited to the pilot deployment described herein. Expansion of identifier coverage beyond the then-current product capabilities, custom connectors requiring signed platform APIs, SOC 2 audits, or ongoing managed hosting by Provider are out of scope unless added in a written amendment signed by both parties.

---

## 2. Deliverables and Timeline (30-Day Pilot Milestones)

| Milestone | Target window | Deliverable |
| --- | --- | --- |
| M1 — Kickoff & environment access | Days 1–3 | Kickoff call (or async intake), environment access confirmed, deployment target selected, BAA status confirmed if required |
| M2 — Deployed instance | Days 4–10 | Hermes Relay running in Client environment; health check passing; signing key configured; zero-egress posture validated for scrub path |
| M3 — Integration & audit chain live | Days 11–20 | At least one Client pipeline path calling scrub/attest; hash-chained attestation receipts generated and verified; optional webhook export configured if requested |
| M4 — Pilot readout | Days 21–30 | Written pilot summary: deployment topology, identifier categories exercised, sample attestation evidence (metadata only — no PHI), recommended production cutover steps |

Pilot fee covers one production-style deployment in a single Client environment for 30 calendar days from the pilot start date. Production subscription terms after the pilot are addressed in Section 3.

---

## 3. Payment Terms

| Item | Amount | When due |
| --- | --- | --- |
| 30-day pilot | **$2,000.00 USD** | Due in full at signing of this SOW |
| PHI AI Readiness Assessment (optional, separate) | $750.00 USD | Due at assessment intake; credited in full toward the pilot if Client proceeds into this SOW |
| Production subscription (after pilot) | $500.00 USD / month | Month-to-month, invoiced at production start; first twelve (12) months lock at the rate in effect at pilot signing |

- Pilot fee of **$2,000 is due at signing**. Work under this SOW begins after Provider receives payment (or written confirmation of payment in process acceptable to Provider).
- Fees are non-refundable once deployment work has commenced, except as required by law or as expressly stated in a signed amendment.
- Production pricing after a successful pilot is month-to-month at $500/month unless the parties execute a superseding order. No enterprise minimum term is required under standard production terms.
- Invoices are payable in USD. Client is responsible for any applicable taxes other than taxes on Provider’s net income.

---

## 4. Client Responsibilities

Client will:

1. Designate a technical contact with authority to grant environment access and approve integration changes.
2. Provide timely access to the deployment target (credentials, network allowances, container/VM host, secrets store as applicable).
3. Ensure Client has authority to process the data used during the pilot and that any HIPAA-covered use is covered by an executed BAA when required.
4. Supply representative (non-production or appropriately authorized) payloads and integration endpoints for testing.
5. Complete security and change-control reviews on Client’s side within the pilot window so milestones are not blocked solely by Client process delays.
6. Retain attestation receipts and operational logs inside Client’s environment; Provider does not host or retain Client PHI.
7. Not reverse engineer, resell, or redistribute Hermes Relay software except as permitted under the license and IP terms in Section 6.

Delays caused by Client’s failure to meet these responsibilities may shift milestone dates without extending Provider’s obligation to deliver beyond a commercially reasonable reschedule within or immediately after the pilot window, unless the parties agree in writing to extend the pilot.

---

## 5. Support Terms

- During the pilot, Client receives **direct support from Andrew Rogers** (Founder & Engineer) via the channel agreed at kickoff (email to andrew@hermesrelay.dev and/or a shared messaging channel).
- Support hours are business hours, U.S. Eastern Time, Monday–Friday, excluding U.S. federal holidays, with best-effort response the same or next business day for pilot-blocking issues.
- Support covers deployment, configuration, API integration, attestation chain verification, and defect triage in the shipped product.
- Support does not include building Client-specific application features, performing Client’s OCR submissions, or acting as Client’s compliance officer.

---

## 6. Intellectual Property Ownership

- **Client owns their deployment.** Configuration files, environment-specific secrets, attestation receipts generated in Client’s environment, and operational data produced by Client’s use of Hermes Relay remain Client’s property. Provider does not claim ownership of Client PHI or Client business data.
- **Sui-Generis LLC owns the software.** Hermes Relay, including source code, binaries, models bundled with the product, documentation authored by Provider, trademarks, and related intellectual property, remain the exclusive property of Sui-Generis LLC (and its licensors, if any).
- Client receives a limited, non-exclusive, non-transferable right to install and use Hermes Relay in Client’s environment for the pilot term (and, if Client purchases production service, for the subscription term) solely for Client’s internal business purposes.
- Client shall not assert ownership of Provider’s software by virtue of hosting it, funding the pilot, or suggesting product improvements. Feedback may be used by Provider to improve the product without obligation to Client.

---

## 7. Termination

- Either party may terminate this SOW for material breach if the other party fails to cure within ten (10) business days after written notice describing the breach.
- Client may terminate for convenience before deployment work begins; if payment has been received and no deployment work has started, Provider will refund the pilot fee less any non-recoverable third-party costs already incurred with Client’s written approval.
- After deployment work has commenced, termination for convenience does not entitle Client to a refund of the pilot fee.
- Provider may suspend services immediately if continuation would violate law or create an unacceptable security risk, and will cooperate in good faith on an orderly wind-down.
- Upon termination or expiration: Client retains its deployment artifacts and attestation receipts in its environment; Provider’s license grant for the pilot ends unless Client has an active production subscription; Provider has no PHI to return or destroy because Hermes Relay is designed so PHI never transits or is retained on Sui-Generis infrastructure (see BAA, if executed).
- Sections 6 (IP), 7 (Termination), and any accrued payment obligations survive termination.

---

## 8. Relationship to Other Documents

- Website commercial terms and product descriptions at https://hermesrelay.dev are informational; this SOW controls for the pilot engagement.
- If a BAA is executed between the parties, the BAA governs Protected Health Information handling obligations to the extent of any conflict with this SOW on HIPAA matters.
- This SOW may be amended only by a written instrument signed by authorized representatives of both parties.

---

## 9. Signature Block

By signing below, each party agrees to the terms of this Statement of Work.

### Sui-Generis LLC

| | |
| --- | --- |
| Signature | ________________________________ |
| Printed name | Andrew Rogers |
| Title | Founder |
| Date | ________________________________ |
| Email | andrew@hermesrelay.dev |

### Client

| | |
| --- | --- |
| Legal name | ________________________________ |
| Signature | ________________________________ |
| Printed name | ________________________________ |
| Title | ________________________________ |
| Date | ________________________________ |
| Email | ________________________________ |

---

*Sui-Generis LLC · Rocky Top, Tennessee · hermesrelay.dev · andrew@hermesrelay.dev*
