# Business Associate Agreement
## Hermes Relay — HIPAA Business Associate Agreement

**Document type:** Business Associate Agreement (BAA)  
**Product:** Hermes Relay — zero-egress PHI redaction API with hash-chained attestation  
**Business Associate:** Sui-Generis LLC  
**Business Associate address:** Rocky Top, Tennessee  
**Business Associate contact:** Andrew Rogers, Founder — andrew@hermesrelay.dev  
**Business Associate website:** https://hermesrelay.dev  
**Repository reference:** https://github.com/g1n0mag1k/hermes-compliance-framework  

| Field | Value |
| --- | --- |
| BAA effective date | ________________________ |
| Covered Entity / Client legal name (“Covered Entity”) | ________________________ |
| Covered Entity address | ________________________ |
| Covered Entity primary contact | ________________________ |
| Covered Entity email | ________________________ |
| Related SOW / order reference (if any) | ________________________ |

This Business Associate Agreement (“Agreement”) is entered into by and between the Covered Entity named above and **Sui-Generis LLC** (“Business Associate”). This Agreement is intended to satisfy the requirements of the Health Insurance Portability and Accountability Act of 1996 and its implementing regulations, including the Privacy, Security, and Breach Notification Rules at 45 CFR Parts 160 and 164 (collectively, “HIPAA”), as applicable to the parties’ relationship in connection with Hermes Relay.

**Availability:** A BAA is available upon request and is required for HIPAA-covered deployments of Hermes Relay.

---

## 1. Definitions

Capitalized terms not defined in this Agreement have the meanings set forth in HIPAA.

- **Protected Health Information (PHI)** means Individually Identifiable Health Information transmitted or maintained in any form or medium, as defined at 45 CFR §160.103.
- **Hermes Relay** means the zero-egress PHI redaction API with hash-chained attestation provided by Business Associate for installation and operation in Covered Entity’s (or its MSP customer’s) environment.
- **Services** means deployment support, integration guidance, audit-chain setup assistance, and related commercial support described in the applicable Statement of Work or order, together with Covered Entity’s licensed use of Hermes Relay software.

---

## 2. Permitted Uses and Disclosures

2.1 Business Associate may Use or Disclose PHI only as permitted or required by this Agreement, as Required by Law, or as necessary to perform the Services for or on behalf of Covered Entity.

2.2 Permitted purposes are limited to:

- Assisting Covered Entity (or its designated MSP) with installation, configuration, troubleshooting, and verification of Hermes Relay in Covered Entity’s environment;
- Advising on attestation-chain setup, API integration, and operational use of redaction and audit features;
- Supporting incident triage related to the Hermes Relay software itself, using only the minimum necessary information and, wherever feasible, de-identified examples, logs that contain no PHI, or screen-shares controlled by Covered Entity.

2.3 Business Associate shall not Use or Disclose PHI in a manner that would violate the Privacy Rule if done by Covered Entity, except as expressly permitted for Business Associates under HIPAA and this Agreement.

2.4 Business Associate shall not Use PHI for marketing, sale of PHI, or any purpose outside the Services, and shall not Disclose PHI to third parties except as permitted by this Agreement, Required by Law, or with Covered Entity’s prior written authorization consistent with HIPAA.

2.5 If Business Associate provides PHI to a subcontractor, Business Associate shall ensure the subcontractor agrees in writing to the same restrictions and conditions that apply to Business Associate with respect to such PHI. Business Associate’s standard Hermes Relay architecture does not require subcontractors to receive PHI (see Section 3).

---

## 3. Zero-Egress Architecture Clause

3.1 **Architectural commitment.** Hermes Relay is designed and documented to run entirely inside Covered Entity’s (or Covered Entity’s MSP customer’s) environment. During scrubbing and attestation operations, PHI is redacted in-flight and is not transmitted to Sui-Generis LLC systems for classification, storage, or processing.

3.2 **PHI never transits Sui-Generis infrastructure.** Under the intended deployment model:

- PHI payloads submitted to Hermes Relay remain on infrastructure Controlled by Covered Entity (or its MSP);
- Business Associate does not operate a multi-tenant cloud classifier that receives Covered Entity PHI;
- Attestation receipts record categories detected and redacted and related cryptographic metadata — not the underlying PHI content;
- Business Associate’s support model is remote assistance to Covered Entity’s deployment, not ingestion of PHI into Business Associate-hosted databases or object stores.

3.3 **Support boundary.** Covered Entity agrees not to email, upload, or otherwise transmit PHI to andrew@hermesrelay.dev, Sui-Generis ticketing systems, or other Business Associate channels. If Covered Entity inadvertently transmits PHI to Business Associate, Business Associate will notify Covered Entity, limit further Use to breach assessment and return/secure disposal instructions, and not retain such PHI longer than necessary for that purpose.

3.4 This Section describes product architecture and contractual obligations between the parties. It does not constitute a certification of HIPAA Safe Harbor de-identification under 45 CFR §164.514(b), nor a substitute for Covered Entity’s own risk analysis and policies.

---

## 4. Safeguards Obligations

4.1 Business Associate shall implement appropriate administrative, physical, and technical safeguards that reasonably and appropriately protect the confidentiality, integrity, and availability of Electronic PHI that Business Associate creates, receives, maintains, or transmits on behalf of Covered Entity, in accordance with the Security Rule (45 CFR Part 164, Subpart C).

4.2 Given the zero-egress design, Business Associate’s primary safeguards for Hermes Relay PHI risk include:

- Designing and maintaining software so that scrubbing does not require PHI egress to Business Associate infrastructure;
- Protecting Business Associate’s own source repositories, signing-key guidance, documentation, and support systems against unauthorized access;
- Using least-privilege practices when accessing Covered Entity systems solely at Covered Entity’s invitation for deployment or support;
- Refraining from copying PHI out of Covered Entity environments during support sessions.

4.3 Covered Entity remains responsible for safeguards within its own environment, including access control, encryption in transit and at rest for systems it operates, workforce training, and retention of attestation receipts.

4.4 Business Associate shall ensure that any workforce member who may have access to PHI (for example, during an inadvertent disclosure or invited troubleshooting session) is subject to appropriate confidentiality obligations and minimum-necessary practices.

---

## 5. Reporting Obligations

5.1 **Security Incident.** Business Associate shall report to Covered Entity any Security Incident of which it becomes aware involving PHI Created, Received, Maintained, or Transmitted by Business Associate on behalf of Covered Entity, in accordance with 45 CFR §164.314(a)(2)(i)(C). Unsuccessful, routine attempts that do not result in unauthorized access (such as pings or port scans against Business Associate’s public website) need not be reported individually if they are logged and available on request.

5.2 **Breach of Unsecured PHI.** Business Associate shall notify Covered Entity without unreasonable delay, and in no case later than sixty (60) calendar days after Discovery, of any Breach of Unsecured PHI that Business Associate accesses, maintains, retains, modifies, records, stores, destroys, or otherwise holds, Uses, or Discloses in violation of this Agreement or HIPAA, consistent with 45 CFR §164.410.

5.3 Breach notices will include, to the extent known: a description of what happened; the date of the Breach and date of Discovery; the types of PHI involved; steps individuals should take; what Business Associate is doing to investigate and mitigate; and contact procedures for more information.

5.4 Because Hermes Relay is designed so PHI does not transit or reside on Sui-Generis infrastructure, reportable Breaches attributable to Business Associate’s custody of PHI are expected to be limited to inadvertent support-channel disclosures or other exceptional events — not routine product operation.

5.5 Business Associate shall mitigate, to the extent practicable, any harmful effect of a Use or Disclosure of PHI in violation of this Agreement known to Business Associate.

---

## 6. Term and Termination

6.1 **Term.** This Agreement begins on the BAA effective date above and continues until terminated as provided herein, or until all Services involving PHI under the related commercial relationship have ended and obligations that survive termination are satisfied.

6.2 **Termination for cause.** Either party may terminate this Agreement if the other party materially breaches HIPAA-related obligations and fails to cure within thirty (30) days after written notice (or immediately if cure is not possible).

6.3 **Termination tied to Services.** If the related SOW or production subscription ends, this Agreement terminates when Business Associate no longer requires PHI access to perform Services — which, under the zero-egress model, typically means Business Associate never held a PHI repository to unwind.

6.4 **Effect of termination.** Upon termination, Business Associate shall return or destroy PHI as set forth in Section 7, continue to protect any PHI that cannot be returned or destroyed, and cease Uses and Disclosures of PHI except as Required by Law or as permitted for wind-down.

6.5 Provisions regarding PHI protection, breach reporting, and limitations that by their nature should survive will survive termination of this Agreement.

---

## 7. Return or Destruction of PHI

7.1 **Not applicable to product data flows — zero retention architecture.** Hermes Relay redacts PHI in-flight inside Covered Entity’s environment and does not store PHI — not even encrypted — on Sui-Generis LLC infrastructure. Attestation receipts retained in Covered Entity’s environment contain metadata about categories detected and redacted, not the PHI itself, and remain under Covered Entity’s control.

7.2 Accordingly, for routine operation of Hermes Relay there is **no Business Associate-held PHI repository to return or destroy** at end of engagement.

7.3 If Business Associate nonetheless Comes into possession of PHI (for example, inadvertent email attachment or paste into a support channel), Business Associate shall, at Covered Entity’s direction and within a reasonable time after termination or upon Covered Entity’s earlier request: (a) return the PHI to Covered Entity, or (b) destroy the PHI and confirm destruction in writing, unless Required by Law to retain a copy. If return or destruction is infeasible, Business Associate shall limit further Uses and Disclosures to those that make return or destruction infeasible and shall continue to protect such PHI.

7.4 Covered Entity is solely responsible for retention, export, archival, or deletion of attestation receipts and logs stored in Covered Entity’s environment.

---

## 8. Additional HIPAA Assurances

8.1 Business Associate shall make available PHI in a Designated Record Set as necessary for Covered Entity to meet an individual’s access or amendment rights under 45 CFR §§164.524 and 164.526, to the limited extent Business Associate maintains such a Designated Record Set — which it does not under the standard Hermes Relay architecture.

8.2 Business Associate shall make its internal practices, books, and records relating to the Use and Disclosure of PHI received from, or created or received by Business Associate on behalf of, Covered Entity available to the Secretary of Health and Human Services for purposes of determining Covered Entity’s or Business Associate’s compliance with HIPAA.

8.3 Business Associate shall document Disclosures of PHI as required for Covered Entity’s accounting of disclosures obligations under 45 CFR §164.528, to the extent Business Associate makes such Disclosures.

---

## 9. Miscellaneous

9.1 This Agreement is governed by HIPAA and, to the extent not preempted, the laws of the State of Tennessee, without regard to conflict-of-law rules.

9.2 Nothing in this Agreement confers third-party beneficiary rights except as HIPAA requires.

9.3 If any provision is held unenforceable, the remainder continues in effect.

9.4 This Agreement may be executed in counterparts (including electronic signature), each of which is deemed an original.

9.5 Amendments must be in writing and signed by both parties, except that the parties shall amend this Agreement as needed to comply with material changes in HIPAA.

---

## 10. Signature Block

By signing below, each party agrees to be bound by this Business Associate Agreement.

### Sui-Generis LLC (Business Associate)

| | |
| --- | --- |
| Signature | ________________________________ |
| Printed name | Andrew Rogers |
| Title | Founder |
| Date | ________________________________ |
| Email | andrew@hermesrelay.dev |

### Covered Entity (Client)

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
*BAA available upon request. Required for HIPAA-covered deployments.*
