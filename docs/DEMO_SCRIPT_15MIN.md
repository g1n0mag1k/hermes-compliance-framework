# Hermes Relay — 15-Minute MSP Demo Script

**Audience:** MSP owner serving HIPAA-covered healthcare clients  
**Duration:** Exactly 15 minutes  
**Presenter prep:** Hermes Relay running at `127.0.0.1:8787`, dashboard open in a second tab, terminal ready with API key exported as `$HERMES_API_KEY`

---

## MINUTES 0–2: THE PROBLEM (no product yet)

**Setup:** Do not show Hermes yet. No slides. No terminal. Just conversation.

Ask these discovery questions **in order**. Wait for their answer after each one. Do not fill the silence.

---

**Question 1:**

> "When one of your healthcare clients uses ChatGPT or Copilot today — what happens if an employee puts a patient name or SSN in the prompt?"

*[Wait. Let them answer.]*

---

**Question 2:**

> "If OCR called you tomorrow and asked you to prove that PHI never reached OpenAI — what would you show them?"

*[Wait. Let them answer.]*

---

**Goal:** Make them say out loud that they have no answer. That's the sale. Do not rescue them. Do not preview the product yet.

When they land on "we don't really have proof" or similar, transition:

> "That's exactly the gap Hermes closes. Let me show you — not tell you."

---

## MINUTES 2–5: THE LIVE SCAN (show don't tell)

**Setup:** Switch to terminal. Hermes must already be running.

### Run this command

```bash
curl -s -X POST http://127.0.0.1:8787/v1/scrub \
  -H "Content-Type: application/json" \
  -H "X-API-Key: $HERMES_API_KEY" \
  -d '{"payload": "Patient: John Smith | SSN: 372-18-5421 | DOB: 1982-03-15 | MRN: 1234567 | Email: john.smith@example.com | Phone: 555-867-5309"}' \
  | python3 -m json.tool
```

**Payload sent (for reference):**

```
Patient: John Smith | SSN: 372-18-5421 | DOB: 1982-03-15 | MRN: 1234567 | Email: john.smith@example.com | Phone: 555-867-5309
```

### Walk through the output — use these exact talking points

Point at **`clean_text`:**

> "PHI is gone. John Smith is now REDACTED_PERSON. The SSN is gone."

Point at **`occurrence_gaps`:**

> "This field proves nothing survived. If any PHI made it through redaction this would catch it and block the request."

Point at **`zero_pii_egress_confirmed`** (inside `compliance_receipt`):

> "This is the field an auditor cares about. True means we can prove nothing left."

Point at **`receipt_hash`** (inside `compliance_receipt`):

> "This is the cryptographic proof. It's chained to every previous scan. Nobody can alter this record without breaking the chain."

**Do not rush.** Let them read the JSON for a few seconds. Answer one question if they ask, then move on.

---

## MINUTES 5–8: THE DASHBOARD

**Setup:** Open `http://127.0.0.1:8787` in the browser (or switch to the tab already open).

### Portfolio view

> "This is what you see across all your healthcare clients. Protection state, PHI coverage, evidence freshness."

Pause. Let them scan the screen.

### Client detail

Click into one client (preferably the workspace you just scanned).

> "16 PHI categories, each mapped to its exact CFR citation. This is what you hand to an auditor."

Scroll slowly through the category list and CFR mappings.

### Trial Scan button

Click **Trial Scan**.

> "Watch this — one click, PHI gets caught, receipt issues, dashboard updates. That's the control working."

Wait for the scan to complete and the dashboard to refresh. Point at the updated evidence timestamp or latest receipt if visible.

### Chain integrity

Point at chain integrity / attestation status on the dashboard.

> "HMAC-SHA256. Independently verifiable without Hermes."

---

## MINUTES 8–11: THE DRATA ANGLE

Ask:

> "Does your client use Drata for compliance automation?"

### If yes

> "Hermes can export metadata-only gateway enforcement evidence to Drata when you configure `HERMES_DRATA_CCT_URL`. The adapter is implemented and contract-tested; we validate live tenant connectivity during design-partner onboarding — I won't claim live Drata sync until we've run it in your environment."

Optional: If you have a validated Drata sandbox, show a gateway enforcement record. Otherwise show the Hermes receipt and `EvidenceEvent` schema from docs.

### If no

> "We can push metadata-only evidence to any webhook — Splunk, your SIEM, a compliance portal. No prompts, no PHI values, just decision + policy digest + receipt digest."

**Bridge to pilot:**

> "Either way, enforcement receipts are signed and hash-chained locally. Export is optional, best-effort, and never affects whether Hermes blocks or forwards."

---

## MINUTES 11–13: THE PILOT OFFER

Deliver this offer **verbatim** (adjust pacing, not wording):

> "Here's what I'm proposing. 30-Day Assurance Sprint — free. One of your healthcare clients, one defined AI workflow, I deploy it personally, weekly feedback call. No obligation.
>
> If at day 30 you can show me a real problem it solved and identify who would pay for it — we move to a 90-day design partner pilot at $1,500 a month. That's $4,500 total, credited toward an annual agreement if you convert.
>
> I'm taking 3 design partners total. Two spots left."

Pause. Do not negotiate yet. Let it land.

---

## MINUTES 13–15: OBJECTION HANDLING

Handle only what they raise. If they raise nothing, pick the two most likely (DLP tool + not using AI). Use these **exact responses**:

---

### Objection 1: "We already have Nightfall / Purview / another DLP tool"

> "Those tools scan data after it reaches a cloud API. PHI leaves your client's environment before it gets scanned. Hermes enforces at the transmission boundary — PHI never reaches the AI provider. And we produce a signed receipt proving that for every single request. Can your current tool do that?"

---

### Objection 2: "Our clients aren't using AI yet"

> "They are. Their employees are using ChatGPT on personal phones and work laptops right now without telling anyone. The question isn't whether they're using AI — it's whether you can prove controls were in place when they did."

---

### Objection 3: "This sounds complex to deploy"

> "I deploy it personally as part of the sprint. One command on the client's machine. I handle everything. Your team touches nothing until we've proven value."

---

### Objection 4: "What if the product isn't ready?"

> "I've been running it on my own machine since September 14th. Every scan I run generates a real receipt in a real attestation chain. The product you're seeing is the product I'm offering."

---

### Objection 5: "We need to involve our client"

> "Good. That means you see value. Let's schedule a 20-minute call with them this week. I'll run the demo live for them the same way I just ran it for you."

---

## CLOSING LINE

Deliver this line. Then **stop talking.**

> "The only question is whether one of your healthcare clients should be the first to have this kind of proof. Who comes to mind?"

*[Silence. Let them answer.]*

---

## POST-DEMO FOLLOW-UP CHECKLIST

Send within **24 hours** of the demo:

- [ ] Design partner brief PDF
- [ ] Dashboard screenshots (portfolio view **and** client detail view)
- [ ] Link to [hermesrelay.dev](https://hermesrelay.dev)
- [ ] One-line summary of what they said in the demo (capture their words about the OCR/audit gap or named client)
- [ ] Calendar link for the 30-day sprint kickoff call

---

## Presenter Notes

| Segment | Time | Key success signal |
|---------|------|-------------------|
| Problem | 0–2 min | They admit they can't prove PHI never left |
| Live scan | 2–5 min | They see `zero_pii_egress_confirmed: true` |
| Dashboard | 5–8 min | They react to CFR citations or Trial Scan |
| Drata | 8–11 min | They connect evidence to their compliance stack |
| Pilot offer | 11–13 min | They ask about a specific client or timeline |
| Close | 13–15 min | They name a client or agree to a follow-up call |

**Before the meeting:** Export `HERMES_API_KEY`, confirm gateway at `:8788` and scrub API at `:8787`, refresh dashboard so portfolio view looks populated. Queue Drata tab only if they use Drata **and** you are demoing `/v1/scrub` (gateway receipts are local-only today).

---

## Gateway demo addendum (minutes 5–12 when showing inline enforcement)

**Quick scripted demo (recommended):**

```bash
.venv/bin/python gateway/demo.py
```

Shows scenarios A–D with `upstream.request_count` after each step (embedded mock upstream; synthetic data only).

Run gateway on `:8788` with workspace API key `$GATEWAY_API_KEY` for live curl demos below.

### 1. Clean request — what Hermes sends

```bash
curl -s -X POST http://127.0.0.1:8788/gateway/openai/v1/chat/completions \
  -H "X-API-Key: $GATEWAY_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o","messages":[{"role":"user","content":"Explain HIPAA minimum necessary."}]}'
```

> "Here is what Hermes sends — unchanged clean content reaches the provider."

### 2. PHI + REDACT (default HIPAA_STRICT)

```bash
curl -s -X POST http://127.0.0.1:8788/gateway/openai/v1/chat/completions \
  -H "X-API-Key: $GATEWAY_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o","messages":[{"role":"user","content":"Patient SSN is 123-45-6789"}]}'
```

> "Here is what Hermes sends — SSN redacted to `[REDACTED_SSN]`. Hermes default policy redacts; blocking is a separate explicit policy."

### 3. PHI + BLOCK (design-partner profile)

Set `HERMES_GATEWAY_POLICY=HIPAA_PRODUCTION_BLOCK` or workspace BLOCK policy.

```bash
curl -s -X POST http://127.0.0.1:8788/gateway/openai/v1/chat/completions \
  -H "X-API-Key: $GATEWAY_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"model":"gpt-4o","messages":[{"role":"user","content":"Patient SSN is 123-45-6789"}]}'
```

> "Here is what Hermes blocks — HTTP 403, upstream receives nothing. Receipt shows `forwarded: false`."

### 4. Receipt verification

Export latest receipt COSE bytes from workspace SQLite and run:

```bash
hermes-verify receipt receipt.cose --public-key gateway-public.pem
```

> "Here is how you independently verify that evidence — VALID or INVALID with policy digest and decision, no PHI values exposed."
