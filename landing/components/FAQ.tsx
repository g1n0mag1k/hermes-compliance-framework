/* ---------------------------------------------------------------------------
 * FAQ -- objection-handling section. Answers the questions a technical
 * buyer or compliance-literate evaluator will actually ask, with the same
 * honesty/precision the rest of the page uses. No hedge-free overclaiming.
 * ------------------------------------------------------------------------- */

type FAQItem = {
  question: string;
  answer: string;
};

const FAQS: readonly FAQItem[] = [
  {
    question: "What happens if Hermes misses a PHI identifier -- a false negative?",
    answer:
      "No automated PHI redaction system achieves perfect recall, and Hermes does not claim certified Safe Harbor de-identification or blanket HIPAA compliance. Hermes detects the following categories: person names, dates, organizations, phone numbers, email addresses, URLs, IP addresses, physical addresses/locations, US bank numbers, Social Security numbers, and payment card numbers (Luhn-validated). Treat it as a strong first layer for PHI reduction, not a substitute for your risk assessment or human review on high-stakes payloads. The cryptographically signed attestation receipt records exactly which of those categories were flagged and redacted for a given transaction — tamper-evident proof of what happened, not a vague compliance claim.",
  },
  {
    question: "Why not just use an enterprise LLM contract with a BAA already in place?",
    answer:
      "An enterprise BAA with OpenAI, Anthropic, or Microsoft covers how that vendor handles PHI once it reaches them -- it does not produce a record proving what PHI was in the payload in the first place, or that it was identified and handled correctly before transmission. Hermes runs before that call, inside your environment, and produces the CFR-cited evidence trail a BAA alone does not generate. The two are complementary, not competing.",
  },
  {
    question: "Do you have SOC 2 or a cyber insurance policy today?",
    answer:
      "Not yet. Hermes is a solo-founder, pre-revenue project moving through pilot engagements now. SOC 2 Type II requires 6-12 months of sustained evidence collection and an independent audit, and is on the roadmap once there is a customer base to audit against. If your organization's vendor risk process requires either as a hard gate today, say so early -- it may mean waiting for a later stage of the product rather than the current pilot.",
  },
  {
    question: "What's the incident response process if something goes wrong?",
    answer:
      "Because Hermes runs entirely inside your environment with zero external calls during scrubbing, an incident involving Hermes itself has a narrower blast radius than a cloud-classifier failure would -- there is no third-party breach surface to notify about. That said, a formal, documented incident response plan matched to your organization's specific deployment is part of the pilot onboarding conversation, not something we hand you generically off a template.",
  },
  {
    question: "Is Hermes a replacement for our compliance officer or MSP's judgment?",
    answer:
      "No. Hermes produces evidence -- a cryptographically verifiable record of what PHI was detected, under which regulation, and what happened to it. It does not replace the judgment calls a compliance officer or MSP makes about risk tolerance, client communication, or regulatory strategy. Think of it as the evidence layer underneath those decisions, not a substitute for making them.",
  },
  {
    question: "What happens to data if we stop using Hermes?",
    answer:
      "PHI is redacted in-flight and never stored, not even encrypted — so there is no PHI store to delete when a pilot or contract ends. Hash-chained attestation receipts (which contain metadata about what was detected, not the PHI itself) remain in your environment and are yours to keep, export, or discard.",
  },
];

export function FAQ() {
  return (
    <section
      id="faq"
      data-section="faq"
      className="px-6 sm:px-8 lg:px-10 py-section border-t-2 border-border"
    >
      <div className="w-full max-w-content mx-auto">

        <p className="font-mono text-mono text-muted uppercase tracking-[0.1em]">
          Before you ask
        </p>
        <h2 className="font-display text-h2 text-ink mt-8 max-w-[26ch]">
          The questions a careful
          <br />
          evaluator asks first.
        </h2>

        <div className="mt-16 flex flex-col">
          {FAQS.map((faq, i) => (
            <div key={faq.question} className={`border-t-2 border-border pt-8 pb-10 ${i === FAQS.length - 1 ? "" : ""}`}>
              <h3 className="font-display font-semibold text-ink text-[1.0625rem] leading-snug max-w-[60ch]">
                {faq.question}
              </h3>
              <p className="font-body text-body text-muted mt-4 max-w-[68ch]">
                {faq.answer}
              </p>
            </div>
          ))}
        </div>

      </div>
    </section>
  );
}
