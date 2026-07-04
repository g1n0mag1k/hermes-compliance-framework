/* ---------------------------------------------------------------------------
 * Assessment — dedicated landing page for the PHI AI Readiness Assessment
 * consulting offer at hermesrelay.dev/assessment.
 * ------------------------------------------------------------------------- */

import type { Metadata } from "next";
import Link from "next/link";

const CALENDLY_URL = "https://calendly.com/hermes/phi-readiness-assessment";

const DELIVERABLES = [
  {
    title: "AI Tool Inventory",
    description:
      "A complete map of every AI tool, API, and workflow touching PHI in your environment — including shadow IT your team forgot to document.",
  },
  {
    title: "PHI Exposure Map",
    description:
      "Where PHI enters, moves through, and exits your AI stack. Every handoff point where data could leak to a third party or leave your environment.",
  },
  {
    title: "Safe Harbor Gap Analysis",
    description:
      "Your current controls measured against all 18 identifier categories in 45 CFR §164.514(b). Gaps ranked by enforcement exposure, not theoretical risk.",
  },
  {
    title: "Remediation Roadmap",
    description:
      "Prioritized action items with estimated effort and compliance impact. What to fix first, what can wait, and what Hermes handles out of the box.",
  },
] as const;

const WHO_ITS_FOR = [
  "MSPs managing HIPAA-covered clients who added AI tools without a compliance review",
  "Billing companies, RCM firms, and healthcare SaaS teams using ChatGPT, Copilot, or custom LLM integrations",
  "Founders and ops leads who need a written gap analysis before their cyber insurer or auditor asks",
  "Teams evaluating the Hermes pilot who want to know their exposure before committing",
] as const;

const WHY_ANDREW = [
  "Built Hermes — zero-egress PHI redaction with SHA-256 hash-chained audit records",
  "Deep familiarity with 45 CFR §164.514(b) Safe Harbor and OCR enforcement patterns",
  "15 years in healthcare IT, MSP operations, and compliance infrastructure",
  "No sales team — you work directly with the engineer who built the product",
] as const;

export const metadata: Metadata = {
  title: "PHI AI Readiness Assessment — Hermes",
  description:
    "A 45-minute working session that maps your AI stack's PHI exposure, scores your Safe Harbor gaps, and delivers a remediation roadmap. $297 limited launch rate.",
  alternates: {
    canonical: "https://hermesrelay.dev/assessment",
  },
  openGraph: {
    title: "PHI AI Readiness Assessment — Hermes",
    description:
      "A 45-minute working session that maps your AI stack's PHI exposure, scores your Safe Harbor gaps, and delivers a remediation roadmap.",
    url: "https://hermesrelay.dev/assessment",
    siteName: "Hermes",
    type: "website",
  },
};

function BookButton({ className = "" }: { className?: string }) {
  return (
    <a
      href={CALENDLY_URL}
      target="_blank"
      rel="noopener noreferrer"
      className={`inline-block bg-signal text-void font-display font-bold text-body px-8 py-4 border-2 border-signal hover:bg-ink hover:border-ink transition-colors ${className}`}
    >
      Book Your Spot
    </a>
  );
}

export default function AssessmentPage() {
  return (
    <main className="flex flex-col min-h-screen">
      {/* Nav */}
      <nav className="border-b-2 border-border px-6 sm:px-8 lg:px-10 py-5">
        <div className="w-full max-w-content mx-auto flex items-center justify-between">
          <Link
            href="/"
            className="font-display text-h3 text-ink hover:text-signal transition-colors"
          >
            Hermes
          </Link>
          <Link
            href="/"
            className="font-mono text-mono text-muted hover:text-signal transition-colors"
          >
            {"←"} Back to main site
          </Link>
        </div>
      </nav>

      {/* Hero */}
      <section
        data-section="hero"
        className="px-6 sm:px-8 lg:px-10 py-section"
      >
        <div className="w-full max-w-content mx-auto">
          <p className="font-mono text-mono text-signal uppercase tracking-[0.1em]">
            PHI AI Readiness Assessment
          </p>
          <h1 className="font-display text-hero text-ink mt-8 max-w-[20ch]">
            Know exactly where your AI stack is leaking PHI.
          </h1>
          <p className="font-body text-body text-muted mt-8 max-w-[58ch]">
            A 45-minute working session with Andrew. You walk through your
            current AI tooling, PHI workflows, and existing controls — and
            leave with a written deliverable package mapping your exposure,
            Safe Harbor gaps, and remediation priorities. No questionnaire.
            No waiting five days. Live, focused, and actionable.
          </p>

          <div className="mt-12 border-2 border-signal bg-surface px-8 py-8 max-w-[480px]">
            <div className="flex items-baseline gap-3">
              <span className="font-display text-h1 text-ink">$297</span>
              <span className="font-mono text-mono text-signal uppercase tracking-[0.1em]">
                Limited Launch Rate
              </span>
            </div>
            <ul className="mt-6 flex flex-col gap-2">
              {[
                "45 minutes — live working session",
                "3 spots available at this rate",
                "Full credit toward the Hermes pilot if you proceed",
              ].map((item) => (
                <li
                  key={item}
                  className="flex items-start gap-3 font-mono text-[12px] text-muted"
                >
                  <span className="text-signal mt-0.5 shrink-0">{"→"}</span>
                  <span>{item}</span>
                </li>
              ))}
            </ul>
          </div>

          <div className="mt-10 flex flex-col items-start gap-4">
            <BookButton />
            <p className="font-mono text-caption text-muted max-w-[480px]">
              After booking, send $297 via Venmo (@hermesrelay) or Cash App
              ($hermesrelay) to confirm your spot. Include your company name
              in the payment note.
            </p>
          </div>
        </div>
      </section>

      {/* Deliverables */}
      <section
        data-section="deliverables"
        className="px-6 sm:px-8 lg:px-10 py-section border-t-2 border-border"
      >
        <div className="w-full max-w-content mx-auto">
          <p className="font-mono text-mono text-muted uppercase tracking-[0.1em]">
            What you get
          </p>
          <h2 className="font-display text-h2 text-ink mt-8 max-w-[24ch]">
            Four deliverables.
            <br />
            One session.
          </h2>
          <p className="font-body text-body text-muted mt-6 max-w-[55ch]">
            Everything is documented in writing during and immediately after
            the session — formatted for your cyber insurer, auditor, or
            internal compliance review.
          </p>

          <div className="mt-16 grid gap-6 md:grid-cols-2">
            {DELIVERABLES.map((item) => (
              <div
                key={item.title}
                className="flex flex-col px-8 py-8 border-2 border-border bg-surface"
              >
                <p className="font-mono text-mono text-signal uppercase tracking-[0.1em]">
                  {item.title}
                </p>
                <p className="font-body text-body text-muted mt-4">
                  {item.description}
                </p>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Who it's for / Why Andrew */}
      <section
        data-section="audience"
        className="px-6 sm:px-8 lg:px-10 py-section border-t-2 border-border"
      >
        <div className="w-full max-w-content mx-auto grid gap-16 md:grid-cols-2">
          <div>
            <p className="font-mono text-mono text-muted uppercase tracking-[0.1em]">
              Who it&apos;s for
            </p>
            <h2 className="font-display text-h3 text-ink mt-6">
              Built for teams shipping AI before compliance catches up.
            </h2>
            <ul className="mt-8 flex flex-col gap-3">
              {WHO_ITS_FOR.map((item) => (
                <li
                  key={item}
                  className="flex items-start gap-3 font-mono text-[12px] text-muted"
                >
                  <span className="text-signal mt-0.5 shrink-0">{"→"}</span>
                  <span>{item}</span>
                </li>
              ))}
            </ul>
          </div>

          <div>
            <p className="font-mono text-mono text-muted uppercase tracking-[0.1em]">
              Why Andrew
            </p>
            <h2 className="font-display text-h3 text-ink mt-6">
              Not a consultant who read the HIPAA FAQ.
            </h2>
            <ul className="mt-8 flex flex-col gap-3">
              {WHY_ANDREW.map((item) => (
                <li
                  key={item}
                  className="flex items-start gap-3 font-mono text-[12px] text-muted"
                >
                  <span className="text-signal mt-0.5 shrink-0">{"→"}</span>
                  <span>{item}</span>
                </li>
              ))}
            </ul>
          </div>
        </div>
      </section>

      {/* Pilot bridge */}
      <section
        data-section="pilot-bridge"
        className="px-6 sm:px-8 lg:px-10 py-section border-t-2 border-border"
      >
        <div className="w-full max-w-content mx-auto">
          <p className="font-mono text-mono text-signal uppercase tracking-[0.1em]">
            Pilot bridge
          </p>
          <h2 className="font-display text-h2 text-ink mt-8 max-w-[28ch]">
            The $297 applies in full toward the pilot.
          </h2>
          <p className="font-body text-body text-muted mt-6 max-w-[58ch]">
            If you proceed to the Hermes pilot after the assessment, the
            entire $297 fee is credited toward the $2,000 pilot engagement.
            You&apos;re not paying twice — you&apos;re de-risking the pilot
            decision with a clear picture of your exposure first.
          </p>

          <div className="mt-10 bg-signal-dim border-l-2 border-signal px-8 py-7 max-w-[640px]">
            <p className="font-body text-body text-ink">
              Assessment → written gap analysis → informed pilot decision.
              Most teams discover 2–3 critical exposure points they didn&apos;t
              know existed. The pilot then targets those gaps directly.
            </p>
          </div>
        </div>
      </section>

      {/* Bottom CTA */}
      <section
        data-section="cta"
        className="bg-void px-6 sm:px-8 lg:px-10 py-section border-t-2 border-border"
      >
        <div className="w-full max-w-content mx-auto flex flex-col items-center text-center">
          <h2 className="font-display text-h2 text-ink">
            Three spots.
            <br />
            $297 each.
            <br />
            Full pilot credit.
          </h2>
          <p className="font-body text-body text-muted mt-8 max-w-[500px]">
            Book a 45-minute session, send payment via Venmo or Cash App,
            and get a written PHI exposure analysis before your next audit
            or insurance renewal.
          </p>
          <div className="mt-10 flex flex-col items-center gap-4">
            <BookButton className="sm:text-h3 sm:px-10 sm:py-5" />
            <p className="font-mono text-caption text-muted">
              Venmo @hermesrelay · Cash App $hermesrelay
            </p>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer
        data-section="footer"
        className="border-t-2 border-border bg-void px-6 sm:px-8 lg:px-10 py-8"
      >
        <div className="w-full max-w-content mx-auto flex flex-col md:flex-row md:justify-between items-center gap-3 md:gap-6 font-mono text-caption text-muted">
          <span>© 2026 Sui-Generis LLC</span>
          <div className="flex flex-wrap items-center justify-center gap-4 md:gap-6">
            <Link href="/privacy" className="hover:text-signal transition-colors">
              Privacy Policy
            </Link>
            <Link href="/" className="hover:text-signal transition-colors">
              hermesrelay.dev
            </Link>
          </div>
        </div>
      </footer>
    </main>
  );
}
