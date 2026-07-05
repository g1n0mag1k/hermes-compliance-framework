"use client";

import { useState } from "react";

const TRUST_SIGNALS: readonly string[] = [
  "Zero-egress architecture",
  "Data never leaves your environment",
  "SHA-256 independently verifiable",
  "Safe Harbor-aligned — building toward 45 CFR §164.514(b)",
  "BAA available upon request",
];

export function CTA() {
  const [submitted, setSubmitted] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(false);

  async function handleSubmit(e: React.FormEvent<HTMLFormElement>) {
    e.preventDefault();
    setLoading(true);
    setError(false);
    const form = e.currentTarget;
    const data = new FormData(form);
    try {
      const response = await fetch("https://formspree.io/f/xnjkdrar", {
        method: "POST",
        body: data,
        headers: { Accept: "application/json" },
      });
      if (!response.ok) {
        throw new Error(`Formspree returned ${response.status}`);
      }
      setSubmitted(true);
    } catch (err) {
      console.error("Pilot request submission failed:", err);
      setError(true);
    } finally {
      setLoading(false);
    }
  }

  return (
    <section
      data-section="cta" id="pilot"
      className="bg-void px-6 sm:px-8 lg:px-10 py-section"
    >
      <div className="w-full max-w-content mx-auto flex flex-col items-center text-center">
        <h2 className="font-display text-h2 text-ink">
          One pilot.
          <br />
          Your environment.
          <br />
          Your audit chain.
        </h2>
        <p className="font-body text-body text-muted mt-8 max-w-[500px]">
          Hermes is currently accepting design partners for remote pilots. 30-day engagement, your infrastructure, full hash-chained audit evidence record from day one.
        </p>

        {submitted ? (
          <div className="mt-10 border border-signal px-8 py-6 max-w-[500px] w-full text-left">
            <p className="font-display text-h3 text-signal">Request received.</p>
            <p className="font-body text-body text-muted mt-2">
              Andrew will follow up at your email within 24 hours.
            </p>
          </div>
        ) : (
          <>
          {error && (
            <div className="mt-10 border border-warn px-8 py-6 max-w-[500px] w-full text-left">
              <p className="font-display text-h3 text-warn">Something went wrong.</p>
              <p className="font-body text-body text-muted mt-2">
                Your request did not go through. Please try again, or email{" "}
                <a href="mailto:andrew@hermesrelay.dev" className="text-signal hover:text-ink transition-colors">
                  andrew@hermesrelay.dev
                </a>{" "}
                directly.
              </p>
            </div>
          )}
          <form
            onSubmit={handleSubmit}
            className="mt-10 w-full max-w-[500px] flex flex-col gap-4 text-left"
          >
            <div className="flex flex-col gap-1">
              <label className="font-mono text-caption text-muted uppercase tracking-widest">
                Name
              </label>
              <input
                type="text"
                name="name"
                required
                placeholder="Jane Smith"
                className="bg-transparent border border-muted text-ink font-body text-body px-4 py-3 focus:outline-none focus:border-signal placeholder:text-muted/40"
              />
            </div>
            <div className="flex flex-col gap-1">
              <label className="font-mono text-caption text-muted uppercase tracking-widest">
                Company
              </label>
              <input
                type="text"
                name="company"
                required
                placeholder="Acme MSP"
                className="bg-transparent border border-muted text-ink font-body text-body px-4 py-3 focus:outline-none focus:border-signal placeholder:text-muted/40"
              />
            </div>
            <div className="flex flex-col gap-1">
              <label className="font-mono text-caption text-muted uppercase tracking-widest">
                Work Email
              </label>
              <input
                type="email"
                name="email"
                required
                placeholder="andrew@hermesrelay.dev"
                className="bg-transparent border border-muted text-ink font-body text-body px-4 py-3 focus:outline-none focus:border-signal placeholder:text-muted/40"
              />
            </div>
            <div className="flex flex-col gap-1">
              <label className="font-mono text-caption text-muted uppercase tracking-widest">
                Phone <span className="normal-case text-muted/60">(optional)</span>
              </label>
              <input
                type="tel"
                name="phone"
                placeholder="(555) 000-0000"
                className="bg-transparent border border-muted text-ink font-body text-body px-4 py-3 focus:outline-none focus:border-signal placeholder:text-muted/40"
              />
            </div>
            <div className="flex flex-col gap-1">
              <label className="font-mono text-caption text-muted uppercase tracking-widest">
                Anything we should know? <span className="normal-case text-muted/60">(optional)</span>
              </label>
              <textarea
                name="message"
                rows={3}
                placeholder="Current AI tooling, PHI workflows, timeline, specific compliance concerns..."
                className="bg-transparent border border-muted text-ink font-body text-body px-4 py-3 focus:outline-none focus:border-signal placeholder:text-muted/40 resize-none"
              />
            </div>
            <button
              type="submit"
              disabled={loading}
              className="mt-2 bg-signal text-void font-display font-bold text-body sm:text-h3 px-6 sm:px-10 py-4 sm:py-5 border-2 border-signal hover:bg-ink hover:border-ink transition-colors disabled:opacity-50"
            >
              {loading ? "Sending…" : "Request the Pilot Program"}
            </button>
          </form>
          </>
        )}

        <p className="font-mono text-caption text-muted mt-10 break-words max-w-full">
          {TRUST_SIGNALS.join("  ·  ")}
        </p>
      </div>
    </section>
  );
}
