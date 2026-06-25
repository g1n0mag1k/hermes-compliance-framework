/* ---------------------------------------------------------------------------
 * Hero — full-viewport, two-column on desktop, stacked on mobile.
 *
 * Left column communicates the proposition (eyebrow, headline, subheadline,
 * primary + secondary CTA, trust line). Right column shows the proposition
 * in motion: a terminal-style ticker streaming simulated, hash-chained
 * audit events. The animation is pure CSS (animate-ticker keyframe in
 * globals.css translates 0 → -50%); the lines are rendered twice
 * back-to-back so the loop is seamless. prefers-reduced-motion users see a
 * static stack via Tailwind's motion-reduce variant.
 * ------------------------------------------------------------------------- */

type AuditEvent = "REDACT" | "VERIFY" | "CHAIN_LINK" | "SEAL";

type AuditLine = {
  ts: string;
  event: AuditEvent;
  cfr: string;
  hash: string;
};

const AUDIT_LINES: readonly AuditLine[] = [
  { ts: "2026-06-25T14:32:01Z", event: "REDACT",     cfr: "45CFR§164.514(b)(2)(i)(A)", hash: "sha256:a3f8...c291" },
  { ts: "2026-06-25T14:32:02Z", event: "VERIFY",     cfr: "45CFR§164.514(b)(2)(i)(B)", hash: "sha256:7b21...e4f0" },
  { ts: "2026-06-25T14:32:03Z", event: "CHAIN_LINK", cfr: "45CFR§164.514(b)(2)(i)(C)", hash: "sha256:e09a...8d17" },
  { ts: "2026-06-25T14:32:04Z", event: "REDACT",     cfr: "45CFR§164.514(b)(2)(i)(J)", hash: "sha256:4d72...91ab" },
  { ts: "2026-06-25T14:32:06Z", event: "SEAL",       cfr: "45CFR§164.514(b)(2)(i)(P)", hash: "sha256:8c54...0e3d" },
  { ts: "2026-06-25T14:32:07Z", event: "REDACT",     cfr: "45CFR§164.514(b)(2)(i)(Q)", hash: "sha256:b6f1...2a48" },
  { ts: "2026-06-25T14:32:09Z", event: "VERIFY",     cfr: "45CFR§164.514(b)(2)(i)(A)", hash: "sha256:1e9d...5b76" },
  { ts: "2026-06-25T14:32:10Z", event: "REDACT",     cfr: "45CFR§164.514(b)(2)(i)(B)", hash: "sha256:fa30...c812" },
  { ts: "2026-06-25T14:32:11Z", event: "CHAIN_LINK", cfr: "45CFR§164.514(b)(2)(i)(C)", hash: "sha256:25a7...8e09" },
  { ts: "2026-06-25T14:32:13Z", event: "REDACT",     cfr: "45CFR§164.514(b)(2)(i)(J)", hash: "sha256:9b4c...d367" },
  { ts: "2026-06-25T14:32:14Z", event: "SEAL",       cfr: "45CFR§164.514(b)(2)(i)(P)", hash: "sha256:6e08...41fc" },
  { ts: "2026-06-25T14:32:16Z", event: "VERIFY",     cfr: "45CFR§164.514(b)(2)(i)(Q)", hash: "sha256:cd17...a59b" },
];

/* Per-event-type accent so the stream reads as live machine output without
 * losing the technical, monospace feel. */
const EVENT_COLOR: Record<AuditEvent, string> = {
  REDACT:     "text-warn",
  VERIFY:     "text-verify",
  CHAIN_LINK: "text-signal",
  SEAL:       "text-ink",
};

function AuditRow({ line }: { line: AuditLine }) {
  return (
    <div className="flex gap-4 whitespace-pre px-5 py-1.5 font-mono text-caption leading-relaxed">
      <span className="text-muted">{line.ts}</span>
      <span className={`${EVENT_COLOR[line.event]} font-medium w-[5.5rem]`}>{line.event}</span>
      <span className="text-ink">{line.cfr}</span>
      <span className="text-signal">{line.hash}</span>
    </div>
  );
}

export function Hero() {
  return (
    <section
      data-section="hero"
      className="min-h-screen flex items-center px-6 sm:px-8 lg:px-10 py-section"
    >
      <div className="w-full max-w-content mx-auto grid gap-12 lg:gap-16 lg:grid-cols-2 items-center">
        {/* -------------------- LEFT COLUMN -------------------- */}
        <div className="flex flex-col">
          <p className="font-mono text-mono text-signal uppercase tracking-[0.1em]">
            PHI Compliance Infrastructure
          </p>

          <h1 className="font-display text-hero text-ink mt-8">
            The audit chain your
            <br />
            OCR investigator
            <br />
            can actually read.
          </h1>

          <p className="font-body text-body text-muted mt-8 max-w-[55ch]">
            Hermes produces a per-token, CFR-cited, SHA-256 hash-chained
            record of every PHI scrubbing decision — inside your environment,
            never leaving it. Built for MSPs serving HIPAA-covered entities.
          </p>

          <div className="mt-10 flex flex-wrap items-center gap-4">
            <a
              href="#pilot"
              className="bg-signal text-void font-display font-bold px-7 py-3.5 border-2 border-signal hover:bg-ink hover:border-ink transition-colors"
            >
              Request a Pilot
            </a>
            <a
              href="#audit-chain"
              className="bg-transparent text-signal font-display font-semibold px-7 py-3.5 border-2 border-signal hover:bg-signal-dim transition-colors"
            >
              See the audit chain output →
            </a>
          </div>

          <p className="font-mono text-caption text-muted mt-8">
            Zero-egress architecture. Data never leaves your environment.
          </p>
        </div>

        {/* -------------------- RIGHT COLUMN — TICKER -------------------- */}
        <div className="flex flex-col">
          <div className="bg-surface border-2 border-signal">
            {/* window chrome */}
            <div className="flex items-center gap-3 border-b-2 border-border px-4 py-3">
              <div className="flex items-center gap-1.5" aria-hidden="true">
                <span className="block w-2.5 h-2.5 rounded-full bg-void border border-border" />
                <span className="block w-2.5 h-2.5 rounded-full bg-void border border-border" />
                <span className="block w-2.5 h-2.5 rounded-full bg-void border border-border" />
              </div>
              <span className="font-mono text-mono text-muted">
                hermes.audit.stream
              </span>
            </div>

            {/* scrolling region — fixed height, vertical mask so lines fade
             * in/out at the edges instead of slamming against the chrome */}
            <div
              className="relative h-80 overflow-hidden"
              style={{
                maskImage:
                  "linear-gradient(to bottom, transparent 0, #000 12%, #000 88%, transparent 100%)",
                WebkitMaskImage:
                  "linear-gradient(to bottom, transparent 0, #000 12%, #000 88%, transparent 100%)",
              }}
              aria-label="Simulated live audit chain feed"
            >
              <div className="absolute inset-x-0 top-0 flex flex-col will-change-transform animate-ticker motion-reduce:animate-none">
                {/* Render the 12 lines twice for a seamless loop. The
                 * keyframe ends at translateY(-50%), so the second copy
                 * appears at the original starting position when it
                 * restarts. */}
                {AUDIT_LINES.map((line, i) => (
                  <AuditRow key={`a-${i}`} line={line} />
                ))}
                {AUDIT_LINES.map((line, i) => (
                  <AuditRow key={`b-${i}`} line={line} />
                ))}
              </div>
            </div>
          </div>

          <p className="font-mono text-caption text-verify mt-4">
            ✓ Chain integrity verified — <br />tamper-evident since block #000001
          </p>
        </div>
      </div>
    </section>
  );
}
