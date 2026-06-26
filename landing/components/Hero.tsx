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

/* Timestamps show time-only — the date is identical for every event in
 * the stream and would just eat horizontal width inside the desktop
 * ticker column without adding information. */
const AUDIT_LINES: readonly AuditLine[] = [
  { ts: "14:32:01Z", event: "REDACT",     cfr: "45CFR§164.514(b)(2)(i)(A)", hash: "sha256:a3f8...c291" },
  { ts: "14:32:02Z", event: "VERIFY",     cfr: "45CFR§164.514(b)(2)(i)(B)", hash: "sha256:7b21...e4f0" },
  { ts: "14:32:03Z", event: "CHAIN_LINK", cfr: "45CFR§164.514(b)(2)(i)(C)", hash: "sha256:e09a...8d17" },
  { ts: "14:32:04Z", event: "REDACT",     cfr: "45CFR§164.514(b)(2)(i)(J)", hash: "sha256:4d72...91ab" },
  { ts: "14:32:06Z", event: "SEAL",       cfr: "45CFR§164.514(b)(2)(i)(P)", hash: "sha256:8c54...0e3d" },
  { ts: "14:32:07Z", event: "REDACT",     cfr: "45CFR§164.514(b)(2)(i)(Q)", hash: "sha256:b6f1...2a48" },
  { ts: "14:32:09Z", event: "VERIFY",     cfr: "45CFR§164.514(b)(2)(i)(A)", hash: "sha256:1e9d...5b76" },
  { ts: "14:32:10Z", event: "REDACT",     cfr: "45CFR§164.514(b)(2)(i)(B)", hash: "sha256:fa30...c812" },
  { ts: "14:32:11Z", event: "CHAIN_LINK", cfr: "45CFR§164.514(b)(2)(i)(C)", hash: "sha256:25a7...8e09" },
  { ts: "14:32:13Z", event: "REDACT",     cfr: "45CFR§164.514(b)(2)(i)(J)", hash: "sha256:9b4c...d367" },
  { ts: "14:32:14Z", event: "SEAL",       cfr: "45CFR§164.514(b)(2)(i)(P)", hash: "sha256:6e08...41fc" },
  { ts: "14:32:16Z", event: "VERIFY",     cfr: "45CFR§164.514(b)(2)(i)(Q)", hash: "sha256:cd17...a59b" },
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
  /* Row width breakdown (text-[11px] / 12px on lg+, gap-3, w-20 event col):
   *   ts(19ch) + event(80px) + cfr(25ch) + hash(18ch) + gaps + px-4
   *   ≈ 470px @ 11px, ≈ 510px @ 12px — fits the desktop ticker column.
   * On mobile the row content stays well above 375px viewport width;
   * whitespace-pre + min-w-max guarantee the row never wraps, and the
   * outer container's overflow-x:auto lets users scroll horizontally
   * to read the entire compliance evidence record instead of having
   * it truncated. */
  return (
    <div className="flex gap-3 whitespace-pre px-4 py-1.5 font-mono text-[11px] leading-relaxed min-w-max lg:text-[12px]">
      <span className="text-muted">{line.ts}</span>
      <span className={`${EVENT_COLOR[line.event]} font-medium w-20`}>{line.event}</span>
      <span className="text-ink">{line.cfr}</span>
      <span className="text-signal">{line.hash}</span>
    </div>
  );
}

export function Hero() {
  /* Layout rules:
   *   - On mobile/tablet (< lg) the headline stack stands alone in a padded
   *     column, the ticker drops below it as a FULL-BLEED panel that touches
   *     the viewport edges. Combined with a horizontal-scroll inner track,
   *     the (intentionally long) compliance evidence record stays readable
   *     without truncation.
   *   - On desktop (lg+) we revert to the two-column layout: proposition on
   *     the left, ticker on the right, both constrained by max-w-content. */
  return (
    <section
      data-section="hero"
      className="min-h-screen flex flex-col justify-center py-section"
    >
      <div className="w-full max-w-content mx-auto grid gap-12 lg:gap-16 lg:grid-cols-[minmax(0,1fr)_minmax(0,1.35fr)] lg:items-center lg:px-10">
        {/* -------------------- LEFT COLUMN -------------------- */}
        <div className="flex flex-col px-6 sm:px-8 lg:px-0">
          <p className="font-mono text-mono text-signal uppercase tracking-[0.1em]">
            PHI Compliance Infrastructure
          </p>

          <h1 className="font-display text-hero text-ink mt-6 sm:mt-8">
            The audit chain your
            <br />
            OCR investigator
            <br />
            can actually read.
          </h1>

          <p className="font-body text-body text-muted mt-6 sm:mt-8 max-w-[55ch]">
            Hermes produces a per-token, CFR-cited, SHA-256 hash-chained
            record of every PHI scrubbing decision — inside your environment,
            never leaving it. Built for MSPs serving HIPAA-covered entities.
          </p>

          <div className="mt-8 sm:mt-10 flex flex-wrap items-center gap-4">
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

        {/* -------------------- RIGHT COLUMN — TICKER --------------------
         * Full-bleed on mobile (no horizontal padding so it spans the
         * viewport), constrained back into the column on desktop. */}
        <div className="flex flex-col">
          <div className="bg-surface border-y-2 lg:border-2 border-signal">
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

            {/* Scrolling region — fixed height, vertical mask fades lines
             * in/out at the edges, horizontal overflow lets users scroll
             * the long record on narrow screens instead of seeing it
             * truncated. */}
            <div
              className="relative h-80 overflow-x-auto overflow-y-hidden"
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

          <p className="font-mono text-caption text-verify mt-4 px-6 sm:px-8 lg:px-0">
            ✓ Chain integrity verified — tamper-evident since block #000001
          </p>
        </div>
      </div>
    </section>
  );
}
