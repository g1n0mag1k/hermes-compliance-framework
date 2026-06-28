/* ---------------------------------------------------------------------------
 * AuditChain — full audit chain output section anchored at #audit-chain.
 * ------------------------------------------------------------------------- */

type AuditEvent = "REDACT" | "VERIFY" | "CHAIN_LINK" | "SEAL";

type ChainEntry = {
  block: string;
  ts: string;
  event: AuditEvent;
  field: string;
  cfr: string;
  prev: string;
  hash: string;
};

const EVENT_COLOR: Record<AuditEvent, string> = {
  REDACT:     "text-warn",
  VERIFY:     "text-verify",
  CHAIN_LINK: "text-signal",
  SEAL:       "text-ink",
};

const CHAIN: readonly ChainEntry[] = [
  { block: "#000001", ts: "14:32:01Z", event: "REDACT",     field: "PATIENT_NAME", cfr: "45CFR§164.514(b)(2)(i)(A)", prev: "0000000000000000",         hash: "sha256:a3f8b291c7e402d1f95a6b3c8e1d4f72a0b5c9e3d6f8a2b4c7e0d3f6a9b2c5e8" },
  { block: "#000002", ts: "14:32:02Z", event: "REDACT",     field: "DATE_OF_BIRTH", cfr: "45CFR§164.514(b)(2)(i)(C)", prev: "sha256:a3f8b291c7e402d1", hash: "sha256:7b21e4f0d8c395a2b6f1e8d4c7a0b3e6f9c2d5a8b1e4f7a0c3d6e9b2c5f8a1d4" },
  { block: "#000003", ts: "14:32:03Z", event: "REDACT",     field: "SSN",           cfr: "45CFR§164.514(b)(2)(i)(J)", prev: "sha256:7b21e4f0d8c395a2", hash: "sha256:e09a8d17f3b4c6e1a2d5f8b0c3e6a9d2f5b8c1e4a7d0f3b6c9e2a5d8f1b4c7e0" },
  { block: "#000004", ts: "14:32:04Z", event: "CHAIN_LINK", field: "BLOCK_SEAL",    cfr: "45CFR§164.312(b)",           prev: "sha256:e09a8d17f3b4c6e1", hash: "sha256:4d7291ab8c3e6f0a1b4d7e0c3f6a9b2e5d8f1a4c7e0b3d6f9a2c5e8b1d4f7a0c3" },
  { block: "#000005", ts: "14:32:06Z", event: "REDACT",     field: "PHONE_NUMBER",  cfr: "45CFR§164.514(b)(2)(i)(D)", prev: "sha256:4d7291ab8c3e6f0a", hash: "sha256:8c540e3db1f4a7c2e5d8b0a3f6c9e2b5d8a1f4c7e0b3d6f9a2c5e8b1d4f7a0c3d6" },
  { block: "#000006", ts: "14:32:07Z", event: "SEAL",       field: "PAYLOAD_SEAL",  cfr: "45CFR§164.312(b)",           prev: "sha256:8c540e3db1f4a7c2", hash: "sha256:b6f12a48e3c7d0f5a8b2e5d9c1f4a7b0e3d6f9c2a5e8b1d4f7a0c3e6b9d2f5a8b1" },
];

function ChainRow({ entry, isLast }: { entry: ChainEntry; isLast: boolean }) {
  return (
    <div className={`grid gap-x-4 gap-y-1 px-4 py-3 font-mono text-[11px] leading-relaxed lg:text-[12px] ${!isLast ? "border-b border-border" : ""}`} style={{ gridTemplateColumns: "5ch 10ch 10ch 16ch 1fr" }}>
      <span className="text-muted">{entry.block}</span>
      <span className="text-muted">{entry.ts}</span>
      <span className={`${EVENT_COLOR[entry.event]} font-medium`}>{entry.event}</span>
      <span className="text-ink">{entry.field}</span>
      <span className="text-signal truncate">{entry.cfr}</span>
      <span className="col-span-5 text-muted truncate">prev: {entry.prev}</span>
      <span className="col-span-5 text-verify truncate">hash: {entry.hash}</span>
    </div>
  );
}

export function AuditChain() {
  const rawInput = `Patient: Sarah Mitchell, DOB 03/14/1978, SSN 412-55-8901\nPhone: (865) 402-7733\nDiagnosis: Type 2 Diabetes, ICD-10 E11.9\nReferring physician requested AI-assisted prior auth summary.`;
  const scrubbedOutput = `Patient: [PATIENT_NAME_A], DOB [DATE_C], SSN [SSN_J]\nPhone: [PHONE_D]\nDiagnosis: Type 2 Diabetes, ICD-10 E11.9\nReferring physician requested AI-assisted prior auth summary.`;

  return (
    <section id="audit-chain" data-section="audit-chain" className="px-6 sm:px-8 lg:px-10 py-section">
      <div className="w-full max-w-content mx-auto">
        <p className="font-mono text-mono text-signal uppercase tracking-[0.1em]">Live audit chain output</p>
        <h2 className="font-display text-h2 text-ink mt-8 max-w-[28ch]">Every PHI decision.<br />Every CFR citation.<br />Every block. Chained.</h2>
        <p className="font-body text-body text-muted mt-6 max-w-[60ch]">This is what Hermes produces for every payload it processes. Each redaction decision is recorded with its CFR citation, sealed into a SHA-256 hash chain, and stored inside your environment. No external processor. No black box. A record an OCR investigator can verify byte-by-byte.</p>

        <div className="mt-16 grid gap-6 lg:grid-cols-2">
          <div className="flex flex-col">
            <div className="bg-surface border-2 border-border">
              <div className="flex items-center gap-3 border-b-2 border-border px-4 py-3">
                <div className="flex items-center gap-1.5" aria-hidden="true"><span className="block w-2.5 h-2.5 rounded-full bg-void border border-border" /><span className="block w-2.5 h-2.5 rounded-full bg-void border border-border" /><span className="block w-2.5 h-2.5 rounded-full bg-void border border-border" /></div>
                <span className="font-mono text-mono text-muted">input.payload</span>
              </div>
              <pre className="font-mono text-[11px] lg:text-[12px] leading-relaxed text-warn px-4 py-4 whitespace-pre-wrap">{rawInput}</pre>
            </div>
            <p className="font-mono text-caption text-warn mt-3">⚠ PHI detected — payload blocked from AI pipeline</p>
          </div>

          <div className="flex flex-col">
            <div className="bg-surface border-2 border-signal">
              <div className="flex items-center gap-3 border-b-2 border-border px-4 py-3">
                <div className="flex items-center gap-1.5" aria-hidden="true"><span className="block w-2.5 h-2.5 rounded-full bg-void border border-border" /><span className="block w-2.5 h-2.5 rounded-full bg-void border border-border" /><span className="block w-2.5 h-2.5 rounded-full bg-void border border-border" /></div>
                <span className="font-mono text-mono text-muted">output.scrubbed</span>
              </div>
              <pre className="font-mono text-[11px] lg:text-[12px] leading-relaxed text-verify px-4 py-4 whitespace-pre-wrap">{scrubbedOutput}</pre>
            </div>
            <p className="font-mono text-caption text-verify mt-3">✓ PHI removed — safe to forward to AI pipeline</p>
          </div>
        </div>

        <div className="mt-10 flex flex-col">
          <div className="bg-surface border-2 border-signal">
            <div className="flex items-center justify-between border-b-2 border-border px-4 py-3">
              <div className="flex items-center gap-3">
                <div className="flex items-center gap-1.5" aria-hidden="true"><span className="block w-2.5 h-2.5 rounded-full bg-void border border-border" /><span className="block w-2.5 h-2.5 rounded-full bg-void border border-border" /><span className="block w-2.5 h-2.5 rounded-full bg-void border border-border" /></div>
                <span className="font-mono text-mono text-muted">hermes.audit.chain — payload_id: hx_20260628_001</span>
              </div>
              <span className="font-mono text-caption text-signal">6 blocks</span>
            </div>
            <div className="grid gap-x-4 px-4 py-2 font-mono text-[10px] uppercase tracking-widest text-muted border-b border-border" style={{ gridTemplateColumns: "5ch 10ch 10ch 16ch 1fr" }}>
              <span>block</span><span>time</span><span>event</span><span>field</span><span>cfr citation</span>
            </div>
            <div className="overflow-x-auto">
              {CHAIN.map((entry, i) => <ChainRow key={entry.block} entry={entry} isLast={i === CHAIN.length - 1} />)}
            </div>
          </div>
          <p className="font-mono text-caption text-verify mt-4">✓ Chain integrity verified — each block hash includes the previous block hash. Tamper-evident since block #000001.</p>
        </div>

        <div className="mt-16 border-t-2 border-border pt-10">
          <p className="font-body text-body text-muted max-w-[60ch]">This record is generated inside your environment for every payload Hermes processes. No configuration required. Ready for OCR audit on day one.</p>
          <a href="#pilot" className="mt-6 inline-block bg-signal text-void font-display font-bold px-7 py-3.5 border-2 border-signal hover:bg-ink hover:border-ink transition-colors">Request a Pilot</a>
        </div>
      </div>
    </section>
  );
}
