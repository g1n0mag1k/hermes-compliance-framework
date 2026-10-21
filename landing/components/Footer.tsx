/* ---------------------------------------------------------------------------
 * Footer — minimal single row.
 *
 * Three mono caption items on a 2px-border-top void strip. Space-between on
 * desktop, stacked + centered on mobile. The right-hand contact is the
 * only interactive element — everything else is text.
 * ------------------------------------------------------------------------- */

export function Footer() {
  return (
    <footer
      data-section="footer"
      className="border-t-2 border-border bg-void px-6 sm:px-8 lg:px-10 py-8"
    >
      <div className="w-full max-w-content mx-auto flex flex-col items-center gap-4 font-mono text-caption text-muted">
        <p className="text-center max-w-[72ch] text-muted/90">
          Hermes produces tamper-evident technical evidence about tested telemetry paths. It is not a HIPAA compliance certification, a de-identification determination, or legal advice.
        </p>
        <div className="w-full flex flex-col md:flex-row md:justify-between items-center gap-3 md:gap-6">
        <span>© 2026 Sui-Generis LLC</span>
        <span>Hermes — hermesrelay.dev</span>
        <a href="https://github.com/g1n0mag1k/hermes-echo" className="hover:text-signal transition-colors">Hermes Echo — CLI behavioral contracts</a>
        <div className="flex flex-wrap items-center justify-center gap-4 md:gap-6">
          <a href="/privacy" className="hover:text-signal transition-colors">Privacy Policy</a>
          <a href="/security" className="hover:text-signal transition-colors">Security</a>
          <a href="mailto:andrew@hermesrelay.dev" className="hover:text-signal transition-colors">andrew@hermesrelay.dev</a>
        </div>
        </div>
      </div>
    </footer>
  );
}
