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
      <div className="w-full max-w-content mx-auto flex flex-col md:flex-row md:justify-between items-center gap-3 md:gap-6 font-mono text-caption text-muted">
        <span>© 2026 Sui-Generis LLC</span>
        <span>Hermes — hermesrelay.dev</span>
        <a
          href="mailto:andrew@hermesrelay.dev"
          className="hover:text-signal transition-colors"
        >
          andrew@hermesrelay.dev
        </a>
      </div>
    </footer>
  );
}
