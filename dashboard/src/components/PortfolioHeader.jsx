import StatCard from "./StatCard.jsx";

function formatRelativeTime(isoString) {
  if (!isoString) {
    return "—";
  }

  const then = new Date(isoString);
  if (Number.isNaN(then.getTime())) {
    return "—";
  }

  const seconds = Math.round((Date.now() - then.getTime()) / 1000);
  if (seconds < 60) {
    return seconds <= 1 ? "just now" : `${seconds} seconds ago`;
  }

  const minutes = Math.round(seconds / 60);
  if (minutes < 60) {
    return minutes === 1 ? "1 minute ago" : `${minutes} minutes ago`;
  }

  const hours = Math.round(minutes / 60);
  if (hours < 24) {
    return hours === 1 ? "1 hour ago" : `${hours} hours ago`;
  }

  const days = Math.round(hours / 24);
  return days === 1 ? "1 day ago" : `${days} days ago`;
}

export default function PortfolioHeader({ status }) {
  const phiCount = Array.isArray(status?.phi_classes_detected_today)
    ? status.phi_classes_detected_today.length
    : 0;

  return (
    <header className="border-b border-slate-200 bg-navy text-white">
      <div className="mx-auto flex max-w-7xl flex-col gap-6 px-6 py-6">
        <div className="flex items-baseline justify-between gap-4">
          <div>
            <p className="text-xs font-medium uppercase tracking-[0.18em] text-blue-200">
              Hermes Relay
            </p>
            <h1 className="mt-1 text-2xl font-semibold tracking-tight">
              Portfolio Dashboard
            </h1>
          </div>
          <p className="text-sm text-slate-300">MSP compliance overview</p>
        </div>

        <div className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
          <StatCard label="Clients Protected" value="1" tone="inverse" />
          <StatCard
            label="PHI Classes Caught Today"
            value={String(phiCount)}
            tone="inverse"
          />
          <StatCard
            label="Chain Position"
            value={status?.chain_position ?? "—"}
            tone="inverse"
          />
          <StatCard
            label="Evidence Current As Of"
            value={formatRelativeTime(status?.evidence_current_as_of)}
            tone="inverse"
          />
        </div>
      </div>
    </header>
  );
}

export { formatRelativeTime };
