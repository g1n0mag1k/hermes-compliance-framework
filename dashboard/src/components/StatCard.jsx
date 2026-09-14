export default function StatCard({ label, value, tone = "default" }) {
  const isInverse = tone === "inverse";

  return (
    <div
      className={
        isInverse
          ? "rounded-lg border border-white/10 bg-white/5 px-4 py-3 shadow-sm"
          : "rounded-lg border border-slate-200 bg-white px-4 py-3 shadow-sm"
      }
    >
      <p
        className={
          isInverse
            ? "text-xs font-medium uppercase tracking-wide text-slate-300"
            : "text-xs font-medium uppercase tracking-wide text-unknown"
        }
      >
        {label}
      </p>
      <p
        className={
          isInverse
            ? "mt-2 text-2xl font-semibold text-white"
            : "mt-2 text-2xl font-semibold text-navy"
        }
      >
        {value}
      </p>
    </div>
  );
}
