import TrendSparkline from "./TrendSparkline.jsx";
import { formatRelativeTime } from "./PortfolioHeader.jsx";

export function deriveProtectionState(status) {
  if (!status) {
    return "Monitoring incomplete —";
  }

  const lastScanAt = status.last_scan_at;
  const hasRecentScan = (() => {
    if (!lastScanAt) {
      return false;
    }
    const then = new Date(lastScanAt);
    if (Number.isNaN(then.getTime())) {
      return false;
    }
    return Date.now() - then.getTime() <= 24 * 60 * 60 * 1000;
  })();

  if (!hasRecentScan) {
    return "Monitoring incomplete —";
  }

  if ((status.critical_findings_open ?? 0) > 0) {
    return "Needs attention !";
  }

  if (status.zero_phi_egress_confirmed) {
    return "Verified ✓";
  }

  return "Needs attention !";
}

export function deriveNextAction(protectionState) {
  if (protectionState === "Verified ✓") {
    return "Continue monitoring";
  }
  if (protectionState === "Needs attention !") {
    return "Review critical findings";
  }
  return "Trigger scan";
}

export function buildTrendSeries(status) {
  const todayCount = Array.isArray(status?.phi_classes_detected_today)
    ? status.phi_classes_detected_today.length
    : 0;
  const baseline = Math.max(0, (status?.total_scans ?? 0) > 0 ? 1 : 0);

  return [
    { day: "D-6", value: baseline },
    { day: "D-5", value: baseline },
    { day: "D-4", value: baseline },
    { day: "D-3", value: baseline },
    { day: "D-2", value: baseline },
    { day: "D-1", value: baseline },
    { day: "D0", value: todayCount },
  ];
}

function protectionTone(label) {
  if (label === "Verified ✓") {
    return "text-verified";
  }
  if (label === "Needs attention !") {
    return "text-critical";
  }
  return "text-unknown";
}

function phiCoverageLabel(status) {
  const classes = status?.phi_classes_detected_today;
  if (!Array.isArray(classes) || classes.length === 0) {
    return "0 classes";
  }
  return `${classes.length} class${classes.length === 1 ? "" : "es"}`;
}

export default function ClientTable({ status }) {
  const protectionState = deriveProtectionState(status);
  const nextAction = deriveNextAction(protectionState);
  const trend = buildTrendSeries(status);

  return (
    <section className="overflow-hidden rounded-lg border border-slate-200 bg-white shadow-sm">
      <div className="border-b border-slate-200 px-4 py-3">
        <h2 className="text-sm font-semibold text-navy">Clients</h2>
      </div>
      <div className="overflow-x-auto">
        <table className="min-w-full text-left text-sm">
          <thead className="bg-slate-50 text-xs uppercase tracking-wide text-unknown">
            <tr>
              <th className="px-4 py-3 font-medium">Client</th>
              <th className="px-4 py-3 font-medium">Protection State</th>
              <th className="px-4 py-3 font-medium">PHI Coverage</th>
              <th className="px-4 py-3 font-medium">Critical/High</th>
              <th className="px-4 py-3 font-medium">Evidence Freshness</th>
              <th className="px-4 py-3 font-medium">Trend</th>
              <th className="px-4 py-3 font-medium">Next Action</th>
            </tr>
          </thead>
          <tbody>
            <tr className="border-t border-slate-100">
              <td className="px-4 py-4 font-medium text-navy">
                Hermes Relay (Self)
              </td>
              <td className={`px-4 py-4 font-medium ${protectionTone(protectionState)}`}>
                {protectionState}
              </td>
              <td className="px-4 py-4 text-navy">{phiCoverageLabel(status)}</td>
              <td className="px-4 py-4 text-navy">
                {status?.critical_findings_open ?? 0}
              </td>
              <td className="px-4 py-4 text-navy">
                {formatRelativeTime(status?.evidence_current_as_of)}
              </td>
              <td className="px-4 py-4">
                <TrendSparkline data={trend} />
              </td>
              <td className="px-4 py-4 text-blue">{nextAction}</td>
            </tr>
          </tbody>
        </table>
      </div>
    </section>
  );
}
