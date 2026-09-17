import React from 'react'
import StatCard from './StatCard.jsx'
import TrialScanButton from './TrialScanButton.jsx'

function timeAgo(isoString) {
  if (!isoString) return '—'
  const diff = Math.floor((Date.now() - new Date(isoString)) / 1000)
  if (diff < 60) return `${diff}s ago`
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`
  return `${Math.floor(diff / 86400)}d ago`
}

export default function PortfolioHeader({ status, onScanComplete }) {
  return (
    <div>
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <div className="w-8 h-8 rounded-full bg-emerald-700 flex items-center justify-center">
            <span className="text-white text-sm font-bold">H</span>
          </div>
          <div>
            <h1 className="text-xl font-bold text-slate-800">Hermes Relay</h1>
            <p className="text-xs text-slate-500">PHI Detection Dashboard</p>
          </div>
        </div>
        <div className="flex items-center gap-4">
          <span className="text-xs text-slate-400">
            hermesrelay.dev · Sui-Generis LLC
          </span>
          <TrialScanButton onComplete={onScanComplete} />
        </div>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-8">
        <StatCard
          label="Clients Protected"
          value="1"
          color="verified"
          sub="Self-deployment active"
        />
        <StatCard
          label="PHI Classes Caught Today"
          value={status?.phi_classes_detected_today?.length ?? '—'}
          color={status?.phi_classes_detected_today?.length > 0 ? 'warning' : 'verified'}
          sub="Last 24 hours"
        />
        <StatCard
          label="Chain Position"
          value={status?.chain_position ?? '—'}
          color="navy"
          sub="Receipts in chain"
        />
        <StatCard
          label="Evidence Current As Of"
          value={timeAgo(status?.evidence_current_as_of)}
          color={
            !status?.evidence_current_as_of ? 'unknown' :
            (Date.now() - new Date(status.evidence_current_as_of)) < 3600000
              ? 'verified' : 'warning'
          }
          sub="Last verified scan"
        />
      </div>
    </div>
  )
}
