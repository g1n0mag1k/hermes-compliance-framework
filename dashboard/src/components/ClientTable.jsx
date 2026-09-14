import React from 'react'
import TrendSparkline from './TrendSparkline.jsx'

function statusLabel(status) {
  if (!status) return { label: 'Monitoring incomplete —', color: 'text-slate-500' }
  if (status.critical_findings_open > 0) return { label: 'Needs attention !', color: 'text-red-600' }
  if (status.zero_phi_egress_confirmed) return { label: 'Verified ✓', color: 'text-emerald-700' }
  return { label: 'Monitoring incomplete —', color: 'text-slate-500' }
}

function timeAgo(isoString) {
  if (!isoString) return '—'
  const diff = Math.floor((Date.now() - new Date(isoString)) / 1000)
  if (diff < 60) return `${diff}s ago`
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`
  return `${Math.floor(diff / 86400)}d ago`
}

export default function ClientTable({ status }) {
  const { label, color } = statusLabel(status)

  return (
    <div className="bg-white rounded-lg border border-slate-200 overflow-hidden">
      <div className="px-5 py-3 border-b border-slate-100 flex items-center justify-between">
        <h2 className="text-sm font-semibold text-slate-700">Client Portfolio</h2>
        <span className="text-xs text-slate-400">
          Sorted by: Critical findings first
        </span>
      </div>

      <table className="w-full text-sm">
        <thead className="bg-slate-50 text-xs text-slate-500 uppercase tracking-wide">
          <tr>
            <th className="px-5 py-3 text-left">Client</th>
            <th className="px-5 py-3 text-left">Protection State</th>
            <th className="px-5 py-3 text-left">PHI Coverage</th>
            <th className="px-5 py-3 text-left">Critical / High</th>
            <th className="px-5 py-3 text-left">Evidence Freshness</th>
            <th className="px-5 py-3 text-left">Trend</th>
            <th className="px-5 py-3 text-left">Next Action</th>
          </tr>
        </thead>
        <tbody>
          <tr className="border-t border-slate-100 hover:bg-slate-50 transition-colors">
            <td className="px-5 py-4">
              <div className="font-medium text-slate-800">Hermes Relay (Self)</div>
              <div className="text-xs text-slate-400">Rocky Top, TN</div>
            </td>
            <td className="px-5 py-4">
              <span className={`font-medium ${color}`}>{label}</span>
            </td>
            <td className="px-5 py-4">
              <div className="flex items-center gap-2">
                <div className="w-24 bg-slate-100 rounded-full h-2">
                  <div
                    className="bg-emerald-600 h-2 rounded-full"
                    style={{ width: status?.zero_phi_egress_confirmed ? '100%' : '0%' }}
                  />
                </div>
                <span className="text-slate-600">
                  {status?.zero_phi_egress_confirmed ? '100%' : '0%'}
                </span>
              </div>
            </td>
            <td className="px-5 py-4">
              <span className={status?.critical_findings_open > 0 ? 'text-red-600 font-semibold' : 'text-emerald-700'}>
                {status?.critical_findings_open ?? '—'}
              </span>
            </td>
            <td className="px-5 py-4 text-slate-600">
              {timeAgo(status?.evidence_current_as_of)}
            </td>
            <td className="px-5 py-4 w-24">
              <TrendSparkline data={[1, 2, 1, 3, 2, 4, status?.total_scans ?? 1]} />
            </td>
            <td className="px-5 py-4 text-slate-500 text-xs">
              {status?.critical_findings_open > 0
                ? 'Review findings'
                : 'Continue monitoring'}
            </td>
          </tr>
        </tbody>
      </table>
    </div>
  )
}
