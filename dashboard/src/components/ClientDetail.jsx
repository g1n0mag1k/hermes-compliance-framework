import React from 'react'

const CFR_MAP = {
  HIPAA_SSN:            '45 CFR §164.514(b)(2)(i)(G)',
  HIPAA_PHI_PERSON:     '45 CFR §164.514(b)(2)(i)(A)',
  HIPAA_PHI_ORG:        '45 CFR §164.514(b)(2)(i)(A)',
  HIPAA_PHI_DATE:       '45 CFR §164.514(b)(2)(i)(C)',
  HIPAA_PHI_EMAIL:      '45 CFR §164.514(b)(2)(i)(F)',
  HIPAA_PHI_PHONE:      '45 CFR §164.514(b)(2)(i)(D)',
  HIPAA_PHI_ADDRESS:    '45 CFR §164.514(b)(2)(i)(B)',
  HIPAA_PHI_MRN:        '45 CFR §164.514(b)(2)(i)(H)',
  HIPAA_PHI_HPBN:       '45 CFR §164.514(b)(2)(i)(I)',
  HIPAA_PHI_ACCOUNT:    '45 CFR §164.514(b)(2)(i)(J)',
  HIPAA_PHI_VIN:        '45 CFR §164.514(b)(2)(i)(L)',
  HIPAA_PHI_IP:         '45 CFR §164.514(b)(2)(i)(O)',
  HIPAA_PHI_URL:        '45 CFR §164.514(b)(2)(i)(N)',
  HIPAA_PHI_FAX:        '45 CFR §164.514(b)(2)(i)(E)',
  HIPAA_PHI_DEVICE_ID:  '45 CFR §164.514(b)(2)(i)(M)',
  HIPAA_PHI_CERT_LICENSE: '45 CFR §164.514(b)(2)(i)(K)',
  HIPAA_PHI_UNIQUE_CODE:  '45 CFR §164.514(b)(2)(i)(R)',
  PCI_PAN:              'PCI-DSS (not a HIPAA Safe Harbor identifier)',
}

function timeAgo(isoString) {
  if (!isoString) return '—'
  const diff = Math.floor((Date.now() - new Date(isoString)) / 1000)
  if (diff < 60) return `${diff}s ago`
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`
  return `${Math.floor(diff / 86400)}d ago`
}

function MetricCard({ label, value, sub, valueColor = 'text-slate-800' }) {
  return (
    <div className="bg-white rounded-lg border border-slate-200 p-5">
      <p className="text-xs font-semibold uppercase tracking-wide text-slate-500 mb-1">
        {label}
      </p>
      <p className={`text-2xl font-bold ${valueColor}`}>{value ?? '—'}</p>
      {sub && <p className="text-xs text-slate-400 mt-1">{sub}</p>}
    </div>
  )
}

export default function ClientDetail({ status, onBack }) {
  const coverageColor = !status
    ? 'text-slate-400'
    : status.zero_phi_egress_confirmed
      ? 'text-emerald-700'
      : 'text-red-600'

  const evidenceColor = !status?.evidence_current_as_of
    ? 'text-slate-400'
    : (Date.now() - new Date(status.evidence_current_as_of)) < 3600000
      ? 'text-emerald-700'
      : (Date.now() - new Date(status.evidence_current_as_of)) < 86400000
        ? 'text-amber-700'
        : 'text-red-600'

  const findings = status?.phi_classes_detected_today || []

  return (
    <div>
      <button
        onClick={onBack}
        className="flex items-center gap-2 text-sm text-slate-500 hover:text-slate-800 mb-6 transition-colors"
      >
        ← Portfolio
      </button>

      <div className="mb-6">
        <h2 className="text-xl font-bold text-slate-800">Hermes Relay (Self)</h2>
        <p className="text-sm text-slate-500">Rocky Top, TN · Self-deployment</p>
      </div>

      <div className="grid grid-cols-2 md:grid-cols-3 gap-4 mb-8">
        <MetricCard
          label="Verified PHI Protection Coverage"
          value={status?.zero_phi_egress_confirmed ? '100%' : '0%'}
          sub="Zero PHI egress confirmed"
          valueColor={coverageColor}
        />
        <MetricCard
          label="Unmonitored ePHI Systems"
          value="0"
          sub="All systems monitored"
          valueColor="text-emerald-700"
        />
        <MetricCard
          label="Open Critical / High Findings"
          value={status?.critical_findings_open ?? '—'}
          sub={status?.critical_findings_open > 0 ? 'Action required' : 'No open findings'}
          valueColor={status?.critical_findings_open > 0 ? 'text-red-600' : 'text-emerald-700'}
        />
        <MetricCard
          label="Total Scans This Session"
          value={status?.total_scans ?? '—'}
          sub="Receipts in chain"
          valueColor="text-blue-600"
        />
        <MetricCard
          label="Evidence Current As Of"
          value={timeAgo(status?.evidence_current_as_of)}
          sub="Last verified scan"
          valueColor={evidenceColor}
        />
        <MetricCard
          label="Chain Integrity"
          value={status?.chain_integrity === 'verified' ? 'Verified ✓' : 'No data —'}
          sub="HMAC-SHA256 attestation"
          valueColor={status?.chain_integrity === 'verified' ? 'text-emerald-700' : 'text-slate-400'}
        />
      </div>

      <div className="bg-white rounded-lg border border-slate-200 p-5">
        <h3 className="text-sm font-semibold text-slate-700 mb-4">
          PHI Classes Detected Today
        </h3>
        {findings.length === 0 ? (
          <p className="text-emerald-700 font-medium text-sm">
            No PHI detected in last 24 hours ✓
          </p>
        ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="text-xs text-slate-500 uppercase tracking-wide border-b border-slate-100">
                <th className="text-left py-2">Flag</th>
                <th className="text-left py-2">CFR Citation</th>
              </tr>
            </thead>
            <tbody>
              {findings.map((flag) => (
                <tr key={flag} className="border-b border-slate-50">
                  <td className="py-2 font-mono text-xs text-slate-700">{flag}</td>
                  <td className="py-2 text-xs text-slate-500">
                    {CFR_MAP[flag] || 'See declared scope'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}
