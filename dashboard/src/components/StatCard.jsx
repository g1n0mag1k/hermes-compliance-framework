import React from 'react'

export default function StatCard({ label, value, color = 'blue', sub }) {
  const colorMap = {
    blue:     'text-blue-600 border-blue-200',
    verified: 'text-emerald-700 border-emerald-200',
    warning:  'text-amber-700 border-amber-200',
    critical: 'text-red-700 border-red-200',
    unknown:  'text-slate-500 border-slate-200',
    navy:     'text-slate-800 border-slate-200',
  }

  return (
    <div className={`bg-white rounded-lg border p-5 ${colorMap[color] || colorMap.blue}`}>
      <p className="text-xs font-semibold uppercase tracking-wide text-slate-500 mb-1">
        {label}
      </p>
      <p className={`text-2xl font-bold ${colorMap[color]?.split(' ')[0]}`}>
        {value ?? '—'}
      </p>
      {sub && (
        <p className="text-xs text-slate-400 mt-1">{sub}</p>
      )}
    </div>
  )
}
