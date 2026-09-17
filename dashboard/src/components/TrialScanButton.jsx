import React, { useState } from 'react'
import { runTrialScan } from '../lib/api.js'

export default function TrialScanButton({ onComplete }) {
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState(null)
  const [success, setSuccess] = useState(false)

  async function handleClick(e) {
    e.stopPropagation()
    setLoading(true)
    setError(null)
    setSuccess(false)
    try {
      await runTrialScan()
      setSuccess(true)
      if (onComplete) {
        await onComplete()
      }
    } catch (err) {
      setError(err.message || 'Trial scan failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="flex flex-col items-end gap-1">
      <button
        type="button"
        onClick={handleClick}
        disabled={loading}
        className="px-4 py-2 bg-emerald-700 text-white text-sm font-medium rounded hover:bg-emerald-800 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
      >
        {loading ? 'Scanning…' : 'Trial Scan'}
      </button>
      {error && (
        <p className="text-xs text-red-600 max-w-xs text-right">{error}</p>
      )}
      {success && !error && (
        <p className="text-xs text-emerald-700">Scan complete — evidence updated</p>
      )}
    </div>
  )
}
