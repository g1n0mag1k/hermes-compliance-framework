import React, { useState, useEffect } from 'react'
import PortfolioHeader from './components/PortfolioHeader.jsx'
import ClientTable from './components/ClientTable.jsx'
import { fetchStatus, API_URL } from './lib/api.js'

export default function App() {
  const [status, setStatus] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)

  async function load() {
    try {
      const data = await fetchStatus()
      setStatus(data)
      setError(null)
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    load()
    const interval = setInterval(load, 30000)
    return () => clearInterval(interval)
  }, [])

  if (loading) {
    return (
      <div className="min-h-screen bg-canvas flex items-center justify-center">
        <div className="text-center">
          <div className="w-8 h-8 border-4 border-blue-600 border-t-transparent rounded-full animate-spin mx-auto mb-4" />
          <p className="text-slate-500 animate-pulse">Connecting to Hermes Relay...</p>
        </div>
      </div>
    )
  }

  if (error) {
    return (
      <div className="min-h-screen bg-canvas flex items-center justify-center">
        <div className="text-center max-w-md">
          <p className="text-red-600 font-semibold mb-2">Unable to reach Hermes Relay</p>
          <p className="text-slate-500 text-sm">{API_URL}</p>
          <p className="text-slate-400 text-xs mt-2">{error}</p>
          <button
            onClick={load}
            className="mt-4 px-4 py-2 bg-blue-600 text-white rounded text-sm hover:bg-blue-700"
          >
            Retry
          </button>
        </div>
      </div>
    )
  }

  return (
    <div className="min-h-screen bg-canvas">
      <header className="bg-navy text-white px-6 py-4 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-7 h-7 rounded-full bg-emerald-600 flex items-center justify-center">
            <span className="text-white text-xs font-bold">H</span>
          </div>
          <span className="font-semibold tracking-wide">HERMES RELAY</span>
        </div>
        <div className="flex items-center gap-2">
          <div className="w-2 h-2 rounded-full bg-emerald-400 animate-pulse" />
          <span className="text-xs text-slate-300">Active Monitoring</span>
        </div>
      </header>

      <main className="max-w-7xl mx-auto px-6 py-8">
        <PortfolioHeader status={status} />
        <ClientTable status={status} />

        <div className="mt-6 text-center text-xs text-slate-400">
          Chain integrity: {status?.chain_integrity} ·
          Total scans: {status?.total_scans} ·
          Evidence current as of: {status?.evidence_current_as_of
            ? new Date(status.evidence_current_as_of).toLocaleString()
            : '—'}
        </div>
      </main>
    </div>
  )
}
