import React, { createContext, useState, useEffect } from 'react'
import PortfolioHeader from './components/PortfolioHeader.jsx'
import ClientTable from './components/ClientTable.jsx'
import ClientDetail from './components/ClientDetail.jsx'
import { RequireRole } from './components/RequireRole.jsx'
import {
  fetchStatus,
  fetchWorkspaces,
  fetchCurrentWorkspace,
  updateSentryConfig,
  syncDrataConfig,
  API_URL,
  API_KEY,
} from './lib/api.js'

export const WorkspaceContext = createContext({ workspace: null })

const DRATA_STATE_LABELS = {
  NOT_CONFIGURED: 'Drata not configured (set HERMES_DRATA_CCT_URL)',
  CONFIGURED: 'Drata configured, connection not tested',
  CONFIG_INVALID: 'Drata configuration invalid (check HTTPS URL and API key)',
  CONNECTION_TEST_FAILED: 'Drata connection test failed',
  CONNECTION_TEST_SUCCEEDED: 'Drata connection test passed',
}

export default function App() {
  const [status, setStatus] = useState(null)
  const [workspaces, setWorkspaces] = useState(null)
  const [workspace, setWorkspace] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [view, setView] = useState('portfolio')
  const [adminMessage, setAdminMessage] = useState(null)

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

  async function loadWorkspaces() {
    try {
      const data = await fetchWorkspaces()
      setWorkspaces(data)
    } catch {
      setWorkspaces(null)
    }
  }

  async function loadCurrentWorkspace() {
    try {
      const data = await fetchCurrentWorkspace()
      setWorkspace(data)
    } catch {
      setWorkspace(null)
    }
  }

  useEffect(() => {
    load()
    loadWorkspaces()
    loadCurrentWorkspace()
    const interval = setInterval(load, 30000)
    return () => clearInterval(interval)
  }, [])

  async function handleUpdateSentry() {
    try {
      await updateSentryConfig()
      setAdminMessage('Sentry DSN updated')
    } catch (err) {
      setAdminMessage(err.message)
    }
  }

  async function handleSyncDrata() {
    try {
      const result = await syncDrataConfig()
      const label = DRATA_STATE_LABELS[result.state] || 'Drata status unknown'
      setAdminMessage(`${label} — Drata sync from the dashboard is not implemented`)
    } catch (err) {
      setAdminMessage(err.message)
    }
  }

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
    <WorkspaceContext.Provider value={{ workspace }}>
      <div className="min-h-screen bg-canvas">
        <header className="bg-navy text-white px-6 py-4 flex items-center justify-between">
          <div
            className="flex items-center gap-3 cursor-pointer"
            onClick={() => setView('portfolio')}
          >
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
          {view === 'portfolio' ? (
            <>
              <PortfolioHeader
                status={status}
                workspaces={workspaces}
                onScanComplete={load}
              />
              <RequireRole allowedRoles={['msp_admin', 'msp_tech']}>
                <div className="flex flex-wrap items-center gap-3 mb-6">
                  <button
                    type="button"
                    onClick={handleUpdateSentry}
                    className="px-3 py-2 text-sm bg-slate-800 text-white rounded hover:bg-slate-700"
                  >
                    Update Sentry DSN
                  </button>
                  <button
                    type="button"
                    onClick={handleSyncDrata}
                    className="px-3 py-2 text-sm bg-slate-800 text-white rounded hover:bg-slate-700"
                  >
                    Check Drata Status
                  </button>
                  {adminMessage && (
                    <span className="text-xs text-slate-500">{adminMessage}</span>
                  )}
                </div>
              </RequireRole>
              <ClientTable
                status={status}
                apiKey={API_KEY}
                onClientClick={() => setView('client')}
              />
            </>
          ) : (
            <ClientDetail
              status={status}
              onBack={() => setView('portfolio')}
            />
          )}

          <div className="mt-6 text-center text-xs text-slate-400">
            Chain integrity: {status?.chain_integrity} ·
            Total scans: {status?.total_scans} ·
            Evidence current as of: {status?.evidence_current_as_of
              ? new Date(status.evidence_current_as_of).toLocaleString()
              : '—'}
          </div>
        </main>
      </div>
    </WorkspaceContext.Provider>
  )
}
