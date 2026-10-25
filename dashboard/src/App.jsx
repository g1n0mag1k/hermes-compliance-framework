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
  fetchDrataStatus,
  API_URL,
  API_KEY,
} from './lib/api.js'

export const WorkspaceContext = createContext({ workspace: null })

// CONNECTED and SYNCING are reserved: they require a live Drata connection
// test, which does not exist, so drataDisplayState() never returns them.
const DRATA_DISPLAY = {
  NOT_CONNECTED: {
    label: 'NOT CONNECTED',
    detail: 'HERMES_DRATA_CCT_URL is not set.',
    className: 'bg-slate-200 text-slate-700',
  },
  CONFIGURED: {
    label: 'CONFIGURED',
    detail: 'Structural config check passed. Not live-validated against a Drata tenant.',
    className: 'bg-blue-100 text-blue-800',
  },
  CONFIG_INVALID: {
    label: 'CONFIG INVALID',
    detail: 'Drata CCT URL must be a well-formed https:// URL and HERMES_DRATA_API_KEY must be set.',
    className: 'bg-red-100 text-red-800',
  },
  CONNECTED: { label: 'CONNECTED', detail: '', className: 'bg-emerald-100 text-emerald-800' },
  SYNCING: { label: 'SYNCING', detail: '', className: 'bg-emerald-100 text-emerald-800' },
  DEGRADED: {
    label: 'DEGRADED',
    detail: 'One or more evidence events were dead-lettered and will not be retried.',
    className: 'bg-amber-100 text-amber-800',
  },
  ERROR: {
    label: 'ERROR',
    detail: 'Evidence export is failing; pending events are waiting to retry.',
    className: 'bg-red-100 text-red-800',
  },
  UNKNOWN: { label: 'UNKNOWN', detail: '', className: 'bg-slate-200 text-slate-700' },
}

function drataDisplayState(s) {
  if (!s.configured) return 'NOT_CONNECTED'
  if (s.connection_state === 'CONFIG_INVALID') return 'CONFIG_INVALID'
  if (s.last_error && s.events_pending > 0) return 'ERROR'
  if (s.events_dead_letter > 0) return 'DEGRADED'
  if (s.connection_state === 'CONFIGURED') return 'CONFIGURED'
  return 'UNKNOWN'
}

function formatCount(value) {
  return value === null || value === undefined ? 'unavailable' : value
}

function DrataStatusPanel({ drataStatus, drataError }) {
  if (drataError) {
    return (
      <div className="mb-6 rounded border border-slate-200 bg-white p-4 text-sm">
        <p className="font-semibold text-slate-700">Drata integration</p>
        <p className="mt-1 text-xs text-red-600">{drataError}</p>
      </div>
    )
  }
  if (!drataStatus) return null

  const display = DRATA_DISPLAY[drataDisplayState(drataStatus)]
  return (
    <div className="mb-6 rounded border border-slate-200 bg-white p-4 text-sm" data-testid="drata-status">
      <div className="flex flex-wrap items-center gap-3">
        <p className="font-semibold text-slate-700">Drata integration</p>
        <span className={`rounded px-2 py-0.5 text-xs font-semibold tracking-wide ${display.className}`}>
          {display.label}
        </span>
        <span className="text-xs text-slate-500">
          Transport: {drataStatus.transport} · Live validated:{' '}
          {drataStatus.live_validated === true ? 'yes' : 'no'} · Partner Connection:{' '}
          {drataStatus.partner_connection === true ? 'yes' : 'no'}
        </span>
      </div>
      {display.detail && <p className="mt-1 text-xs text-slate-500">{display.detail}</p>}
      <dl className="mt-3 grid grid-cols-2 gap-x-6 gap-y-1 text-xs text-slate-600 sm:grid-cols-4">
        <div>
          <dt className="text-slate-400">Pending</dt>
          <dd>{formatCount(drataStatus.events_pending)}</dd>
        </div>
        <div>
          <dt className="text-slate-400">Exported</dt>
          <dd>{formatCount(drataStatus.events_exported)}</dd>
        </div>
        <div>
          <dt className="text-slate-400">Dead letter</dt>
          <dd>{formatCount(drataStatus.events_dead_letter)}</dd>
        </div>
        <div>
          <dt className="text-slate-400">Last exported</dt>
          <dd>
            {drataStatus.last_exported_at
              ? new Date(drataStatus.last_exported_at).toLocaleString()
              : '—'}
          </dd>
        </div>
      </dl>
      {drataStatus.last_error && (
        <p className="mt-2 text-xs text-red-700">Last error: {drataStatus.last_error}</p>
      )}
    </div>
  )
}

export default function App() {
  const [status, setStatus] = useState(null)
  const [workspaces, setWorkspaces] = useState(null)
  const [workspace, setWorkspace] = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState(null)
  const [view, setView] = useState('portfolio')
  const [adminMessage, setAdminMessage] = useState(null)
  const [drataStatus, setDrataStatus] = useState(null)
  const [drataError, setDrataError] = useState(null)

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

  async function loadDrataStatus() {
    try {
      const data = await fetchDrataStatus()
      setDrataStatus(data)
      setDrataError(null)
    } catch (err) {
      setDrataStatus(null)
      setDrataError(err.message)
    }
  }

  useEffect(() => {
    load()
    loadWorkspaces()
    loadCurrentWorkspace()
    loadDrataStatus()
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
              <RequireRole allowedRoles={['org_admin', 'operator']}>
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
                    onClick={loadDrataStatus}
                    className="px-3 py-2 text-sm bg-slate-800 text-white rounded hover:bg-slate-700"
                  >
                    Check Drata Status
                  </button>
                  {adminMessage && (
                    <span className="text-xs text-slate-500">{adminMessage}</span>
                  )}
                </div>
                <DrataStatusPanel drataStatus={drataStatus} drataError={drataError} />
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
