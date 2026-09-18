import React, { useEffect, useState } from 'react'
import { LineChart, Line, ResponsiveContainer } from 'recharts'
import { fetchScanHistory } from '../lib/api.js'

const FALLBACK_DATA = [1, 2, 1, 3, 2, 4, 1]

export default function TrendSparkline({ apiKey }) {
  const [chartData, setChartData] = useState(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let cancelled = false

    async function load() {
      setLoading(true)
      try {
        const data = await fetchScanHistory(apiKey, 7)
        if (!cancelled) {
          setChartData(
            data.history.map((entry, i) => ({
              i,
              v: entry.scan_count,
            }))
          )
        }
      } catch {
        if (!cancelled) {
          setChartData(FALLBACK_DATA.map((v, i) => ({ i, v })))
        }
      } finally {
        if (!cancelled) {
          setLoading(false)
        }
      }
    }

    if (apiKey) {
      load()
    } else {
      setChartData(FALLBACK_DATA.map((v, i) => ({ i, v })))
      setLoading(false)
    }

    return () => {
      cancelled = true
    }
  }, [apiKey])

  if (loading) {
    return (
      <div className="h-10 flex items-center">
        <p className="text-xs text-slate-400">Loading...</p>
      </div>
    )
  }

  return (
    <ResponsiveContainer width="100%" height={40}>
      <LineChart data={chartData}>
        <Line
          type="monotone"
          dataKey="v"
          stroke="#2563EB"
          strokeWidth={2}
          dot={false}
          isAnimationActive={false}
        />
      </LineChart>
    </ResponsiveContainer>
  )
}
