import React from 'react'
import { LineChart, Line, ResponsiveContainer } from 'recharts'

export default function TrendSparkline({ data }) {
  const chartData = (data || [0, 0, 0, 0, 0, 0, 0]).map((v, i) => ({
    i,
    v,
  }))

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
