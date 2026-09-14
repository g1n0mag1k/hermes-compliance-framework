import {
  Line,
  LineChart,
  ResponsiveContainer,
} from "recharts";

export default function TrendSparkline({ data }) {
  const points =
    Array.isArray(data) && data.length > 0
      ? data
      : [
          { day: "D-6", value: 0 },
          { day: "D-5", value: 0 },
          { day: "D-4", value: 0 },
          { day: "D-3", value: 0 },
          { day: "D-2", value: 0 },
          { day: "D-1", value: 0 },
          { day: "D0", value: 0 },
        ];

  return (
    <div className="h-10 w-28">
      <ResponsiveContainer width="100%" height="100%">
        <LineChart data={points} margin={{ top: 4, right: 4, bottom: 4, left: 4 }}>
          <Line
            type="monotone"
            dataKey="value"
            stroke="#2563EB"
            strokeWidth={2}
            dot={false}
            isAnimationActive={false}
          />
        </LineChart>
      </ResponsiveContainer>
    </div>
  );
}
