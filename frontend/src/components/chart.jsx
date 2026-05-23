import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer } from "recharts";

export default function Chart({ alerts }) {

  const data = [
    { name: "HIGH", value: alerts.filter(a => a[1] === "HIGH").length },
    { name: "MEDIUM", value: alerts.filter(a => a[1] === "MEDIUM").length },
    { name: "LOW", value: alerts.filter(a => a[1] === "LOW").length },
  ];

  return (
    <div className="glass p-4 h-64">
      <h2 className="mb-2">📊 Risk Distribution</h2>

      <ResponsiveContainer width="100%" height="100%">
        <BarChart data={data}>
          <XAxis dataKey="name" stroke="#aaa" />
          <YAxis />
          <Tooltip />
          <Bar dataKey="value" fill="#38bdf8" />
        </BarChart>
      </ResponsiveContainer>
    </div>
  );
}