export default function KPI({ title, value, color }) {
  return (
    <div className={`glass p-4 hover-card neon ${color}`}>
      <div>{title}</div>
      <div className="text-2xl font-bold">{value}</div>
    </div>
  );
}