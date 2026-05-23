export default function AlertCard({ alert, onClick }) {
  return (
    <div
      onClick={() => onClick(alert)}
      className="p-3 rounded-lg bg-[#0f172a] border border-gray-800 cursor-pointer hover-card"
    >
      <div className="flex justify-between text-sm">
        <span>ID: {alert[0]}</span>
        <span className={
          alert[1]==="HIGH" ? "text-red-400" :
          alert[1]==="MEDIUM" ? "text-yellow-400" :
          "text-green-400"
        }>
          {alert[1]}
        </span>
      </div>

      <div className="text-xs text-gray-400 mt-1">
        {alert[3]}
      </div>
    </div>
  );
}