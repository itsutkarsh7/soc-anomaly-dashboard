export default function Sidebar() {
  return (
    <div className="w-64 bg-[#020617] border-r border-gray-800 p-6">
      <h2 className="text-xl font-bold mb-6">🛡️ ZeTheta</h2>

      <nav className="space-y-4 text-gray-400">
        <div className="hover:text-white cursor-pointer">Dashboard</div>
        <div className="hover:text-white cursor-pointer">Alerts</div>
        <div className="hover:text-white cursor-pointer">Analytics</div>
      </nav>
    </div>
  );
}