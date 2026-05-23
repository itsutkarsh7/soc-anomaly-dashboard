export default function AlertModal({ alert, onClose }) {
  if (!alert) return null;

  return (
    <div className="fixed inset-0 bg-black bg-opacity-70 flex justify-center items-center">

      <div className="glass p-6 w-[400px]">
        <h2 className="text-xl mb-4">🔍 Alert Details</h2>

        <p><b>ID:</b> {alert[0]}</p>
        <p><b>Risk:</b> {alert[1]}</p>
        <p><b>Score:</b> {alert[2]}</p>
        <p><b>Reason:</b> {alert[3]}</p>
        <p><b>Status:</b> {alert[4]}</p>

        <button 
          className="mt-4 bg-blue-500 px-4 py-2 rounded"
          onClick={onClose}
        >
          Close
        </button>
      </div>

    </div>
  );
}