import { useState } from "react";
import PropTypes from "prop-types";

function WorkerPanel({ workers, onAdd, onDelete }) {
  const [showAdd, setShowAdd] = useState(false);
  const [newWorker, setNewWorker] = useState({ name: "", address: "", capabilities: "{}" });

  const handleSubmit = (e) => {
    e.preventDefault();
    try {
      const caps = JSON.parse(newWorker.capabilities);
      onAdd({ ...newWorker, capabilities: caps });
      setShowAdd(false);
      setNewWorker({ name: "", address: "", capabilities: "{}" });
    } catch (err) {
      alert("Invalid JSON for capabilities");
    }
  };

  return (
    <div className="panel">
      <div className="panel-header">
        <h2>Worker Nodes</h2>
        <button className="btn btn-sm" onClick={() => setShowAdd(!showAdd)}>
          {showAdd ? "Cancel" : "+ Add Worker"}
        </button>
      </div>

      {showAdd && (
        <form onSubmit={handleSubmit} className="panel-body worker-form">
          <div className="form-group">
            <label>Name</label>
            <input
              type="text"
              required
              value={newWorker.name}
              onChange={(e) => setNewWorker({ ...newWorker, name: e.target.value })}
            />
          </div>
          <div className="form-group">
            <label>Address (host:port)</label>
            <input
              type="text"
              required
              placeholder="192.168.1.5:22"
              value={newWorker.address}
              onChange={(e) => setNewWorker({ ...newWorker, address: e.target.value })}
            />
          </div>
          <div className="form-group">
            <label>Capabilities (JSON)</label>
            <textarea
              rows={3}
              value={newWorker.capabilities}
              onChange={(e) => setNewWorker({ ...newWorker, capabilities: e.target.value })}
            />
          </div>
          <button type="submit" className="btn btn-primary">Register</button>
        </form>
      )}

      <div className="panel-body worker-list">
        {workers.length === 0 ? (
          <p className="muted">
            No worker config detected. Add a node to distribute scans.
          </p>
        ) : (
          workers.map((worker) => (
            <div key={worker.address} className="worker-card">
              <div className="worker-header">
                <div>
                  <h3>{worker.name}</h3>
                  <p className="muted">{worker.address}</p>
                </div>
                <button
                  className="btn btn-danger btn-sm"
                  onClick={() => onDelete(worker.address)}
                >
                  Delete
                </button>
              </div>
              <p className={`badge ${worker.reachable ? "badge-success" : "badge-error"}`}>
                {worker.reachable ? "reachable" : "offline"}
              </p>
              <div className="worker-capabilities">
                {Object.keys(worker.capabilities || {}).length === 0 ? (
                  <p className="muted">No capabilities listed.</p>
                ) : (
                  <ul>
                    {Object.entries(worker.capabilities).map(([key, value]) => (
                      <li key={key}>
                        <strong>{key}:</strong> {value}
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            </div>
          ))
        )}
      </div>
    </div>
  );
}

WorkerPanel.propTypes = {
  workers: PropTypes.arrayOf(
    PropTypes.shape({
      name: PropTypes.string.isRequired,
      address: PropTypes.string.isRequired,
      reachable: PropTypes.bool.isRequired,
      capabilities: PropTypes.object,
    }),
  ),
  onAdd: PropTypes.func.isRequired,
  onDelete: PropTypes.func.isRequired,
};

WorkerPanel.defaultProps = {
  workers: [],
};

export default WorkerPanel;
