import PropTypes from "prop-types";

function WorkerPanel({ workers }) {
  return (
    <div className="panel">
      <div className="panel-header">
        <h2>Worker Nodes</h2>
      </div>
      <div className="panel-body worker-list">
        {workers.length === 0 ? (
          <p className="muted">
            No worker config detected. Define nodes in an orchestrator config file if you plan to distribute scans.
          </p>
        ) : (
          workers.map((worker) => (
            <div key={worker.address} className="worker-card">
              <div>
                <h3>{worker.name}</h3>
                <p className="muted">{worker.address}</p>
                <p className={`badge ${worker.reachable ? "badge-success" : "badge-error"}`}>
                  {worker.reachable ? "reachable" : "offline"}
                </p>
              </div>
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
};

WorkerPanel.defaultProps = {
  workers: [],
};

export default WorkerPanel;
