import PropTypes from "prop-types";

const formatDate = (value) => {
  if (!value) return "-";
  try {
    return new Date(value).toLocaleString();
  } catch (err) {
    return value;
  }
};

function Dashboard({ scans, loading }) {
  if (loading) {
    return (
      <section className="dashboard skeleton-grid">
        {[...Array(4)].map((_, index) => (
          <div key={index} className="skeleton-card" />
        ))}
      </section>
    );
  }

  const total = scans.length;
  const running = scans.filter((scan) => scan.status === "running").length;
  const failed = scans.filter((scan) => scan.status === "failed").length;
  const latest = scans[0];
  return (
    <section className="dashboard">
      <div className="card">
        <h3>Total Jobs</h3>
        <p>{loading ? "…" : total}</p>
      </div>
      <div className="card">
        <h3>Running</h3>
        <p>{loading ? "…" : running}</p>
      </div>
      <div className="card">
        <h3>Failed</h3>
        <p>{loading ? "…" : failed}</p>
      </div>
      <div className="card card-wide">
        <h3>Latest Summary</h3>
        {latest ? (
          <ul>
            <li>
              <strong>Job:</strong> {latest.job_id}
            </li>
            <li>
              <strong>Status:</strong> {latest.status}
            </li>
            <li>
              <strong>Trend:</strong> {latest.trend || "-"}
            </li>
            <li>
              <strong>Last Updated:</strong> {formatDate(latest.summary?.timestamp)}
            </li>
          </ul>
        ) : (
          <p>No scans yet. Kick off a new job.</p>
        )}
      </div>
    </section>
  );
}

Dashboard.propTypes = {
  scans: PropTypes.arrayOf(PropTypes.object).isRequired,
  loading: PropTypes.bool,
};

Dashboard.defaultProps = {
  loading: false,
};

export default Dashboard;
