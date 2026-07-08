import PropTypes from "prop-types";

function Dashboard({ scans, loading }) {
  if (loading) {
    return (
      <section className="dashboard-grid skeleton-grid">
        {[...Array(4)].map((_, index) => (
          <div key={index} className="skeleton-card" />
        ))}
      </section>
    );
  }

  const running = scans.filter((scan) => scan.status === "running").length;

  // Aggregate totals from completed scans
  let totalHosts = 0;
  let totalVulns = 0;
  let totalOpenPorts = 0;

  scans.forEach(scan => {
    if (scan.summary) {
      totalHosts += (scan.summary.hosts || 0);
      totalVulns += (scan.summary.vulnerabilities || 0);
      totalOpenPorts += (scan.summary.open_ports || 0);
    }
  });

  return (
    <section className="dashboard-grid">
      <div className="stat-card">
        <span className="stat-label">Active Jobs</span>
        <span className={`stat-value ${running > 0 ? "glow" : ""}`} style={{ color: running > 0 ? "var(--status-info)" : "inherit" }}>
          {running}
        </span>
      </div>

      <div className="stat-card">
        <span className="stat-label">Total Vulnerabilities</span>
        <span className="stat-value" style={{ color: totalVulns > 0 ? "var(--status-error)" : "inherit" }}>
          {totalVulns}
        </span>
      </div>

      <div className="stat-card">
        <span className="stat-label">Total Hosts Scanned</span>
        <span className="stat-value">{totalHosts}</span>
      </div>

      <div className="stat-card">
        <span className="stat-label">Total Open Ports</span>
        <span className="stat-value">{totalOpenPorts}</span>
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
