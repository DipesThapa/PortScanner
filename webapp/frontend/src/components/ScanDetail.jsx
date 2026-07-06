import { Fragment, useEffect, useMemo, useState } from "react";
import PropTypes from "prop-types";
import NetworkGraph from "./NetworkGraph.jsx";

// --- Sub-components (Renderers) ---

const RenderSummary = ({ summary }) => {
  if (!summary) return <p className="text-muted">No summary data available.</p>;
  return (
    <div className="panel" style={{ background: 'transparent', border: 'none', padding: 0 }}>
      {Object.entries(summary).map(([key, value]) => (
        <div key={key} className="flex-row space-between" style={{ padding: '8px 0', borderBottom: '1px solid var(--border-subtle)' }}>
          <span className="text-secondary" style={{ textTransform: 'capitalize' }}>{key}</span>
          <span className="text-primary text-mono">{typeof value === "object" ? JSON.stringify(value) : String(value)}</span>
        </div>
      ))}
    </div>
  );
};

RenderSummary.propTypes = { summary: PropTypes.object };

const RenderDiff = ({ diff }) => {
  if (!diff) return <p className="text-muted">No changes detected from previous scans.</p>;
  return (
    <div className="diff-block">
      {Object.entries(diff).map(([section, data]) => (
        <div key={section} className="mb-4">
          <h4 className="text-secondary mb-2" style={{ textTransform: 'uppercase', fontSize: '0.8rem' }}>{section}</h4>
          <pre className="log-box" style={{ background: 'var(--bg-card)', border: 'none' }}>{JSON.stringify(data, null, 2)}</pre>
        </div>
      ))}
    </div>
  );
};

RenderDiff.propTypes = { diff: PropTypes.object };

const RenderPlugins = ({ plugins }) => {
  if (!plugins) return <p className="text-muted">No plugin output available.</p>;
  return (
    <div>
      {Object.entries(plugins).map(([name, payload]) => (
        <div key={name} className="mb-4">
          <h4 className="text-secondary mb-2" style={{ textTransform: 'uppercase', fontSize: '0.8rem' }}>{name}</h4>
          <pre className="log-box">{JSON.stringify(payload, null, 2)}</pre>
        </div>
      ))}
    </div>
  );
};

RenderPlugins.propTypes = { plugins: PropTypes.object };

// --- Helpers & Maps ---

const severityOrder = { critical: 4, high: 3, medium: 2, low: 1 };
const riskBadgeMap = {
  critical: "badge-severity-critical",
  high: "badge-severity-high",
  medium: "badge-severity-medium",
  low: "badge-severity-low",
};
const statusBadgeMap = {
  pending: { label: "Pending", className: "badge-info" },
  running: { label: "Running", className: "badge-info" },
  completed: { label: "Completed", className: "badge-success" },
  failed: { label: "Failed", className: "badge-error" },
};

const formatTimestamp = (value) => {
  if (!value) return "-";
  try { return new Date(value).toLocaleString(); } catch (err) { return value; }
};

const extractCommandKey = (command) => {
  if (!command) return "";
  return command.trim().split(/\s+/)[0];
};

// --- Intel Component ---

const RenderServiceIntel = ({ intel }) => {
  const findings = intel?.findings || [];
  const metrics = intel?.metrics || {};

  if (findings.length === 0) {
    return (
      <div className="flex-row" style={{ height: '200px', justifyContent: 'center', color: 'var(--text-muted)' }}>
        <p>No service intelligence findings recorded.</p>
      </div>
    );
  }

  return (
    <div className="service-intel">
      <div className="dashboard-grid mb-4" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))' }}>
        <div className="stat-card">
          <span className="stat-label">Findings</span>
          <span className="stat-value">{metrics.total_findings || findings.length}</span>
        </div>
        <div className="stat-card">
          <span className="stat-label">Targets</span>
          <span className="stat-value">{metrics.affected_targets || "-"}</span>
        </div>
      </div>

      <div className="intel-cards">
        {findings.map((finding, index) => {
          const risk = (finding.risk || "").toLowerCase();
          const badge = riskBadgeMap[risk] || "badge-muted";
          const header = `${finding.protocol || ""}/${finding.port || "?"}`;
          return (
            <article key={`${finding.service || "service"}-${index}`} className="panel" style={{ padding: '16px', background: 'var(--bg-card)' }}>
              <header className="flex-row space-between mb-4">
                <div>
                  <h4 style={{ color: 'var(--text-primary)', fontSize: '1rem' }}>{finding.summary || finding.service || "Service"}</h4>
                  <span className="text-muted text-mono" style={{ fontSize: '0.8rem' }}>{header}</span>
                </div>
                <span className={`badge ${badge}`}>{finding.risk || "info"}</span>
              </header>

              {finding.banner && (
                <div className="mb-4">
                  <div className="log-box" style={{ padding: '8px', fontSize: '0.75rem', color: 'var(--text-dim)' }}>
                    {finding.banner}
                  </div>
                </div>
              )}

              {finding.recommendations && finding.recommendations.length > 0 && (
                <div>
                  <h5 className="text-secondary" style={{ fontSize: '0.75rem', textTransform: 'uppercase' }}>Recommendations</h5>
                  <ul className="text-muted" style={{ paddingLeft: '20px', fontSize: '0.85rem' }}>
                    {finding.recommendations.map((rec, i) => <li key={i}>{rec}</li>)}
                  </ul>
                </div>
              )}
            </article>
          );
        })}
      </div>
    </div>
  );
};

RenderServiceIntel.propTypes = { intel: PropTypes.object };

// --- Deep Dive Component ---

const DeepDiveSection = ({
  scan,
  tasks,
  allowlist,
  onRunDeepDive,
  onRefreshDeepDive,
  onFetchDeepDiveOutput,
  onUploadScript,
  busy,
}) => {
  const [showUpload, setShowUpload] = useState(false);
  const [uploadName, setUploadName] = useState("");
  const [uploadContent, setUploadContent] = useState("");
  const [notice, setNotice] = useState("");
  const [expanded, setExpanded] = useState({});
  const [loadingMap, setLoadingMap] = useState({});

  useEffect(() => {
    setExpanded({});
    setLoadingMap({});
    setNotice("");
    setShowUpload(false);
    setUploadName("");
    setUploadContent("");
  }, [scan?.job_id]);

  const deepDiveTasks = useMemo(() => scan?.plugins?.["deep-dive"]?.tasks || [], [scan?.plugins]);

  const allowlistEntries = useMemo(() => {
    if (!allowlist || !Array.isArray(allowlist.entries)) return [];
    return allowlist.entries;
  }, [allowlist]);

  const allowlistSet = useMemo(() => new Set(allowlistEntries), [allowlistEntries]);
  const enforcementEnabled = allowlist?.enforced !== false;

  const allCommands = useMemo(() => {
    const collected = [];
    deepDiveTasks.forEach((task) => {
      (task.commands || []).forEach((cmd) => cmd && collected.push(cmd));
    });
    return Array.from(new Set(collected));
  }, [deepDiveTasks]);

  const commandsByAllowance = useMemo(() => {
    if (!enforcementEnabled || allowlistSet.size === 0) return { allowed: allCommands, blocked: [] };
    const allowed = [], blocked = [];
    allCommands.forEach(cmd => {
      (allowlistSet.has(extractCommandKey(cmd)) ? allowed : blocked).push(cmd);
    });
    return { allowed, blocked };
  }, [allCommands, allowlistSet, enforcementEnabled]);

  const sortedTasks = useMemo(() => {
    return [...(tasks || [])].sort((a, b) => new Date(b.created_at || 0) - new Date(a.created_at || 0));
  }, [tasks]);

  const hasCommands = deepDiveTasks.length > 0;

  const handleRunAll = async () => {
    if (!scan?.job_id || !onRunDeepDive || allCommands.length === 0) return;
    const toRun = commandsByAllowance.allowed;
    if (enforcementEnabled && allowlistSet.size > 0 && toRun.length === 0) {
      setNotice("No allowlisted commands are available for automated execution.");
      return;
    }
    setNotice("");
    await onRunDeepDive(scan.job_id, toRun.length > 0 ? toRun : allCommands);
  };

  const handleRunCommand = (command) => {
    if (!scan?.job_id || !onRunDeepDive || !command) return;
    const key = extractCommandKey(command);
    if (enforcementEnabled && allowlistSet.size > 0 && !allowlistSet.has(key)) {
      setNotice(`Command '${key}' is blocked by the deep-dive allowlist.`);
      return;
    }
    setNotice("");
    onRunDeepDive(scan.job_id, [command]);
  };

  const handleToggleTask = async (task) => {
    if (!task) return;
    const isOpen = !!expanded[task.id];
    if (!isOpen && onFetchDeepDiveOutput && !task.stdout && !task.stderr) {
      setLoadingMap((prev) => ({ ...prev, [task.id]: true }));
      try { await onFetchDeepDiveOutput(task.id); }
      catch (err) { /* ignore */ }
      finally { setLoadingMap((prev) => { const n = { ...prev }; delete n[task.id]; return n; }); }
    }
    setExpanded((prev) => ({ ...prev, [task.id]: !isOpen }));
  };

  const handleUploadSubmit = (e) => {
    e.preventDefault();
    if (onUploadScript) {
      onUploadScript(uploadName, uploadContent);
      setShowUpload(false);
      setUploadName("");
      setUploadContent("");
    }
  };

  return (
    <div className="deep-dive-section">
      <div className="flex-row space-between mb-4">
        <div></div>
        <div className="flex-row">
          {onUploadScript && (
            <button className="btn btn-secondary" disabled={busy} onClick={() => setShowUpload(!showUpload)}>
              {showUpload ? "Cancel" : "Upload Script"}
            </button>
          )}
          <button className="btn btn-secondary" disabled={!scan?.job_id || busy} onClick={() => onRefreshDeepDive && onRefreshDeepDive(scan.job_id)}>
            Refresh
          </button>
          <button className="btn btn-primary" disabled={!hasCommands || busy} onClick={handleRunAll}>
            Run All Suggested
          </button>
        </div>
      </div>

      {showUpload && (
        <div className="panel mb-4" style={{ background: 'var(--bg-card)', padding: '16px' }}>
          <form onSubmit={handleUploadSubmit}>
            <h4 className="mb-4">Upload Custom Script</h4>
            <div className="form-group">
              <label>Script Name (e.g. audit.sh)</label>
              <input type="text" required value={uploadName} onChange={e => setUploadName(e.target.value)} />
            </div>
            <div className="form-group">
              <label>Content</label>
              <textarea rows={6} required value={uploadContent} onChange={e => setUploadContent(e.target.value)} className="text-mono" />
            </div>
            <div className="flex-row" style={{ justifyContent: 'flex-end' }}>
              <button type="submit" className="btn btn-primary">Upload</button>
            </div>
          </form>
        </div>
      )}

      {notice && <div className="alert alert-info">{notice}</div>}

      {/* Suggested Commands Grid */}
      {hasCommands ? (
        <div className="dashboard-grid mb-4" style={{ gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))' }}>
          {deepDiveTasks.map((task, index) => {
            const titleParts = [task.service || "service", task.port || "", task.target].filter(Boolean).join(" • ");
            return (
              <div key={`${task.service}-${index}`} className="panel" style={{ padding: '12px', background: 'var(--bg-card)' }}>
                <div className="flex-row space-between mb-2">
                  <h5 className="text-primary">{titleParts}</h5>
                  {task.credentials && <span className="badge badge-info">Creds</span>}
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                  {(task.commands || []).map((cmd, i) => {
                    const key = extractCommandKey(cmd);
                    const blocked = enforcementEnabled && allowlistSet.size > 0 && !allowlistSet.has(key);
                    return (
                      <div key={i} className="flex-row input-group">
                        <input type="text" readOnly value={cmd} className="text-mono" style={{ fontSize: '0.75rem', background: 'rgba(0,0,0,0.3)', border: 'none' }} />
                        <button className="btn btn-secondary" style={{ padding: '4px 8px' }} disabled={busy || blocked} onClick={() => handleRunCommand(cmd)}>Run</button>
                      </div>
                    )
                  })}
                </div>
              </div>
            )
          })}
        </div>
      ) : (
        <p className="text-muted mb-4">No automated deep-dive suggestions available.</p>
      )}

      {/* Execution Log */}
      <div className="panel">
        <div className="panel-header">
          <h2>Execution Log</h2>
        </div>
        <div className="panel-body" style={{ padding: 0 }}>
          {sortedTasks.length === 0 ? (
            <div style={{ padding: '16px' }} className="text-muted">No tasks executed yet.</div>
          ) : (
            <table style={{ width: '100%' }}>
              <thead>
                <tr>
                  <th>Command</th>
                  <th>Status</th>
                  <th>Result</th>
                  <th>Time</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {sortedTasks.map(task => {
                  const badgeVal = statusBadgeMap[(task.status || '').toLowerCase()] || { label: task.status, className: "badge-muted" };
                  return (
                    <Fragment key={task.id}>
                      <tr>
                        <td><code style={{ fontSize: '0.75rem' }}>{task.command}</code></td>
                        <td><span className={`badge ${badgeVal.className}`}>{badgeVal.label}</span></td>
                        <td>{task.return_code ?? "—"}</td>
                        <td>{formatTimestamp(task.created_at)}</td>
                        <td>
                          <button className="btn btn-secondary" style={{ padding: '2px 8px', fontSize: '0.7rem' }} onClick={() => handleToggleTask(task)}>
                            {expanded[task.id] ? "Hide" : "View"}
                          </button>
                        </td>
                      </tr>
                      {expanded[task.id] && (
                        <tr>
                          <td colSpan={5} style={{ padding: '0', background: '#000' }}>
                            {loadingMap[task.id] ? (
                              <div style={{ padding: '12px' }} className="text-muted">Loading...</div>
                            ) : (
                              <div style={{ padding: '12px', display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '12px' }}>
                                <div><h6 className="text-muted mb-2">STDOUT</h6><pre className="log-box" style={{ border: 'none' }}>{task.stdout || ""}</pre></div>
                                <div><h6 className="text-muted mb-2">STDERR</h6><pre className="log-box" style={{ border: 'none' }}>{task.stderr || ""}</pre></div>
                              </div>
                            )}
                          </td>
                        </tr>
                      )}
                    </Fragment>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>
      </div>
    </div>
  );
};
DeepDiveSection.propTypes = { scan: PropTypes.object, tasks: PropTypes.array, allowlist: PropTypes.object, onRunDeepDive: PropTypes.func, onRefreshDeepDive: PropTypes.func, onFetchDeepDiveOutput: PropTypes.func, onUploadScript: PropTypes.func, busy: PropTypes.bool };


// --- Vulns Component ---

const RenderVulnerabilities = ({ vulnerabilities }) => {
  if (!vulnerabilities?.length) return <p className="text-muted">No vulnerabilities detected.</p>;

  const sorted = [...vulnerabilities].sort((a, b) => {
    return (severityOrder[(b.severity || '').toLowerCase()] || 0) - (severityOrder[(a.severity || '').toLowerCase()] || 0);
  });

  return (
    <table className="vuln-table">
      <thead>
        <tr>
          <th>Title</th>
          <th>Severity</th>
          <th>Location</th>
          <th>CVEs</th>
        </tr>
      </thead>
      <tbody>
        {sorted.map((item, i) => {
          const sevKey = (item.severity || '').toLowerCase();
          const badgeClass = riskBadgeMap[sevKey] || 'badge-info';
          return (
            <tr key={i}>
              <td style={{ fontWeight: 500 }}>{item.title || item.script_id}</td>
              <td><span className={`badge ${badgeClass}`}>{item.severity || 'Info'}</span></td>
              <td className="text-mono text-muted">{item.port ? `${item.port}/${item.protocol || ''}` : item.scope}</td>
              <td className="text-mono">{Array.isArray(item.cves) ? item.cves.join(", ") : ""}</td>
            </tr>
          )
        })}
      </tbody>
    </table>
  );
};
RenderVulnerabilities.propTypes = { vulnerabilities: PropTypes.array };

// --- Main ScanDetail Component ---

function ScanDetail(props) {
  const { scan } = props;
  const [activeTab, setActiveTab] = useState("overview");
  const [isExpanded, setIsExpanded] = useState(false);

  // Reset tab when scan changes
  useEffect(() => { setActiveTab("overview"); }, [scan?.job_id]);

  if (!scan) {
    return (
      <div className="panel scan-detail-panel">
        <div className="panel-header">
          <h2>Scan Details</h2>
        </div>
        <div className="panel-body" style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', flexDirection: 'column', color: 'var(--text-secondary)' }}>
          <p>Select a scan job to inspect details.</p>
        </div>
      </div>
    );
  }

  const jobLabel = scan.job_id.substring(0, 8);
  const statusBadge = (statusBadgeMap[scan.status] || {}).className || "badge-muted";

  return (
    <div className={`panel scan-detail-panel ${isExpanded ? 'panel-fullscreen' : ''}`}>
      <div className="panel-header">
        <div className="flex-row">
          <h2 style={{ marginRight: '16px' }}>Details</h2>
          <span className="text-mono text-muted" style={{ fontSize: '0.85rem' }}>#{jobLabel}</span>
          <span className={`badge ${statusBadge}`} style={{ marginLeft: '8px' }}>{scan.status}</span>
        </div>
        <div className="flex-row">
          <button className="btn-icon" onClick={() => props.onDeleteScan && props.onDeleteScan(scan.job_id)} title="Delete Scan" style={{ marginRight: '8px', color: '#ef4444' }}>
            <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M3 6h18M19 6v14a2 2 0 0 1-2 2H7a2 2 0 0 1-2-2V6m3 0V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2" /></svg>
          </button>
          <button className="btn-icon" onClick={() => setIsExpanded(!isExpanded)} title={isExpanded ? "Collapse" : "Expand"}>
            {isExpanded ? (
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M8 3v3a2 2 0 0 1-2 2H3m18 0h-3a2 2 0 0 1-2-2V3m0 18v-3a2 2 0 0 1 2-2h3M3 16h3a2 2 0 0 1 2 2v3" /></svg>
            ) : (
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2"><path d="M15 3h6v6M9 21H3v-6M21 3l-7 7M3 21l7-7" /></svg>
            )}
          </button>
        </div>
      </div>

      <nav className="tabs-nav">
        <button className={`tab-btn ${activeTab === 'overview' ? 'active' : ''}`} onClick={() => setActiveTab('overview')}>Overview</button>
        <button className={`tab-btn ${activeTab === 'network' ? 'active' : ''}`} onClick={() => setActiveTab('network')}>Network Intel</button>
        <button className={`tab-btn ${activeTab === 'topology' ? 'active' : ''}`} onClick={() => setActiveTab('topology')}>Topology</button>
        <button className={`tab-btn ${activeTab === 'vulnerabilities' ? 'active' : ''}`} onClick={() => setActiveTab('vulnerabilities')}>Vulnerabilities</button>
        <button className={`tab-btn ${activeTab === 'terminal' ? 'active' : ''}`} onClick={() => setActiveTab('terminal')}>Terminal / Deep Dive</button>
        <button className={`tab-btn ${activeTab === 'logs' ? 'active' : ''}`} onClick={() => setActiveTab('logs')}>Raw Logs</button>
      </nav>

      <div className="panel-body">
        {activeTab === 'overview' && (
          <div className="dashboard-grid" style={{ gridTemplateColumns: '1fr 1fr' }}>
            <div>
              <h3 className="mb-4">Summary</h3>
              <RenderSummary summary={scan.summary} />
            </div>
            <div>
              <h3 className="mb-4">Artifacts & Changes</h3>
              <RenderDiff diff={scan.diff} />
              <div className="mt-4">
                <h4 className="text-secondary mb-2" style={{ fontSize: '0.8rem' }}>ARTIFACTS</h4>
                {Object.keys(scan.artifacts || {}).length === 0 ? <p className="text-muted">None</p> : (
                  <ul className="text-mono text-sm pl-4">
                    {Object.keys(scan.artifacts).map(k => <li key={k}>{k}</li>)}
                  </ul>
                )}
              </div>
            </div>
          </div>
        )}

        {activeTab === 'network' && (
          <RenderServiceIntel intel={scan.plugins?.['service-intel']} />
        )}

        {activeTab === 'topology' && (
          <div style={{ height: '100%', minHeight: '500px' }}>
            <NetworkGraph scan={scan} />
          </div>
        )}

        {activeTab === 'vulnerabilities' && (
          <RenderVulnerabilities vulnerabilities={scan.vulnerabilities} />
        )}

        {activeTab === 'terminal' && (
          <DeepDiveSection
            scan={scan}
            tasks={props.deepDiveTasks}
            allowlist={props.deepDiveAllowlist}
            busy={props.deepDiveBusy}
            onRunDeepDive={props.onRunDeepDive}
            onRefreshDeepDive={props.onRefreshDeepDive}
            onFetchDeepDiveOutput={props.onFetchDeepDiveOutput}
            onUploadScript={props.onUploadScript}
          />
        )}

        {activeTab === 'logs' && (
          <div>
            <div className="mb-4">
              <h3>Standard Output</h3>
              <pre className="log-box">{scan.logs || "(empty)"}</pre>
            </div>
            <div className="mb-4">
              <h3>Plugin Raw Data</h3>
              <RenderPlugins plugins={scan.plugins} />
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

ScanDetail.propTypes = {
  scan: PropTypes.object,
  deepDiveTasks: PropTypes.array,
  deepDiveAllowlist: PropTypes.object,
  deepDiveBusy: PropTypes.bool,
  onRunDeepDive: PropTypes.func,
  onRefreshDeepDive: PropTypes.func,
  onFetchDeepDiveOutput: PropTypes.func,
  onUploadScript: PropTypes.func,
  onDeleteScan: PropTypes.func,
};

export default ScanDetail;
