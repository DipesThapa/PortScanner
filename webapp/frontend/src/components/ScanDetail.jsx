import { Fragment, useEffect, useMemo, useState } from "react";
import PropTypes from "prop-types";

const RenderSummary = ({ summary }) => {
  if (!summary) return <p>No summary yet.</p>;
  return (
    <table className="summary-table">
      <tbody>
        {Object.entries(summary).map(([key, value]) => (
          <tr key={key}>
            <th>{key}</th>
            <td>{typeof value === "object" ? JSON.stringify(value) : String(value)}</td>
          </tr>
        ))}
      </tbody>
    </table>
  );
};

RenderSummary.propTypes = {
  summary: PropTypes.object,
};

RenderSummary.defaultProps = {
  summary: null,
};

const RenderDiff = ({ diff }) => {
  if (!diff) return <p>No diff available.</p>;
  return (
    <div className="diff-block">
      {Object.entries(diff).map(([section, data]) => (
        <div key={section}>
          <h4>{section}</h4>
          <pre>{JSON.stringify(data, null, 2)}</pre>
        </div>
      ))}
    </div>
  );
};

RenderDiff.propTypes = {
  diff: PropTypes.object,
};

RenderDiff.defaultProps = {
  diff: null,
};

const RenderPlugins = ({ plugins }) => {
  if (!plugins) return <p>No plugin output.</p>;
  return (
    <div className="diff-block">
      {Object.entries(plugins).map(([name, payload]) => (
        <div key={name}>
          <h4>{name}</h4>
          <pre>{JSON.stringify(payload, null, 2)}</pre>
        </div>
      ))}
    </div>
  );
};

RenderPlugins.propTypes = {
  plugins: PropTypes.object,
};

RenderPlugins.defaultProps = {
  plugins: null,
};

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
  try {
    return new Date(value).toLocaleString();
  } catch (err) {
    return value;
  }
};

const extractCommandKey = (command) => {
  if (!command) return "";
  return command.trim().split(/\s+/)[0];
};

const RenderServiceIntel = ({ intel }) => {
  const findings = intel?.findings || [];
  const metrics = intel?.metrics || {};
  const riskCounts = metrics.by_risk || {};

  if (findings.length === 0) {
    return <p className="muted">No service intelligence findings were recorded.</p>;
  }

  const riskSummary = Object.keys(riskCounts).sort(
    (a, b) => (severityOrder[b] || 0) - (severityOrder[a] || 0),
  );

  return (
    <div className="service-intel">
      <div className="service-intel-summary">
        <div className="intel-metric">
          <span className="metric-label">Findings</span>
          <span className="metric-value">{metrics.total_findings || findings.length}</span>
        </div>
        <div className="intel-metric">
          <span className="metric-label">Affected Targets</span>
          <span className="metric-value">{metrics.affected_targets || "-"}</span>
        </div>
        <div className="intel-metric risk-breakdown">
          <span className="metric-label">Risk Breakdown</span>
          <div className="risk-pills">
            {riskSummary.length === 0 && <span className="badge badge-muted">n/a</span>}
            {riskSummary.map((key) => (
              <span key={key} className={`badge ${riskBadgeMap[key] || "badge-muted"}`}>
                {key}: {riskCounts[key]}
              </span>
            ))}
          </div>
        </div>
      </div>
      <div className="intel-cards">
        {findings.map((finding, index) => {
          const risk = (finding.risk || "").toLowerCase();
          const badge = riskBadgeMap[risk] || "badge-muted";
          const header = `${finding.protocol || ""}/${finding.port || "?"}`;
          return (
            <article key={`${finding.service || "service"}-${index}`} className="intel-card">
              <header>
                <div>
                  <h4>{finding.summary || finding.service || "Service"}</h4>
                  <span className="intel-location">{header}</span>
                </div>
                <span className={`badge ${badge}`}>{finding.risk || "info"}</span>
              </header>
              {finding.observations && finding.observations.length > 0 && (
                <div className="intel-section">
                  <span className="intel-section-title">Observations</span>
                  <ul>
                    {finding.observations.map((obs, obsIndex) => (
                      <li key={`obs-${obsIndex}`}>{obs}</li>
                    ))}
                  </ul>
                </div>
              )}
              {finding.recommendations && finding.recommendations.length > 0 && (
                <div className="intel-section">
                  <span className="intel-section-title">Recommendations</span>
                  <ul>
                    {finding.recommendations.map((rec, recIndex) => (
                      <li key={`rec-${recIndex}`}>{rec}</li>
                    ))}
                  </ul>
                </div>
              )}
              {finding.references && finding.references.length > 0 && (
                <div className="intel-section intel-references">
                  <span className="intel-section-title">References</span>
                  <ul>
                    {finding.references.map((ref, refIndex) => (
                      <li key={`ref-${refIndex}`}>
                        {ref.startsWith("http") ? (
                          <a href={ref} target="_blank" rel="noreferrer">
                            {ref}
                          </a>
                        ) : (
                          ref
                        )}
                      </li>
                    ))}
                  </ul>
                </div>
              )}
              {finding.banner && (
                <div className="intel-section">
                  <span className="intel-section-title">Banner</span>
                  <code className="intel-banner">{finding.banner}</code>
                </div>
              )}
            </article>
          );
        })}
      </div>
    </div>
  );
};

RenderServiceIntel.propTypes = {
  intel: PropTypes.shape({
    findings: PropTypes.arrayOf(PropTypes.object),
    metrics: PropTypes.object,
  }),
};

RenderServiceIntel.defaultProps = {
  intel: null,
};

const DeepDiveSection = ({
  scan,
  tasks,
  allowlist,
  onRunDeepDive,
  onRefreshDeepDive,
  onFetchDeepDiveOutput,
  busy,
}) => {
  const [expanded, setExpanded] = useState({});
  const [loadingMap, setLoadingMap] = useState({});
  const [notice, setNotice] = useState("");

  useEffect(() => {
    setExpanded({});
    setLoadingMap({});
    setNotice("");
  }, [scan?.job_id]);

  const deepDiveTasks = useMemo(() => {
    const plugin = scan?.plugins?.["deep-dive"];
    if (!plugin) return [];
    return Array.isArray(plugin.tasks) ? plugin.tasks : [];
  }, [scan?.plugins]);

  const allowlistEntries = useMemo(() => {
    if (!allowlist || !Array.isArray(allowlist.entries)) return [];
    return allowlist.entries;
  }, [allowlist]);

  const allowlistSet = useMemo(() => new Set(allowlistEntries), [allowlistEntries]);
  const enforcementEnabled = allowlist?.enforced !== false;

  const allCommands = useMemo(() => {
    const collected = [];
    deepDiveTasks.forEach((task) => {
      (task.commands || []).forEach((command) => {
        if (command) {
          collected.push(command);
        }
      });
    });
    return Array.from(new Set(collected));
  }, [deepDiveTasks]);

  const commandsByAllowance = useMemo(() => {
    if (!enforcementEnabled || allowlistSet.size === 0) {
      return { allowed: allCommands, blocked: [] };
    }
    const allowedList = [];
    const blockedList = [];
    allCommands.forEach((command) => {
      const key = extractCommandKey(command);
      if (allowlistSet.has(key)) {
        allowedList.push(command);
      } else {
        blockedList.push(command);
      }
    });
    return { allowed: allowedList, blocked: blockedList };
  }, [allCommands, allowlistSet, enforcementEnabled]);

  const sortedTasks = useMemo(() => {
    const list = Array.isArray(tasks) ? tasks : [];
    return [...list].sort((a, b) => {
      const timeA = a?.created_at ? new Date(a.created_at).getTime() : 0;
      const timeB = b?.created_at ? new Date(b.created_at).getTime() : 0;
      return timeB - timeA;
    });
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

  const handleRefresh = () => {
    if (!scan?.job_id || !onRefreshDeepDive) return;
    onRefreshDeepDive(scan.job_id);
  };

  const handleToggleTask = async (task) => {
    if (!task) return;
    const isOpen = !!expanded[task.id];
    if (!isOpen && onFetchDeepDiveOutput && !task.stdout && !task.stderr) {
      setLoadingMap((prev) => ({ ...prev, [task.id]: true }));
      try {
        await onFetchDeepDiveOutput(task.id);
      } catch (err) {
        // Error surfaced via parent; keep UI responsive.
      } finally {
        setLoadingMap((prev) => {
          const next = { ...prev };
          delete next[task.id];
          return next;
        });
      }
    }
    setExpanded((prev) => ({ ...prev, [task.id]: !isOpen }));
  };

  return (
    <section className="deep-dive-section">
      <div className="deep-dive-header">
        <h3>Deep-Dive Follow-ups</h3>
        <div className="deep-dive-actions">
          <button
            type="button"
            className="btn btn-secondary"
            onClick={handleRefresh}
            disabled={!scan?.job_id || busy}
          >
            Refresh Tasks
          </button>
          <button
            type="button"
            className="btn btn-primary"
            onClick={handleRunAll}
            disabled={!hasCommands || busy}
          >
            Run All
          </button>
        </div>
      </div>
      {notice && <div className="alert alert-info deep-dive-notice">{notice}</div>}
      {enforcementEnabled && (
        <div className="deep-dive-allowlist">
          <span className="muted">Allowlisted commands:</span>
          {allowlistEntries.length === 0 ? (
            <span className="badge badge-info">All commands</span>
          ) : (
            <div className="chip-group">
              {allowlistEntries.map((entry) => (
                <span key={entry} className="chip">
                  {entry}
                </span>
              ))}
            </div>
          )}
        </div>
      )}
      {!hasCommands ? (
        <p className="muted">No deep-dive commands were suggested for this scan.</p>
      ) : (
        <div className="deep-dive-commands">
          {deepDiveTasks.map((task, index) => {
            const { target, service, port, protocol } = task;
            const titleParts = [service || "service", port && protocol ? `${port}/${protocol}` : port, target];
            return (
              <article key={`${service || "task"}-${port || index}`} className="deep-dive-card">
                <header>
                  <h4>{titleParts.filter(Boolean).join(" • ")}</h4>
                  {task.credentials && <span className="badge badge-info">Credentials loaded</span>}
                </header>
                <ul className="command-list">
                  {(task.commands || []).map((command, cmdIndex) => {
                    const key = extractCommandKey(command);
                    const blocked = enforcementEnabled && allowlistSet.size > 0 && !allowlistSet.has(key);
                    return (
                      <li key={`${command}-${cmdIndex}`}>
                        <code className="command-text">{command}</code>
                        {blocked && (
                          <span className="badge badge-error" title="This command is blocked by the allowlist">
                            Blocked
                          </span>
                        )}
                        <button
                          type="button"
                          className="btn btn-secondary"
                          onClick={() => handleRunCommand(command)}
                          disabled={busy || blocked}
                        >
                          Run
                        </button>
                      </li>
                    );
                  })}
                </ul>
              </article>
            );
          })}
        </div>
      )}
      {enforcementEnabled && commandsByAllowance.blocked.length > 0 && (
        <p className="muted blocked-note">
          {commandsByAllowance.blocked.length} command
          {commandsByAllowance.blocked.length > 1 ? "s are" : " is"} blocked by the current allowlist.
        </p>
      )}
      <div className="deep-dive-tasks">
        <div className="deep-dive-header">
          <h4>Execution Queue</h4>
        </div>
        {sortedTasks.length === 0 ? (
          <p className="muted">No deep-dive commands have been queued yet.</p>
        ) : (
          <table className="task-table">
            <thead>
              <tr>
                <th>Command</th>
                <th>Status</th>
                <th>Return Code</th>
                <th>Created</th>
                <th>Updated</th>
                <th>Output</th>
              </tr>
            </thead>
            <tbody>
              {sortedTasks.map((task) => {
                const badgeKey = (task.status || "").toLowerCase();
                const badge = statusBadgeMap[badgeKey] || {
                  label: task.status || "unknown",
                  className: "badge-muted",
                };
                return (
                  <Fragment key={task.id}>
                    <tr>
                      <td>
                        <code className="command-text">{task.command}</code>
                      </td>
                      <td>
                        <span className={`badge ${badge.className}`}>{badge.label}</span>
                      </td>
                      <td>{task.return_code === null || task.return_code === undefined ? "—" : task.return_code}</td>
                      <td>{formatTimestamp(task.created_at)}</td>
                      <td>{formatTimestamp(task.updated_at)}</td>
                      <td>
                        <button
                          type="button"
                          className="btn btn-secondary"
                          onClick={() => handleToggleTask(task)}
                        >
                          {expanded[task.id] ? "Hide" : "View"}
                        </button>
                      </td>
                    </tr>
                    {expanded[task.id] && (
                      <tr className="task-output-row">
                        <td colSpan={6}>
                          {loadingMap[task.id] ? (
                            <p className="muted">Loading task output…</p>
                          ) : (
                            <div className="task-output">
                              <div>
                                <h5>Stdout</h5>
                                <pre className="log-box">{task.stdout || "(empty)"}</pre>
                              </div>
                              <div>
                                <h5>Stderr</h5>
                                <pre className="log-box">{task.stderr || "(empty)"}</pre>
                              </div>
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
    </section>
  );
};

DeepDiveSection.propTypes = {
  scan: PropTypes.shape({
    job_id: PropTypes.string,
    plugins: PropTypes.object,
  }),
  tasks: PropTypes.arrayOf(PropTypes.object),
  allowlist: PropTypes.shape({
    entries: PropTypes.arrayOf(PropTypes.string),
    enforced: PropTypes.bool,
  }),
  onRunDeepDive: PropTypes.func,
  onRefreshDeepDive: PropTypes.func,
  onFetchDeepDiveOutput: PropTypes.func,
  busy: PropTypes.bool,
};

DeepDiveSection.defaultProps = {
  scan: null,
  tasks: [],
  allowlist: { entries: [], enforced: true },
  onRunDeepDive: () => {},
  onRefreshDeepDive: () => {},
  onFetchDeepDiveOutput: () => {},
  busy: false,
};

const RenderVulnerabilities = ({ vulnerabilities }) => {
  if (!vulnerabilities || vulnerabilities.length === 0) {
    return <p>No exploitable or vulnerable findings recorded.</p>;
  }

  const sorted = [...vulnerabilities].sort((a, b) => {
    const sevA = severityOrder[(a.severity || "").toLowerCase()] || 0;
    const sevB = severityOrder[(b.severity || "").toLowerCase()] || 0;
    return sevB - sevA;
  });

  const formatSeverity = (severity) => {
    if (!severity) return { label: "info", className: "badge-muted" };
    const key = severity.toLowerCase();
    if (key in severityOrder) {
      return { label: severity, className: `badge-severity-${key}` };
    }
    return { label: severity, className: "badge-info" };
  };

  return (
    <table className="vuln-table">
      <thead>
        <tr>
          <th>Title</th>
          <th>Target</th>
          <th>Location</th>
          <th>Severity</th>
          <th>Source</th>
          <th>CVEs</th>
        </tr>
      </thead>
      <tbody>
        {sorted.map((item, index) => {
          const severity = formatSeverity(item.severity);
          const location = item.port ? `${item.port}${item.protocol ? '/' + item.protocol : ''}` : item.scope || 'Host';
          const cves = Array.isArray(item.cves) ? item.cves.join(", ") : "";
          return (
            <tr key={`${item.title || item.script_id || index}-${index}`}>
              <td>{item.title || item.script_id || "(unnamed finding)"}</td>
              <td>{item.target || "-"}</td>
              <td>{location || "-"}</td>
              <td>
                <span className={`badge ${severity.className}`}>{severity.label}</span>
              </td>
              <td>{item.source || "nmap"}</td>
              <td>{cves || "-"}</td>
            </tr>
          );
        })}
      </tbody>
    </table>
  );
};

RenderVulnerabilities.propTypes = {
  vulnerabilities: PropTypes.arrayOf(PropTypes.object),
};

RenderVulnerabilities.defaultProps = {
  vulnerabilities: [],
};

function ScanDetail({
  scan,
  deepDiveTasks,
  deepDiveBusy,
  deepDiveAllowlist,
  onRunDeepDive,
  onRefreshDeepDive,
  onFetchDeepDiveOutput,
}) {
  if (!scan) {
    return (
      <div className="panel">
        <div className="panel-header">
          <h2>Scan Details</h2>
        </div>
        <div className="panel-body">
          <p>Select a job to inspect its summary, diff, and plugin output.</p>
        </div>
      </div>
    );
  }
  return (
    <div className="panel">
      <div className="panel-header">
        <h2>Scan Details</h2>
        <div className="chip-group">
          <span className="chip">Job: {scan.job_id}</span>
          <span className="chip">Status: {scan.status}</span>
        </div>
      </div>
      <div className="panel-body">
        <section>
          <h3>Service Intelligence</h3>
          <RenderServiceIntel intel={scan.plugins?.["service-intel"]} />
        </section>
        <DeepDiveSection
          scan={scan}
          tasks={deepDiveTasks}
          allowlist={deepDiveAllowlist}
          onRunDeepDive={onRunDeepDive}
          onRefreshDeepDive={onRefreshDeepDive}
          onFetchDeepDiveOutput={onFetchDeepDiveOutput}
          busy={deepDiveBusy}
        />
        <section>
          <h3>Vulnerabilities &amp; Exposures</h3>
          <RenderVulnerabilities vulnerabilities={scan.vulnerabilities} />
        </section>
        <section>
          <h3>Summary</h3>
          <RenderSummary summary={scan.summary} />
        </section>
        <section>
          <h3>Diff</h3>
          <RenderDiff diff={scan.diff} />
        </section>
        <section>
          <h3>Plugin Output</h3>
          <RenderPlugins plugins={scan.plugins} />
        </section>
        <section>
          <h3>Artifacts</h3>
          {Object.keys(scan.artifacts || {}).length === 0 ? (
            <p>No artifacts captured yet.</p>
          ) : (
            <ul>
              {Object.entries(scan.artifacts).map(([key]) => (
                <li key={key}>{key}</li>
              ))}
            </ul>
          )}
        </section>
        <section>
          <h3>Logs</h3>
          <pre className="log-box">{scan.logs || "(empty)"}</pre>
        </section>
      </div>
    </div>
  );
}

ScanDetail.propTypes = {
  scan: PropTypes.shape({
    job_id: PropTypes.string,
    status: PropTypes.string,
    summary: PropTypes.object,
    diff: PropTypes.object,
    plugins: PropTypes.object,
    artifacts: PropTypes.object,
    logs: PropTypes.string,
  }),
  deepDiveTasks: PropTypes.arrayOf(PropTypes.object),
  deepDiveBusy: PropTypes.bool,
  deepDiveAllowlist: PropTypes.shape({
    entries: PropTypes.arrayOf(PropTypes.string),
    enforced: PropTypes.bool,
  }),
  onRunDeepDive: PropTypes.func,
  onRefreshDeepDive: PropTypes.func,
  onFetchDeepDiveOutput: PropTypes.func,
};

ScanDetail.defaultProps = {
  scan: null,
  deepDiveTasks: [],
  deepDiveBusy: false,
  deepDiveAllowlist: { entries: [], enforced: true },
  onRunDeepDive: () => {},
  onRefreshDeepDive: () => {},
  onFetchDeepDiveOutput: () => {},
};

export default ScanDetail;
