import React, { useCallback, useEffect, useMemo, useState } from "react";
import axios from "axios";
import Dashboard from "./components/Dashboard.jsx";
import ScanList from "./components/ScanList.jsx";
import ScanDetail from "./components/ScanDetail.jsx";
import NewScanForm from "./components/NewScanForm.jsx";
import SchedulePanel from "./components/SchedulePanel.jsx";
import WorkerPanel from "./components/WorkerPanel.jsx";

const API = axios.create({
  baseURL: "/api",
});

// API key handling: the backend requires an X-API-Key header on every /api call
// and a ?token= parameter on the status WebSocket. We persist it in localStorage
// and prompt once if it is missing.
export function getApiKey() {
  let key = localStorage.getItem("ps_api_key");
  if (!key) {
    key = window.prompt("Enter the PortScanner API key (see server logs or web_runs/.api_key):") || "";
    if (key) localStorage.setItem("ps_api_key", key.trim());
  }
  return (key || "").trim();
}

API.interceptors.request.use((config) => {
  const key = getApiKey();
  if (key) config.headers["X-API-Key"] = key;
  return config;
});

// If the key is rejected, clear it so the user is prompted again next time.
API.interceptors.response.use(
  (response) => response,
  (err) => {
    if (err?.response?.status === 401) {
      localStorage.removeItem("ps_api_key");
    }
    return Promise.reject(err);
  }
);

const POLL_INTERVAL = 7000;

function App() {
  const [scans, setScans] = useState([]);
  const [selectedId, setSelectedId] = useState(null);
  const [loading, setLoading] = useState(false);
  const [submitting, setSubmitting] = useState(false);
  const [deepDiveBusy, setDeepDiveBusy] = useState(false);
  const [error, setError] = useState("");
  const [info, setInfo] = useState("");
  const [showToast, setShowToast] = useState(false);
  const [workers, setWorkers] = useState([]);
  const [deepDiveTasks, setDeepDiveTasks] = useState({});
  const [deepDiveAllowlist, setDeepDiveAllowlist] = useState({ entries: [], enforced: true });

  const [connected, setConnected] = useState(false);

  const loadWorkers = async () => {
    try {
      const response = await API.get("/workers");
      setWorkers(Array.isArray(response.data) ? response.data : []);
    } catch (err) {
      console.error("Failed to load workers", err);
    }
  };

  const loadAllowlist = useCallback(async () => {
    try {
      const response = await API.get("/deepdive/allowlist/info");
      const payload = response.data || {};
      setDeepDiveAllowlist({
        entries: Array.isArray(payload.entries) ? payload.entries : [],
        enforced: payload.enforced !== false,
      });
    } catch (err) {
      console.error("Failed to load deep-dive allowlist", err);
    }
  }, []);

  const selectedScan = useMemo(
    () => (Array.isArray(scans) ? scans.find((scan) => scan.job_id === selectedId) : null) || null,
    [selectedId, scans],
  );
  const selectedDeepDiveTasks = useMemo(() => deepDiveTasks[selectedId] || [], [deepDiveTasks, selectedId]);

  const loadScans = async () => {
    setLoading(true);
    setError("");
    try {
      const response = await API.get("/scans");
      setScans(Array.isArray(response.data) ? response.data : []);
    } catch (err) {
      setError(err?.response?.data?.detail || err.message);
    } finally {
      setLoading(false);
    }
  };

  const loadDeepDiveTasks = useCallback(
    async (jobId) => {
      if (!jobId) return [];
      try {
        const response = await API.get(`/scans/${jobId}/deepdive`);
        const tasks = response.data || [];
        setDeepDiveTasks((prev) => ({
          ...prev,
          [jobId]: tasks,
        }));
        return tasks;
      } catch (err) {
        const message = err?.response?.data?.detail || err.message;
        setError(message);
        throw err;
      }
    },
    [],
  );

  const mergeDeepDiveTasks = useCallback((tasks) => {
    if (!Array.isArray(tasks)) return;
    const grouped = tasks.reduce((acc, task) => {
      if (!task?.job_id) {
        return acc;
      }
      const jobId = task.job_id;
      if (!acc[jobId]) {
        acc[jobId] = [];
      }
      acc[jobId].push(task);
      return acc;
    }, {});
    setDeepDiveTasks((prev) => {
      const next = { ...prev };
      Object.entries(grouped).forEach(([jobId, taskList]) => {
        const existing = prev[jobId] || [];
        const existingMap = existing.reduce((map, item) => {
          map[item.id] = item;
          return map;
        }, {});
        next[jobId] = taskList.map((task) => {
          const prior = existingMap[task.id];
          if (!prior) return task;
          const { stdout, stderr } = prior;
          return {
            ...task,
            stdout,
            stderr,
          };
        });
      });
      return next;
    });
  }, []);

  useEffect(() => {
    loadScans();
    loadWorkers();
    loadAllowlist();
    const intervalId = setInterval(loadScans, POLL_INTERVAL);
    const workerInterval = setInterval(loadWorkers, POLL_INTERVAL * 2);
    const protocol = window.location.protocol === "https:" ? "wss" : "ws";
    const wsToken = encodeURIComponent(getApiKey());
    const ws = new WebSocket(`${protocol}://${window.location.host}/ws/status?token=${wsToken}`);
    ws.onopen = () => setConnected(true);
    ws.onclose = () => setConnected(false);
    ws.onmessage = (event) => {
      try {
        const data = JSON.parse(event.data);
        if (Array.isArray(data.jobs)) {
          setScans(data.jobs);
        }
        if (Array.isArray(data.workers)) {
          setWorkers(data.workers);
        }
        if (Array.isArray(data.deep_dive)) {
          mergeDeepDiveTasks(data.deep_dive);
        }
      } catch (err) {
        console.warn("Failed to parse status message", err);
      }
    };
    ws.onerror = () => ws.close();
    return () => {
      clearInterval(intervalId);
      clearInterval(workerInterval);
      ws.close();
    };
  }, [loadAllowlist, mergeDeepDiveTasks]);

  useEffect(() => {
    if (!selectedId) return;
    loadDeepDiveTasks(selectedId).catch(() => null);
  }, [loadDeepDiveTasks, selectedId]);

  const handleSubmit = async (payload) => {
    setSubmitting(true);
    setInfo("Submitting scan job…");
    setShowToast(true);
    setError("");
    try {
      const response = await API.post("/scans", payload);
      setSelectedId(response.data.job_id);
      setInfo(`Scan job queued (ID: ${response.data.job_id})`);
      setShowToast(true);
      await loadScans();
    } catch (err) {
      setError(err?.response?.data?.detail || err.message);
      setInfo("Submission failed");
      setShowToast(true);
    } finally {
      setSubmitting(false);
      setTimeout(() => setShowToast(false), 4000);
      setTimeout(() => setInfo(""), 4200);
    }
  };

  const handleRunSchedule = async (scheduleId) => {
    setSubmitting(true);
    setInfo("Launching scheduled scan…");
    setShowToast(true);
    setError("");
    try {
      const response = await API.post(`/schedules/${scheduleId}/run`);
      setSelectedId(response.data.job_id);
      setInfo(`Scheduled scan queued (ID: ${response.data.job_id})`);
      await loadScans();
    } catch (err) {
      setError(err?.response?.data?.detail || err.message);
      setInfo("Schedule launch failed");
    } finally {
      setSubmitting(false);
      setTimeout(() => setShowToast(false), 4000);
      setTimeout(() => setInfo(""), 4200);
    }
  };

  const handleRunDeepDive = async (jobId, commands) => {
    if (!jobId) return;
    setDeepDiveBusy(true);
    setError("");
    setInfo("Launching deep-dive command…");
    setShowToast(true);
    try {
      const payload =
        Array.isArray(commands) && commands.length > 0
          ? { commands }
          : {};
      await API.post(`/scans/${jobId}/deepdive`, payload);
      await loadDeepDiveTasks(jobId);
      setInfo("Deep-dive task queued");
    } catch (err) {
      const message = err?.response?.data?.detail || err.message;
      setError(message);
      setInfo("Failed to queue deep-dive task");
    } finally {
      setDeepDiveBusy(false);
      setShowToast(true);
      setTimeout(() => setShowToast(false), 4000);
      setTimeout(() => setInfo(""), 4200);
    }
  };

  const handleRefreshDeepDive = async (jobId) => {
    if (!jobId) return;
    try {
      await loadDeepDiveTasks(jobId);
    } catch (err) {
      console.error("Failed to refresh deep-dive tasks", err);
    }
  };

  const handleFetchDeepDiveOutput = async (taskId) => {
    try {
      const response = await API.get(`/deepdive/${taskId}`, { params: { include_output: true } });
      const task = response.data;
      if (task?.job_id) {
        setDeepDiveTasks((prev) => {
          const next = { ...prev };
          const items = next[task.job_id] || [];
          next[task.job_id] = items.map((item) =>
            item.id === task.id
              ? { ...item, stdout: task.stdout, stderr: task.stderr, status: task.status, return_code: task.return_code }
              : item,
          );
          return next;
        });
      }
      return response.data;
    } catch (err) {
      const message = err?.response?.data?.detail || err.message;
      setError(message);
      throw err;
    }
  };

  const handleAddWorker = async (worker) => {
    try {
      await API.post("/workers", worker);
      loadWorkers();
    } catch (err) {
      console.error("Failed to add worker", err);
      alert("Failed to add worker: " + (err.response?.data?.detail || err.message));
    }
  };

  const handleDeleteWorker = async (address) => {
    if (!confirm(`Are you sure you want to remove worker ${address}?`)) return;
    try {
      await API.delete(`/workers/${encodeURIComponent(address)}`);
      loadWorkers();
    } catch (err) {
      console.error("Failed to delete worker", err);
      alert("Failed to delete worker: " + (err.response?.data?.detail || err.message));
    }
  };

  const handleUploadScript = async (name, content) => {
    try {
      await API.post("/plugins/scripts", { name, content });
      alert("Script uploaded successfully. It is now available in the allowlist.");
      const info = await API.get("/deepdive/allowlist/info");
      setDeepDiveAllowlist(info.data);
    } catch (err) {
      console.error("Failed to upload script", err);
      alert("Failed to upload script: " + (err.response?.data?.detail || err.message));
    }
  };

  // --- Theme Toggle ---
  const [theme, setTheme] = useState(localStorage.getItem("theme") || "dark");

  useEffect(() => {
    document.documentElement.setAttribute("data-theme", theme);
    localStorage.setItem("theme", theme);
  }, [theme]);

  const toggleTheme = () => {
    setTheme(prev => prev === "dark" ? "light" : "dark");
  };

  // --- Delete Scan ---
  const deleteScan = async (jobId) => {
    console.log("Requesting delete for job:", jobId);
    if (!confirm("Are you sure you want to delete this scan? This action cannot be undone.")) {
      console.log("Delete cancelled by user");
      return;
    }
    try {
      console.log("Sending DELETE request...");
      await API.delete(`/scans/${jobId}`);
      console.log("DELETE successful");
      // Remove from local state
      setScans(prev => prev.filter(s => s.job_id !== jobId));
      if (selectedId === jobId) setSelectedId(null);
    } catch (err) {
      console.error("Delete failed:", err);
      alert("Failed to delete scan: " + err.message);
    }
  };

  return (
    <div className="container">
      <header className="header">
        <h1>Port Scanner Control Center</h1>
        <div style={{ display: 'flex', gap: '8px', paddingRight: '16px' }}>
          <button className="btn-icon" onClick={toggleTheme} title={`Switch to ${theme === 'dark' ? 'Light' : 'Dark'} Mode`}>
            {theme === 'dark' ? '☀️' : '🌙'}
          </button>
        </div>
      </header>
      {error && <div className="alert alert-error">{error}</div>}
      {info && (
        <div className={`toast ${showToast ? "show" : "hide"}`}>
          <span>{info}</span>
        </div>
      )}
      <main className="main-grid">
        <div className="left-column">
          <Dashboard scans={scans} loading={loading} />
          <SectionPair>
            <NewScanForm onSubmit={handleSubmit} submitting={submitting} />
            <SchedulePanel api={API} onRun={handleRunSchedule} />
          </SectionPair>
          <WorkerPanel workers={workers} onAdd={handleAddWorker} onDelete={handleDeleteWorker} />
        </div>
        <div className="right-column">
          <ScanList
            scans={scans}
            selectedId={selectedId}
            onSelect={setSelectedId}
            loading={loading}
            onDelete={deleteScan}
          />
          <ScanDetail
            scan={selectedScan}
            deepDiveTasks={selectedDeepDiveTasks}
            deepDiveBusy={deepDiveBusy}
            deepDiveAllowlist={deepDiveAllowlist}
            onRunDeepDive={handleRunDeepDive}
            onRefreshDeepDive={handleRefreshDeepDive}
            onFetchDeepDiveOutput={handleFetchDeepDiveOutput}
            onUploadScript={handleUploadScript}
            onDeleteScan={deleteScan}
          />
        </div>
      </main>
    </div>
  );
}

class ErrorBoundary extends React.Component {
  constructor(props) {
    super(props);
    this.state = { hasError: false, error: null };
  }

  static getDerivedStateFromError(error) {
    return { hasError: true, error };
  }

  componentDidCatch(error, errorInfo) {
    console.error("ErrorBoundary caught an error", error, errorInfo);
  }

  render() {
    if (this.state.hasError) {
      return (
        <div style={{ padding: "2rem", color: "#ef4444", background: "#0f172a" }}>
          <h1>Something went wrong.</h1>
          <pre>{this.state.error?.toString()}</pre>
        </div>
      );
    }

    return this.props.children;
  }
}

function SectionPair({ children }) {
  return <div className="section-pair">{children}</div>;
}

export default function AppWrapper() {
  return (
    <ErrorBoundary>
      <App />
    </ErrorBoundary>
  );
}
