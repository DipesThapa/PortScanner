import { useCallback, useEffect, useMemo, useState } from "react";
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

  const loadWorkers = async () => {
    try {
      const response = await API.get("/workers");
      setWorkers(response.data || []);
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
    () => scans.find((scan) => scan.job_id === selectedId) || null,
    [selectedId, scans],
  );
  const selectedDeepDiveTasks = useMemo(() => deepDiveTasks[selectedId] || [], [deepDiveTasks, selectedId]);

  const loadScans = async () => {
    setLoading(true);
    setError("");
    try {
      const response = await API.get("/scans");
      setScans(response.data || []);
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
    const ws = new WebSocket(`${protocol}://${window.location.host}/ws/status`);
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

  return (
    <div className="layout">
      <header>
        <h1>Port Scanner Control Center</h1>
        <p className="subtitle">
          Track scans, review results, and launch new jobs using the FastAPI backend.
        </p>
      </header>
      {error && <div className="alert alert-error">{error}</div>}
      {info && (
        <div className={`toast ${showToast ? "show" : "hide"}`}>
          <span>{info}</span>
        </div>
      )}
      <Dashboard scans={scans} loading={loading} />
      <main className="main-grid">
        <section className="grid-pair">
          <NewScanForm onSubmit={handleSubmit} submitting={submitting} />
          <SchedulePanel api={API} onRun={handleRunSchedule} />
        </section>
        <section className="grid-pair">
          <ScanList scans={scans} selectedId={selectedId} onSelect={setSelectedId} loading={loading} />
          <WorkerPanel workers={workers} />
        </section>
        <section className="panel-full">
          <ScanDetail
            scan={selectedScan}
            deepDiveTasks={selectedDeepDiveTasks}
            deepDiveBusy={deepDiveBusy}
            deepDiveAllowlist={deepDiveAllowlist}
            onRunDeepDive={handleRunDeepDive}
            onRefreshDeepDive={handleRefreshDeepDive}
            onFetchDeepDiveOutput={handleFetchDeepDiveOutput}
          />
        </section>
      </main>
    </div>
  );
}

export default App;
