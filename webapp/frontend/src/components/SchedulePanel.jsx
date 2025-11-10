import { useEffect, useState } from "react";
import PropTypes from "prop-types";

const sanitizeTarget = (value) =>
  value
    .trim()
    .replace(/^[a-z]+:\/\//i, "")
    .replace(/\/+$|#.*$/g, "");

const setupPayload = (form) => ({
  name: form.name,
  request: {
    targets: form.targets
      .split(/[\s,]+/)
      .map(sanitizeTarget)
      .filter(Boolean),
    ports: form.ports || undefined,
    intel: form.intel,
  },
});

function SchedulePanel({ api, onRun }) {
  const [form, setForm] = useState({ name: "", targets: "", ports: "", intel: true });
  const [schedules, setSchedules] = useState([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");

  const loadSchedules = async () => {
    setLoading(true);
    setError("");
    try {
      const response = await api.get("/schedules");
      setSchedules(response.data || []);
    } catch (err) {
      setError(err?.response?.data?.detail || err.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadSchedules();
  }, []);

  const handleChange = (event) => {
    const { name, value, type, checked } = event.target;
    setForm((prev) => ({
      ...prev,
      [name]: type === "checkbox" ? checked : value,
    }));
  };

  const handleSubmit = async (event) => {
    event.preventDefault();
    setLoading(true);
    setError("");
    try {
      await api.post("/schedules", setupPayload(form));
      setForm({ name: "", targets: "", ports: "", intel: true });
      await loadSchedules();
    } catch (err) {
      setError(err?.response?.data?.detail || err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleDelete = async (id) => {
    setLoading(true);
    setError("");
    try {
      await api.delete(`/schedules/${id}`);
      await loadSchedules();
    } catch (err) {
      setError(err?.response?.data?.detail || err.message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="panel">
      <div className="panel-header">
        <h2>Scheduled Scans</h2>
      </div>
      <div className="panel-body">
        {error && <p className="alert alert-error">{error}</p>}
        <form className="schedule-form" onSubmit={handleSubmit}>
          <label htmlFor="schedule-name">
            Name
            <input
              id="schedule-name"
              name="name"
              value={form.name}
              onChange={handleChange}
              required
            />
          </label>
          <label htmlFor="schedule-targets">
            Targets
            <textarea
              id="schedule-targets"
              name="targets"
              value={form.targets}
              onChange={handleChange}
              placeholder="127.0.0.1"
              required
            />
          </label>
          <label htmlFor="schedule-ports">
            Port Range
            <input
              id="schedule-ports"
              name="ports"
              value={form.ports}
              onChange={handleChange}
              placeholder="1-1024"
            />
          </label>
          <label className="checkbox" htmlFor="schedule-intel">
            <input
              id="schedule-intel"
              name="intel"
              type="checkbox"
              checked={form.intel}
              onChange={handleChange}
            />
            Enable service intelligence
          </label>
          <button type="submit" className="btn btn-primary" disabled={loading}>
            {loading ? "Saving…" : "Save Schedule"}
          </button>
        </form>
        <div className="schedule-list">
          {loading && <p className="muted">Refreshing…</p>}
          {!loading && schedules.length === 0 && <p>No schedules yet.</p>}
          {schedules.map((schedule) => (
            <div key={schedule.id} className="schedule-item">
              <div>
                <h3>{schedule.name}</h3>
                <p className="muted">{schedule.id}</p>
                <p className="muted">
                  Targets: {schedule.request.targets.join(", ") || "(none)"}
                </p>
              </div>
              <div className="schedule-actions">
                <button type="button" className="btn" onClick={() => onRun(schedule.id)}>
                  Run now
                </button>
                <button type="button" className="btn btn-secondary" onClick={() => handleDelete(schedule.id)}>
                  Delete
                </button>
              </div>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

SchedulePanel.propTypes = {
  api: PropTypes.object.isRequired,
  onRun: PropTypes.func.isRequired,
};

export default SchedulePanel;
