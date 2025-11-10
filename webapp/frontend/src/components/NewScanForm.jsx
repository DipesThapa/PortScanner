import { useState } from "react";
import PropTypes from "prop-types";

const availablePlugins = [
  { id: "threat-intel", label: "Threat Intel" },
  { id: "auto-responder", label: "Auto Responder" },
  { id: "deep-dive", label: "Deep Dive" },
];

const defaultPluginSelection = availablePlugins.reduce(
  (acc, plugin) => ({
    ...acc,
    [plugin.id]: true,
  }),
  {},
);

const emptyForm = {
  targets: "",
  ports: "",
  intel: true,
  exporters: "stdout",
};

function NewScanForm({ onSubmit, submitting }) {
  const [form, setForm] = useState(emptyForm);
  const [plugins, setPlugins] = useState(defaultPluginSelection);

  const handleChange = (event) => {
    const { name, value, type, checked } = event.target;
    setForm((prev) => ({
      ...prev,
      [name]: type === "checkbox" ? checked : value,
    }));
  };

  const handlePluginToggle = (event) => {
    const { name, checked } = event.target;
    setPlugins((prev) => ({
      ...prev,
      [name]: checked,
    }));
  };

  const sanitizeTarget = (value) =>
    value
      .trim()
      .replace(/^[a-z]+:\/\//i, "")
      .replace(/\/+$|#.*$/g, "");

  const handleSubmit = (event) => {
    event.preventDefault();
    const payload = {
      targets: form.targets
        .split(/[\\s,]+/)
        .map(sanitizeTarget)
        .filter(Boolean),
      ports: form.ports || undefined,
      intel: form.intel,
      plugins: availablePlugins
        .filter((plugin) => plugins[plugin.id])
        .map((plugin) => plugin.id),
      exporters: form.exporters
        .split(/[\\s,]+/)
        .map((value) => value.trim())
        .filter(Boolean),
    };
    onSubmit(payload);
  };

  const handleReset = () => {
    setForm(emptyForm);
    setPlugins(defaultPluginSelection);
  };

  return (
    <form className="panel" onSubmit={handleSubmit}>
      <div className="panel-header">
        <h2>New Scan</h2>
        <button type="button" className="btn btn-secondary" onClick={handleReset}>
          Reset
        </button>
      </div>
      <div className="panel-body form-grid">
        <label htmlFor="targets">
          Targets
          <textarea
            id="targets"
            name="targets"
            placeholder="127.0.0.1 192.168.1.10"
            value={form.targets}
            onChange={handleChange}
            required
          />
        </label>
        <label htmlFor="ports">
          Port Range
          <input
            id="ports"
            name="ports"
            placeholder="1-1024"
            value={form.ports}
            onChange={handleChange}
          />
        </label>
        <label htmlFor="intel">
          <input
            id="intel"
            name="intel"
            type="checkbox"
            checked={form.intel}
            onChange={handleChange}
          />
          Enable service intelligence
        </label>
        <fieldset className="plugin-options">
          <legend>Plugins</legend>
          {availablePlugins.map((plugin) => (
            <label key={plugin.id} htmlFor={`plugin-${plugin.id}`} className="checkbox">
              <input
                id={`plugin-${plugin.id}`}
                type="checkbox"
                name={plugin.id}
                checked={plugins[plugin.id]}
                onChange={handlePluginToggle}
              />
              {plugin.label}
            </label>
          ))}
        </fieldset>
        <label htmlFor="exporters">
          Exporters
          <input
            id="exporters"
            name="exporters"
            value={form.exporters}
            onChange={handleChange}
            placeholder="stdout,jsonl"
          />
        </label>
      </div>
      <div className="panel-footer">
        <button type="submit" className="btn btn-primary" disabled={submitting}>
          {submitting ? "Submitting…" : "Launch Scan"}
        </button>
      </div>
    </form>
  );
}

NewScanForm.propTypes = {
  onSubmit: PropTypes.func.isRequired,
  submitting: PropTypes.bool,
};

NewScanForm.defaultProps = {
  submitting: false,
};

export default NewScanForm;
