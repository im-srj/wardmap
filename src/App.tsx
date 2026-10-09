import { useState } from "react";
import { runScan } from "./api";
import { PRESETS, type Preset } from "./presets";
import { ScanForm } from "./components/ScanForm";
import { ResultsTable } from "./components/ResultsTable";
import type { ScanResult } from "./types";
import "./App.css";

type Status =
  | { kind: "idle" }
  | { kind: "scanning" }
  | { kind: "done"; result: ScanResult }
  | { kind: "error"; message: string };

function App() {
  const [target, setTarget] = useState("");
  const [preset, setPreset] = useState<Preset>(PRESETS[0]);
  const [status, setStatus] = useState<Status>({ kind: "idle" });

  async function onRun() {
    setStatus({ kind: "scanning" });
    try {
      const result = await runScan(target, preset.flags);
      setStatus({ kind: "done", result });
    } catch (e) {
      setStatus({ kind: "error", message: String(e) });
    }
  }

  return (
    <div className="app">
      <header className="app__header">
        <h1 className="app__title">Cartograph</h1>
        <span className="app__subtitle">a modern nmap front-end</span>
      </header>

      <main className="app__main">
        <ScanForm
          target={target}
          onTargetChange={setTarget}
          preset={preset}
          onPresetChange={setPreset}
          onRun={onRun}
          scanning={status.kind === "scanning"}
        />

        <section className="app__results">
          {status.kind === "idle" && (
            <p className="placeholder">
              Enter a target and run a scan. You own the target or have
              permission to scan it.
            </p>
          )}
          {status.kind === "scanning" && (
            <p className="placeholder placeholder--busy">
              Scanning {target}…
            </p>
          )}
          {status.kind === "error" && (
            <div className="error-banner" role="alert">
              {status.message}
            </div>
          )}
          {status.kind === "done" && <ResultsTable result={status.result} />}
        </section>
      </main>
    </div>
  );
}

export default App;
