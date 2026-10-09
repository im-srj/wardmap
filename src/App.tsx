import { useCallback, useEffect, useState } from "react";
import { getScan, listScans, runScan } from "./api";
import { PRESETS, type Preset } from "./presets";
import { ScanForm } from "./components/ScanForm";
import { ResultsTable } from "./components/ResultsTable";
import { HistoryList } from "./components/HistoryList";
import type { ScanResult, StoredScan } from "./types";
import "./App.css";

type Status =
  | { kind: "idle" }
  | { kind: "scanning" }
  | { kind: "done"; result: ScanResult; historical: boolean }
  | { kind: "error"; message: string };

function App() {
  const [target, setTarget] = useState("");
  const [preset, setPreset] = useState<Preset>(PRESETS[0]);
  const [status, setStatus] = useState<Status>({ kind: "idle" });
  const [history, setHistory] = useState<StoredScan[]>([]);
  const [selectedId, setSelectedId] = useState<number | null>(null);

  const refreshHistory = useCallback(async () => {
    try {
      setHistory(await listScans());
    } catch {
      // A history load failure shouldn't break scanning; leave it as-is.
    }
  }, []);

  useEffect(() => {
    refreshHistory();
  }, [refreshHistory]);

  async function onRun() {
    setStatus({ kind: "scanning" });
    try {
      const result = await runScan(target, preset.flags);
      setStatus({ kind: "done", result, historical: false });
      const list = await listScans();
      setHistory(list);
      setSelectedId(list[0]?.id ?? null); // the scan we just saved
    } catch (e) {
      setStatus({ kind: "error", message: String(e) });
    }
  }

  async function onSelectHistory(scan: StoredScan) {
    setSelectedId(scan.id);
    setTarget(scan.target);
    try {
      const result = await getScan(scan.id);
      setStatus({ kind: "done", result, historical: true });
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

      <div className="app__body">
        <aside className="sidebar">
          <div className="sidebar__title">History</div>
          <HistoryList
            scans={history}
            selectedId={selectedId}
            onSelect={onSelectHistory}
          />
        </aside>

        <main className="app__main">
          <ScanForm
            target={target}
            onTargetChange={(t) => {
              setTarget(t);
              setSelectedId(null); // editing starts a new scan context
            }}
            preset={preset}
            onPresetChange={setPreset}
            onRun={onRun}
            scanning={status.kind === "scanning"}
          />

          <section className="app__results">
            {status.kind === "idle" && (
              <p className="placeholder">
                Enter a target and run a scan, or pick a past scan from the
                history. You own the target or have permission to scan it.
              </p>
            )}
            {status.kind === "scanning" && (
              <p className="placeholder placeholder--busy">Scanning {target}…</p>
            )}
            {status.kind === "error" && (
              <div className="error-banner" role="alert">
                {status.message}
              </div>
            )}
            {status.kind === "done" && (
              <>
                {status.historical && (
                  <div className="saved-banner">
                    Viewing a saved scan. Run a new scan to update.
                  </div>
                )}
                <ResultsTable result={status.result} />
              </>
            )}
          </section>
        </main>
      </div>
    </div>
  );
}

export default App;
