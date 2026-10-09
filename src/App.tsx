import { useCallback, useEffect, useState } from "react";
import { diffScans, getScan, listScans, runScan } from "./api";
import { PRESETS, type Preset } from "./presets";
import { ScanForm } from "./components/ScanForm";
import { ResultsTable } from "./components/ResultsTable";
import { TopologyView } from "./components/TopologyView";
import { HistoryList } from "./components/HistoryList";
import { CompareBar } from "./components/CompareBar";
import { DiffView } from "./components/DiffView";
import type { ScanDiff, ScanResult, StoredScan } from "./types";
import "./App.css";

type View =
  | { kind: "idle" }
  | { kind: "scanning"; target: string }
  | { kind: "error"; message: string }
  | { kind: "scan"; result: ScanResult; historical: boolean }
  | { kind: "diff"; diff: ScanDiff; oldLabel: string; newLabel: string };

function scanLabel(s: StoredScan): string {
  return `${s.target} · ${new Date(s.createdAt * 1000).toLocaleString()}`;
}

function App() {
  const [target, setTarget] = useState("");
  const [preset, setPreset] = useState<Preset>(PRESETS[0]);
  const [view, setView] = useState<View>({ kind: "idle" });
  const [history, setHistory] = useState<StoredScan[]>([]);
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const [resultMode, setResultMode] = useState<"table" | "map">("table");

  const refreshHistory = useCallback(async () => {
    try {
      setHistory(await listScans());
    } catch {
      // Non-fatal: leave history as-is.
    }
  }, []);

  useEffect(() => {
    refreshHistory();
  }, [refreshHistory]);

  async function onRun() {
    setView({ kind: "scanning", target });
    try {
      const result = await runScan(target, preset.flags);
      setView({ kind: "scan", result, historical: false });
      const list = await listScans();
      setHistory(list);
      setSelectedId(list[0]?.id ?? null); // the scan we just saved
    } catch (e) {
      setView({ kind: "error", message: String(e) });
    }
  }

  async function onSelectHistory(scan: StoredScan) {
    setSelectedId(scan.id);
    setTarget(scan.target);
    try {
      const result = await getScan(scan.id);
      setView({ kind: "scan", result, historical: true });
    } catch (e) {
      setView({ kind: "error", message: String(e) });
    }
  }

  async function onCompare(oldScan: StoredScan, newScan: StoredScan) {
    try {
      const diff = await diffScans(oldScan.id, newScan.id);
      setView({
        kind: "diff",
        diff,
        oldLabel: scanLabel(oldScan),
        newLabel: scanLabel(newScan),
      });
    } catch (e) {
      setView({ kind: "error", message: String(e) });
    }
  }

  function backToLatest() {
    if (selectedId != null) {
      const s = history.find((h) => h.id === selectedId);
      if (s) {
        onSelectHistory(s);
        return;
      }
    }
    setView({ kind: "idle" });
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
              setSelectedId(null);
            }}
            preset={preset}
            onPresetChange={setPreset}
            onRun={onRun}
            scanning={view.kind === "scanning"}
          />

          <CompareBar history={history} onCompare={onCompare} />

          <section className="app__results">
            {view.kind === "idle" && (
              <p className="placeholder">
                Enter a target and run a scan, or pick a past scan from the
                history. You own the target or have permission to scan it.
              </p>
            )}
            {view.kind === "scanning" && (
              <p className="placeholder placeholder--busy">
                Scanning {view.target}…
              </p>
            )}
            {view.kind === "error" && (
              <div className="error-banner" role="alert">
                {view.message}
              </div>
            )}
            {view.kind === "scan" && (
              <>
                {view.historical && (
                  <div className="saved-banner">
                    Viewing a saved scan. Run a new scan to update.
                  </div>
                )}
                <div className="result-toggle">
                  <button
                    type="button"
                    className={
                      "toggle-btn" +
                      (resultMode === "table" ? " toggle-btn--active" : "")
                    }
                    onClick={() => setResultMode("table")}
                  >
                    Table
                  </button>
                  <button
                    type="button"
                    className={
                      "toggle-btn" +
                      (resultMode === "map" ? " toggle-btn--active" : "")
                    }
                    onClick={() => setResultMode("map")}
                  >
                    Map
                  </button>
                </div>
                {resultMode === "table" ? (
                  <ResultsTable result={view.result} />
                ) : (
                  <TopologyView result={view.result} />
                )}
              </>
            )}
            {view.kind === "diff" && (
              <DiffView
                diff={view.diff}
                oldLabel={view.oldLabel}
                newLabel={view.newLabel}
                onClose={backToLatest}
              />
            )}
          </section>
        </main>
      </div>
    </div>
  );
}

export default App;
