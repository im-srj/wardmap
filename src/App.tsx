import { useCallback, useEffect, useState } from "react";
import { diffScans, getScan, listScans, runScan } from "./api";
import { PRESETS, buildCommand, buildFlags, type Preset } from "./presets";
import { useTheme } from "./themes";
import { ScanForm } from "./components/ScanForm";
import { ResultStats, ResultsTable } from "./components/ResultsTable";
import { TopologyView } from "./components/TopologyView";
import { HistoryList, relativeTime } from "./components/HistoryList";
import { CompareBar } from "./components/CompareBar";
import { DiffView } from "./components/DiffView";
import { ThemePicker } from "./components/ThemePicker";
import { BrandMark, Icon } from "./components/Icon";
import type { ScanDiff, ScanResult, StoredScan } from "./types";
import "./App.css";

type View =
  | { kind: "idle" }
  | { kind: "scanning"; target: string; command: string }
  | { kind: "error"; message: string }
  | { kind: "scan"; result: ScanResult; historical: StoredScan | null }
  | { kind: "diff"; diff: ScanDiff; oldLabel: string; newLabel: string };

function scanLabel(s: StoredScan): string {
  return `${s.target} · ${new Date(s.createdAt * 1000).toLocaleString()}`;
}

/** Example targets offered on the empty state. scanme.nmap.org is the Nmap
 *  project's host published specifically for people to test scans against. */
const EXAMPLES = ["localhost", "scanme.nmap.org", "192.168.1.0/24"];

function App() {
  const [target, setTarget] = useState("");
  const [preset, setPreset] = useState<Preset>(PRESETS[0]);
  const [scripts, setScripts] = useState<string[]>([]);
  const [view, setView] = useState<View>({ kind: "idle" });
  const [history, setHistory] = useState<StoredScan[]>([]);
  const [selectedId, setSelectedId] = useState<number | null>(null);
  const [resultMode, setResultMode] = useState<"table" | "map">("table");
  const [theme, setTheme] = useTheme();
  const [showAppearance, setShowAppearance] = useState(false);
  const closeAppearance = useCallback(() => setShowAppearance(false), []);

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
    const flags = buildFlags(preset, scripts);
    setView({ kind: "scanning", target, command: buildCommand(flags, target) });
    try {
      const result = await runScan(target, flags);
      setView({ kind: "scan", result, historical: null });
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
      setView({ kind: "scan", result, historical: scan });
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

  function newScan() {
    setSelectedId(null);
    setTarget("");
    setView({ kind: "idle" });
  }

  const scanning = view.kind === "scanning";
  const [title, subtitle] = headerText(view);

  return (
    <div className="app">
      <aside className="sidebar">
        <div className="brand">
          <BrandMark />
          <div className="brand__text">
            <span className="brand__name">Cartograph</span>
            <span className="brand__tag">network mapper</span>
          </div>
        </div>

        <button
          type="button"
          className="btn btn--secondary sidebar__new"
          onClick={newScan}
          disabled={scanning}
        >
          <Icon name="plus" size={15} />
          New scan
        </button>

        <div className="sidebar__heading">
          <span>History</span>
          {history.length > 0 && (
            <span className="count">{history.length}</span>
          )}
        </div>
        <HistoryList
          scans={history}
          selectedId={selectedId}
          onSelect={onSelectHistory}
        />

        <div className="sidebar__footer">
          <Icon name="shield" size={14} />
          Local only · no telemetry
        </div>
      </aside>

      <main className="main">
        <header className="topbar">
          <div className="topbar__titles">
            <h1 className="topbar__title">{title}</h1>
            {subtitle && <span className="topbar__subtitle">{subtitle}</span>}
          </div>
          <button
            type="button"
            className="btn btn--ghost"
            onClick={() => setShowAppearance(true)}
            aria-haspopup="dialog"
          >
            <Icon name="palette" size={16} />
            Appearance
          </button>
        </header>

        <div className="main__scroll">
          <div className="main__inner">
            <ScanForm
              target={target}
              onTargetChange={(t) => {
                setTarget(t);
                setSelectedId(null);
              }}
              preset={preset}
              onPresetChange={setPreset}
              scripts={scripts}
              onScriptsChange={setScripts}
              onRun={onRun}
              scanning={scanning}
              collapsible={view.kind === "scan" || view.kind === "diff"}
            />

            <CompareBar history={history} onCompare={onCompare} />

            <section className="results-area" aria-live="polite">
              {view.kind === "idle" && (
                <div className="card empty">
                  <span className="empty__radar" aria-hidden="true">
                    <span className="empty__sweep" />
                  </span>
                  <div className="empty__title">Ready to map</div>
                  <p className="empty__text">
                    Enter a target above and run a scan, or open a past scan
                    from the history. Only scan hosts you own or are authorized
                    to test.
                  </p>
                  <div className="empty__examples">
                    <span className="muted">Try</span>
                    {EXAMPLES.map((ex) => (
                      <button
                        key={ex}
                        type="button"
                        className="chip"
                        onClick={() => setTarget(ex)}
                      >
                        {ex}
                      </button>
                    ))}
                  </div>
                </div>
              )}

              {view.kind === "scanning" && (
                <ScanningCard target={view.target} command={view.command} />
              )}

              {view.kind === "error" && (
                <div className="card error-card" role="alert">
                  <span className="error-card__icon">
                    <Icon name="alert" size={18} />
                  </span>
                  <div className="error-card__body">
                    <div className="error-card__title">
                      Something went wrong
                    </div>
                    <pre className="error-card__msg">{view.message}</pre>
                  </div>
                </div>
              )}

              {view.kind === "scan" && (
                <>
                  {view.historical && (
                    <div className="banner">
                      <Icon name="history" size={15} />
                      Viewing a saved scan from{" "}
                      {new Date(
                        view.historical.createdAt * 1000,
                      ).toLocaleString()}
                      . Run a new scan to refresh it.
                    </div>
                  )}
                  <ResultStats result={view.result} />
                  <div className="results-toolbar">
                    <div
                      className="segmented"
                      role="tablist"
                      aria-label="Result view"
                    >
                      <button
                        type="button"
                        role="tab"
                        aria-selected={resultMode === "table"}
                        className={
                          "segmented__btn" +
                          (resultMode === "table"
                            ? " segmented__btn--active"
                            : "")
                        }
                        onClick={() => setResultMode("table")}
                      >
                        <Icon name="table" size={14} />
                        Table
                      </button>
                      <button
                        type="button"
                        role="tab"
                        aria-selected={resultMode === "map"}
                        className={
                          "segmented__btn" +
                          (resultMode === "map"
                            ? " segmented__btn--active"
                            : "")
                        }
                        onClick={() => setResultMode("map")}
                      >
                        <Icon name="graph" size={14} />
                        Map
                      </button>
                    </div>
                    <code
                      className="results-toolbar__args"
                      title={view.result.args}
                    >
                      {view.result.scanner} {view.result.version}
                    </code>
                  </div>
                  {resultMode === "table" ? (
                    <ResultsTable result={view.result} />
                  ) : (
                    <div className="card topo-card">
                      <TopologyView result={view.result} />
                    </div>
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
          </div>
        </div>
      </main>

      {showAppearance && (
        <ThemePicker
          current={theme}
          onChange={setTheme}
          onClose={closeAppearance}
        />
      )}
    </div>
  );
}

function headerText(view: View): [string, string | null] {
  switch (view.kind) {
    case "idle":
      return ["New scan", "Choose a target and profile"];
    case "scanning":
      return ["Scanning", view.target];
    case "error":
      return ["Scan failed", null];
    case "scan":
      return view.historical
        ? [
            "Saved scan",
            `${view.historical.target} · ${relativeTime(view.historical.createdAt)}`,
          ]
        : ["Scan results", null];
    case "diff":
      return ["Compare scans", "What changed between two runs"];
  }
}

/** In-progress card: a radar sweep, the exact command, and an elapsed timer
 *  (nmap gives no progress over -oX, so elapsed time is the honest signal). */
function ScanningCard({
  target,
  command,
}: {
  target: string;
  command: string;
}) {
  const [elapsed, setElapsed] = useState(0);
  useEffect(() => {
    const start = Date.now();
    const id = setInterval(() => setElapsed((Date.now() - start) / 1000), 100);
    return () => clearInterval(id);
  }, []);

  return (
    <div className="card scanning">
      <span className="empty__radar empty__radar--active" aria-hidden="true">
        <span className="empty__sweep" />
      </span>
      <div className="scanning__body">
        <div className="empty__title">
          Scanning <span className="mono">{target}</span>
        </div>
        <code className="scanning__cmd">{command}</code>
        <div className="scanning__meta">
          <Icon name="clock" size={14} />
          {elapsed.toFixed(1)}s elapsed
        </div>
      </div>
    </div>
  );
}

export default App;
