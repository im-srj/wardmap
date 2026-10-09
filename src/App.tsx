import { useCallback, useEffect, useRef, useState } from "react";
import {
  analyzeCommand,
  cancelScan,
  diffScans,
  getScan,
  listScans,
  nmapVersion,
  startScan,
} from "./api";
import { PRESETS } from "./presets";
import { commandText, findOption, needsRoot, quoteArg } from "./options";
import { useTheme } from "./themes";
import { ScanForm } from "./components/ScanForm";
import { ResultStats, ResultsTable } from "./components/ResultsTable";
import { ExposureMap } from "./components/ExposureMap";
import { HistoryList, relativeTime } from "./components/HistoryList";
import { CompareBar } from "./components/CompareBar";
import { DiffView } from "./components/DiffView";
import { ThemePicker } from "./components/ThemePicker";
import { BrandMark, Icon } from "./components/Icon";
import type {
  CmdAnalysis,
  CmdIssue,
  CmdItem,
  ScanDiff,
  ScanProgress,
  ScanResult,
  StoredScan,
} from "./types";
import "./App.css";

type View =
  | { kind: "idle" }
  | { kind: "scanning" }
  | { kind: "error"; message: string }
  | { kind: "scan"; result: ScanResult; historical: StoredScan | null }
  | { kind: "diff"; diff: ScanDiff; oldLabel: string; newLabel: string };

/** The scan in flight. Lives outside `View` so it keeps running (and keeps
 *  reporting) while the user browses history or a diff. */
interface ActiveRun {
  runId: string;
  target: string;
  command: string;
  startedAt: number;
  progress: ScanProgress | null;
}

type NmapStatus =
  | { kind: "checking" }
  | { kind: "ok"; version: string }
  | { kind: "missing"; error: string };

function scanLabel(s: StoredScan): string {
  return `${s.target} · ${new Date(s.createdAt * 1000).toLocaleString()}`;
}

/** Example targets offered on the empty state. scanme.nmap.org is the Nmap
 *  project's host published specifically for people to test scans against. */
const EXAMPLES = ["localhost", "scanme.nmap.org", "192.168.1.0/24"];

function App() {
  const [target, setTarget] = useState("");
  // The command's options (everything but targets) as canonical items; the
  // presets, script browser, option builder and command editor all edit this.
  const [optItems, setOptItems] = useState<CmdItem[]>(PRESETS[0].items);
  // The backend's analysis of `forCommand` (stale once the command changes).
  const [analysis, setAnalysis] = useState<{
    forCommand: string;
    result: CmdAnalysis;
  } | null>(null);
  const analyzeSeq = useRef(0);
  // Run as root follows the options (any root-only option ticks it) unless
  // the user has explicitly chosen otherwise.
  const [elevateOverride, setElevateOverride] = useState<boolean | null>(
    null,
  );
  const [view, setView] = useState<View>({ kind: "idle" });
  const [run, setRun] = useState<ActiveRun | null>(null);
  const [nmap, setNmap] = useState<NmapStatus>({ kind: "checking" });
  // Read inside async completions, where the closed-over `view` is stale.
  const viewRef = useRef(view);
  viewRef.current = view;
  const cancelledRun = useRef<string | null>(null);
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

  const elevate = elevateOverride ?? needsRoot(optItems);
  const command = commandText(optItems, target, elevate);

  // Re-check the command whenever it changes (debounced). The backend is the
  // authority on what nmap will make of it and what Cartograph won't run.
  useEffect(() => {
    const seq = ++analyzeSeq.current;
    const id = setTimeout(() => {
      analyzeCommand(command).then((result) => {
        if (seq === analyzeSeq.current)
          setAnalysis({ forCommand: command, result });
      });
    }, 120);
    return () => clearTimeout(id);
  }, [command]);

  /** The command line was edited by hand: adopt the backend's reading of it. */
  async function onEditCommand(text: string) {
    const seq = ++analyzeSeq.current;
    const result = await analyzeCommand(text);
    if (seq !== analyzeSeq.current) return;
    // Unbalanced quotes: nothing parsed, so keep the current options rather
    // than wiping them; just show why.
    if (result.issues.some((i) => i.message.startsWith("Unbalanced"))) {
      setAnalysis({ forCommand: text, result });
      return;
    }
    const items = result.items.filter((i) => i.kind !== "target");
    setOptItems(items);
    // Typed/removed `sudo` is an explicit choice only if it differs from
    // what the options would pick by themselves.
    setElevateOverride(result.sudo === needsRoot(items) ? null : result.sudo);
    setTarget(
      result.items
        .filter((i) => i.kind === "target")
        .map((i) => quoteArg(i.name))
        .join(" "),
    );
    setSelectedId(null);
  }

  const checked = analysis?.forCommand === command ? analysis.result : null;
  const issues = displayIssues(
    analysis?.result.issues ?? [],
    optItems,
    target,
    elevate,
  );

  useEffect(() => {
    nmapVersion().then(
      (version) => setNmap({ kind: "ok", version }),
      (e) => setNmap({ kind: "missing", error: String(e) }),
    );
  }, []);

  async function onRun() {
    const handle = startScan(command, (progress) =>
      setRun((r) => (r && r.runId === handle.runId ? { ...r, progress } : r)),
    );
    setRun({
      runId: handle.runId,
      target: target.trim() || "target list",
      command,
      startedAt: Date.now(),
      progress: null,
    });
    setView({ kind: "scanning" });
    try {
      const result = await handle.result;
      const list = await listScans();
      setHistory(list);
      // Only jump to the result if the user is still watching this scan;
      // otherwise it just appears at the top of the history.
      if (viewRef.current.kind === "scanning") {
        setView({ kind: "scan", result, historical: null });
        setSelectedId(list[0]?.id ?? null); // the scan we just saved
      }
    } catch (e) {
      if (cancelledRun.current === handle.runId) {
        if (viewRef.current.kind === "scanning") setView({ kind: "idle" });
      } else {
        setView({ kind: "error", message: String(e) });
      }
    } finally {
      setRun(null);
    }
  }

  function onCancel() {
    if (!run) return;
    cancelledRun.current = run.runId;
    cancelScan(run.runId);
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
    setElevateOverride(null);
    setSelectedId(null);
    setTarget("");
    setView({ kind: "idle" });
  }

  const scanning = run !== null;
  const [title, subtitle] = headerText(view, run);

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
        >
          <Icon name="plus" size={15} />
          New scan
        </button>

        {run && view.kind !== "scanning" && (
          <button
            type="button"
            className="sidebar__run"
            onClick={() => setView({ kind: "scanning" })}
          >
            <span className="spinner" aria-hidden="true" />
            <span className="sidebar__run-target">{run.target}</span>
            <span className="sidebar__run-pct">
              {run.progress ? `${Math.floor(run.progress.percent)}%` : "…"}
            </span>
          </button>
        )}

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
          <span>
            Local only · no telemetry
            {nmap.kind === "ok" && (
              <span className="sidebar__nmap">nmap {nmap.version}</span>
            )}
          </span>
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
            {nmap.kind === "missing" && <NmapMissing error={nmap.error} />}
            <ScanForm
              target={target}
              onTargetChange={(t) => {
                setTarget(t);
                setSelectedId(null);
              }}
              items={optItems}
              onItemsChange={setOptItems}
              command={command}
              elevate={elevate}
              onElevateChange={(on) =>
                setElevateOverride(on === needsRoot(optItems) ? null : on)
              }
              issues={issues}
              onEditCommand={onEditCommand}
              canRun={
                checked !== null &&
                !checked.issues.some((i) => i.level === "block")
              }
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

              {view.kind === "scanning" && run && (
                <ScanningCard run={run} onCancel={onCancel} />
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
                    <ExposureMap result={view.result} />
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

function headerText(
  view: View,
  run: ActiveRun | null,
): [string, string | null] {
  switch (view.kind) {
    case "idle":
      return ["New scan", "Choose a target and profile"];
    case "scanning":
      return ["Scanning", run?.target ?? null];
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

/** What to show under the command: the backend's issues (minus "add a
 *  target" while the target box is simply still empty — the disabled Run
 *  button says that), plus catalogue-based heads-ups about privileges and
 *  spoofing. */
function displayIssues(
  backend: CmdIssue[],
  items: CmdItem[],
  target: string,
  elevate: boolean,
): CmdIssue[] {
  const out = backend.filter(
    (i) => !(target.trim() === "" && i.message === "Add at least one target."),
  );
  const defs = items.map((i) => findOption(i.name));
  const root = items.filter((_, k) => defs[k]?.root).map((i) => i.name);
  if (root.length > 0 && !elevate)
    out.push({
      level: "warn",
      message: `${root.join(", ")} ${root.length === 1 ? "needs" : "need"} root privileges. Tick “Run as root” (you'll be asked for your password), or nmap will refuse ${root.length === 1 ? "it" : "them"}.`,
    });
  const spoof = items
    .filter((_, k) => defs[k]?.risk === "spoofing")
    .map((i) => i.name);
  if (spoof.length > 0)
    out.push({
      level: "warn",
      message: `${spoof.join(", ")} ${spoof.length === 1 ? "disguises" : "disguise"} where the scan comes from. Only use this on networks you're authorized to test.`,
    });
  return out;
}

function fmtDuration(secs: number): string {
  if (secs < 60) return `${Math.round(secs)}s`;
  const m = Math.floor(secs / 60);
  return `${m}m ${Math.round(secs % 60)}s`;
}

/** In-progress card: the exact command, nmap's own phase + percent + ETA
 *  (from `--stats-every`), elapsed time, and Cancel. Before nmap's first
 *  report — and on platforms where it can't report — the bar is
 *  indeterminate and elapsed time is the honest signal. */
function ScanningCard({
  run,
  onCancel,
}: {
  run: ActiveRun;
  onCancel: () => void;
}) {
  const [now, setNow] = useState(Date.now());
  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), 250);
    return () => clearInterval(id);
  }, []);
  const elapsed = (now - run.startedAt) / 1000;
  const p = run.progress;

  return (
    <div className="card scanning">
      <span className="empty__radar empty__radar--active" aria-hidden="true">
        <span className="empty__sweep" />
      </span>
      <div className="scanning__body">
        <div className="scanning__head">
          <div className="empty__title">
            Scanning <span className="mono">{run.target}</span>
          </div>
          <button
            type="button"
            className="btn btn--secondary"
            onClick={onCancel}
          >
            <Icon name="x" size={14} />
            Cancel
          </button>
        </div>
        <code className="scanning__cmd">{run.command}</code>
        <div
          className={"progress" + (p ? "" : " progress--indeterminate")}
          role="progressbar"
          aria-label="Scan progress"
          aria-valuemin={0}
          aria-valuemax={100}
          aria-valuenow={p ? Math.floor(p.percent) : undefined}
        >
          <div
            className="progress__fill"
            style={p ? { width: `${Math.min(p.percent, 100)}%` } : undefined}
          />
        </div>
        <div className="scanning__meta">
          <Icon name="clock" size={14} />
          {p ? (
            <span>
              {p.task} · {p.percent.toFixed(1)}%
              {p.remainingSecs != null &&
                ` · ~${fmtDuration(p.remainingSecs)} left`}
            </span>
          ) : (
            <span>Starting…</span>
          )}
          <span className="scanning__elapsed">
            {fmtDuration(elapsed)} elapsed
          </span>
        </div>
      </div>
    </div>
  );
}

/** Startup preflight failed: nmap isn't installed / not on PATH. Plain text,
 *  not links — a link would navigate the app's own webview away. */
function NmapMissing({ error }: { error: string }) {
  return (
    <div className="card error-card" role="alert">
      <span className="error-card__icon">
        <Icon name="alert" size={18} />
      </span>
      <div className="error-card__body">
        <div className="error-card__title">nmap isn't installed</div>
        <p className="nmap-missing__text">
          Cartograph drives the real nmap binary, which wasn't found on your
          PATH. Install it, then restart Cartograph:
        </p>
        <ul className="nmap-missing__list">
          <li>
            Linux: <code>sudo apt install nmap</code> (or your distro's
            package manager)
          </li>
          <li>
            macOS: <code>brew install nmap</code>
          </li>
          <li>
            Windows: the installer from <code>nmap.org/download</code>{" "}
            (includes Npcap)
          </li>
        </ul>
        <pre className="error-card__msg">{error}</pre>
      </div>
    </div>
  );
}

export default App;
