import { useCallback, useEffect, useRef, useState } from "react";
import {
  analyzeCommand,
  cancelScan,
  deleteProfile,
  diffScans,
  exportScan,
  getScan,
  importScans,
  importZenmapProfiles,
  listProfiles,
  listScans,
  newRunId,
  nmapVersion,
  saveProfile,
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
import { ScanActions } from "./components/ScanActions";
import { ThemePicker } from "./components/ThemePicker";
import { BrandMark, Icon } from "./components/Icon";
import type {
  CmdAnalysis,
  CmdIssue,
  CmdItem,
  ExportFormat,
  ImportReport,
  Profile,
  ScanDiff,
  ScanProgress,
  ScanResult,
  StoredScan,
} from "./types";
import "./App.css";

/** A re-run's result compared with the scan it re-ran. */
interface Comparison {
  baseline: StoredScan;
  diff: ScanDiff;
}

type View =
  | { kind: "idle" }
  | { kind: "scanning"; runId: string }
  | { kind: "error"; message: string }
  | {
      kind: "scan";
      result: ScanResult;
      /** Its history row (null only if the history refresh failed). */
      saved: StoredScan | null;
      /** Opened from history, rather than just run. */
      historical: boolean;
      comparison: Comparison | null;
    }
  | { kind: "diff"; diff: ScanDiff; oldLabel: string; newLabel: string };

/** A scan running or waiting to run. Lives outside `View` so it keeps going
 *  (and reporting) while the user browses history, a diff, or another run. */
interface ActiveRun {
  runId: string;
  target: string;
  command: string;
  /** Re-run of this saved scan: compare the result with it. */
  baseline: StoredScan | null;
  /** Null while queued. */
  startedAt: number | null;
  progress: ScanProgress | null;
}

/** Scans that may run at once; more are queued. Each is still an explicit
 *  Run click, and a root scan asks for the password when it starts. */
const MAX_PARALLEL = 2;

interface Notice {
  tone: "info" | "error";
  text: string;
}

function importNotice(r: ImportReport, noun: string, already: string): Notice {
  const parts = [`Imported ${r.imported} ${noun}${r.imported === 1 ? "" : "s"}`];
  if (r.skipped) parts.push(`${r.skipped} ${already}`);
  const text = [parts.join(" · ") + ".", ...r.errors].join("\n");
  return { tone: r.errors.length && !r.imported ? "error" : "info", text };
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
  const [runs, setRuns] = useState<ActiveRun[]>([]);
  // Runs handed to the backend (the rest of `runs` are queued), and those
  // the user cancelled.
  const launched = useRef(new Set<string>());
  const cancelled = useRef(new Set<string>());
  const [rerunOf, setRerunOf] = useState<StoredScan | null>(null);
  const [profiles, setProfiles] = useState<Profile[]>([]);
  const [notice, setNotice] = useState<Notice | null>(null);
  const scrollRef = useRef<HTMLDivElement>(null);
  const [nmap, setNmap] = useState<NmapStatus>({ kind: "checking" });
  // Read inside async completions, where the closed-over `view` is stale.
  const viewRef = useRef(view);
  viewRef.current = view;
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

  const refreshProfiles = useCallback(async () => {
    try {
      setProfiles(await listProfiles());
    } catch {
      // Non-fatal: leave profiles as-is.
    }
  }, []);

  useEffect(() => {
    refreshHistory();
    refreshProfiles();
  }, [refreshHistory, refreshProfiles]);

  const elevate = elevateOverride ?? needsRoot(optItems);
  const command = commandText(optItems, target, elevate);

  // Re-check the command whenever it changes (debounced). The backend is the
  // authority on what nmap will make of it and what Wardmap won't run.
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

  function onRun() {
    // The same command already running or queued: show it, don't repeat it.
    const dup = runs.find((r) => r.command === command);
    if (dup) {
      setView({ kind: "scanning", runId: dup.runId });
      return;
    }
    const run: ActiveRun = {
      runId: newRunId(),
      target: target.trim() || "target list",
      command,
      baseline: rerunOf,
      startedAt: null,
      progress: null,
    };
    setRuns((rs) => [...rs, run]);
    setRerunOf(null);
    setView({ kind: "scanning", runId: run.runId });
  }

  // Start queued runs while there's a free slot.
  useEffect(() => {
    const running = runs.filter((r) => launched.current.has(r.runId)).length;
    runs
      .filter((r) => !launched.current.has(r.runId))
      .slice(0, Math.max(0, MAX_PARALLEL - running))
      .forEach(launch);
  }, [runs]);

  // Watching a run that is gone (e.g. removed from the queue): nothing to show.
  useEffect(() => {
    if (view.kind === "scanning" && !runs.some((r) => r.runId === view.runId))
      setView({ kind: "idle" });
  }, [view, runs]);

  async function launch(run: ActiveRun) {
    launched.current.add(run.runId);
    const update = (f: (r: ActiveRun) => ActiveRun) =>
      setRuns((rs) => rs.map((r) => (r.runId === run.runId ? f(r) : r)));
    const watching = () => {
      const v = viewRef.current;
      return v.kind === "scanning" && v.runId === run.runId;
    };
    update((r) => ({ ...r, startedAt: Date.now() }));
    try {
      const { scanId, result } = await startScan(
        run.runId,
        run.command,
        (progress) => update((r) => ({ ...r, progress })),
      );
      const list = await listScans().catch(() => null);
      if (list) setHistory(list);
      let comparison: Comparison | null = null;
      if (run.baseline) {
        const diff = await diffScans(run.baseline.id, scanId).catch(() => null);
        if (diff) comparison = { baseline: run.baseline, diff };
      }
      // Only jump to the result if the user is still watching this scan;
      // otherwise it just appears at the top of the history.
      if (watching()) {
        setView({
          kind: "scan",
          result,
          saved: list?.find((s) => s.id === scanId) ?? null,
          historical: false,
          comparison,
        });
        setSelectedId(scanId);
      }
    } catch (e) {
      if (cancelled.current.has(run.runId)) {
        if (watching()) setView({ kind: "idle" });
      } else if (watching()) {
        setView({ kind: "error", message: String(e) });
      } else {
        setNotice({ tone: "error", text: `Scan of ${run.target} failed: ${e}` });
      }
    } finally {
      launched.current.delete(run.runId);
      cancelled.current.delete(run.runId);
      setRuns((rs) => rs.filter((r) => r.runId !== run.runId));
    }
  }

  function onCancel(runId: string) {
    if (!launched.current.has(runId)) {
      // Still queued: just drop it.
      setRuns((rs) => rs.filter((r) => r.runId !== runId));
      return;
    }
    cancelled.current.add(runId);
    cancelScan(runId);
  }

  /** Load a saved scan's command into the form. It runs only when the user
   *  presses Run, and the result is then compared with this scan. */
  function onRerun(scan: StoredScan) {
    setRerunOf(scan);
    setView({ kind: "idle" });
    scrollRef.current?.scrollTo({ top: 0, behavior: "smooth" });
    onEditCommand(scan.command);
  }

  async function onExport(scan: StoredScan, format: ExportFormat) {
    try {
      const path = await exportScan(scan.id, format);
      if (path) setNotice({ tone: "info", text: `Exported to ${path}` });
    } catch (e) {
      setNotice({ tone: "error", text: `Export failed: ${e}` });
    }
  }

  async function onImportScans() {
    try {
      const report = await importScans();
      if (!report) return;
      await refreshHistory();
      setNotice(importNotice(report, "scan", "already in history"));
    } catch (e) {
      setNotice({ tone: "error", text: `Import failed: ${e}` });
    }
  }

  async function onImportZenmap() {
    try {
      const report = await importZenmapProfiles();
      if (!report) return;
      await refreshProfiles();
      setNotice(
        importNotice(report, "profile", "skipped (name already used)"),
      );
    } catch (e) {
      setNotice({ tone: "error", text: `Import failed: ${e}` });
    }
  }

  async function onSaveProfile(
    id: number | null,
    name: string,
    description: string,
  ): Promise<Profile> {
    const saved = await saveProfile(
      id,
      name,
      description,
      commandText(optItems, ""),
    );
    await refreshProfiles();
    return saved;
  }

  async function onDeleteProfile(id: number) {
    await deleteProfile(id);
    await refreshProfiles();
  }

  async function onSelectHistory(scan: StoredScan) {
    setSelectedId(scan.id);
    setTarget(scan.target);
    try {
      const result = await getScan(scan.id);
      setView({
        kind: "scan",
        result,
        saved: scan,
        historical: true,
        comparison: null,
      });
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
    setRerunOf(null);
    setSelectedId(null);
    setTarget("");
    setView({ kind: "idle" });
  }

  const watched =
    view.kind === "scanning"
      ? runs.find((r) => r.runId === view.runId)
      : undefined;
  const [title, subtitle] = headerText(view, watched);

  return (
    <div className="app">
      <aside className="sidebar">
        <div className="brand">
          <BrandMark />
          <div className="brand__text">
            <span className="brand__name">Wardmap</span>
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

        {runs
          .filter((r) => r !== watched)
          .map((r) => (
            <button
              key={r.runId}
              type="button"
              className="sidebar__run"
              onClick={() => setView({ kind: "scanning", runId: r.runId })}
              title={r.command}
            >
              {r.startedAt !== null ? (
                <span className="spinner" aria-hidden="true" />
              ) : (
                <Icon name="clock" size={14} />
              )}
              <span className="sidebar__run-target">{r.target}</span>
              <span className="sidebar__run-pct">
                {r.startedAt === null
                  ? "queued"
                  : r.progress
                    ? `${Math.floor(r.progress.percent)}%`
                    : "…"}
              </span>
            </button>
          ))}

        <div className="sidebar__heading">
          <span>History</span>
          <span className="sidebar__heading-end">
            {history.length > 0 && (
              <span className="count">{history.length}</span>
            )}
            <button
              type="button"
              className="icon-btn icon-btn--sm"
              onClick={onImportScans}
              aria-label="Import nmap XML files"
              title="Import nmap XML files"
            >
              <Icon name="upload" size={14} />
            </button>
          </span>
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

        <div className="main__scroll" ref={scrollRef}>
          <div className="main__inner">
            {nmap.kind === "missing" && <NmapMissing error={nmap.error} />}
            {notice && (
              <div
                className={`notice notice--${notice.tone}`}
                role={notice.tone === "error" ? "alert" : "status"}
              >
                <Icon
                  name={notice.tone === "error" ? "alert" : "check"}
                  size={15}
                />
                <span className="notice__text">{notice.text}</span>
                <button
                  type="button"
                  className="icon-btn icon-btn--sm"
                  onClick={() => setNotice(null)}
                  aria-label="Dismiss"
                >
                  <Icon name="x" size={13} />
                </button>
              </div>
            )}
            <ScanForm
              target={target}
              onTargetChange={(t) => {
                setTarget(t);
                setSelectedId(null);
                setRerunOf(null);
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
              queueFull={runs.length >= MAX_PARALLEL}
              rerunOf={rerunOf}
              onClearRerun={() => setRerunOf(null)}
              profiles={profiles}
              onSaveProfile={onSaveProfile}
              onDeleteProfile={onDeleteProfile}
              onImportZenmap={onImportZenmap}
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

              {watched && (
                <ScanningCard
                  run={watched}
                  onCancel={() => onCancel(watched.runId)}
                />
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
                  {view.historical && view.saved && (
                    <div className="banner">
                      <Icon name="history" size={15} />
                      Viewing a saved scan from{" "}
                      {new Date(view.saved.createdAt * 1000).toLocaleString()}
                      . Re-run it to see what changed.
                    </div>
                  )}
                  {view.comparison && (
                    <ComparisonBanner
                      comparison={view.comparison}
                      onShow={() => {
                        const c = view.comparison!;
                        setView({
                          kind: "diff",
                          diff: c.diff,
                          oldLabel: scanLabel(c.baseline),
                          newLabel: view.saved
                            ? scanLabel(view.saved)
                            : "this scan",
                        });
                      }}
                    />
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
                    {view.saved && (
                      <ScanActions
                        scan={view.saved}
                        onRerun={onRerun}
                        onExport={onExport}
                      />
                    )}
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
  run: ActiveRun | undefined,
): [string, string | null] {
  switch (view.kind) {
    case "idle":
      return ["New scan", "Choose a target and profile"];
    case "scanning":
      return [run?.startedAt === null ? "Queued" : "Scanning", run?.target ?? null];
    case "error":
      return ["Scan failed", null];
    case "scan":
      return view.historical && view.saved
        ? [
            "Saved scan",
            `${view.saved.target} · ${relativeTime(view.saved.createdAt)}`,
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

/** After a re-run: how the result differs from the scan it re-ran. */
function ComparisonBanner({
  comparison,
  onShow,
}: {
  comparison: Comparison;
  onShow: () => void;
}) {
  const { baseline, diff } = comparison;
  const when = relativeTime(baseline.createdAt);
  if (diff.unchanged)
    return (
      <div className="banner">
        <Icon name="compare" size={15} />
        No changes since the scan from {when}.
      </div>
    );
  const ports = diff.hosts.reduce((n, h) => n + h.ports.length, 0);
  const hosts = diff.hosts.length;
  return (
    <div className="banner banner--changed">
      <Icon name="compare" size={15} />
      <span>
        Changed since the scan from {when}: {hosts} host
        {hosts === 1 ? "" : "s"}
        {ports > 0 && `, ${ports} port change${ports === 1 ? "" : "s"}`}.
      </span>
      <button
        type="button"
        className="btn btn--secondary btn--sm banner__action"
        onClick={onShow}
      >
        Show changes
      </button>
    </div>
  );
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
  const queued = run.startedAt === null;
  const elapsed = queued ? 0 : (now - run.startedAt!) / 1000;
  const p = run.progress;

  return (
    <div className="card scanning">
      <span className="empty__radar empty__radar--active" aria-hidden="true">
        <span className="empty__sweep" />
      </span>
      <div className="scanning__body">
        <div className="scanning__head">
          <div className="empty__title">
            {queued ? "Queued" : "Scanning"}{" "}
            <span className="mono">{run.target}</span>
          </div>
          <button
            type="button"
            className="btn btn--secondary"
            onClick={onCancel}
          >
            <Icon name="x" size={14} />
            {queued ? "Remove from queue" : "Cancel"}
          </button>
        </div>
        <code className="scanning__cmd">{run.command}</code>
        {!queued && <div
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
        </div>}
        <div className="scanning__meta">
          <Icon name="clock" size={14} />
          {queued ? (
            <span>
              Starts when a running scan finishes (at most {MAX_PARALLEL} run
              at once).
            </span>
          ) : p ? (
            <span>
              {p.task} · {p.percent.toFixed(1)}%
              {p.remainingSecs != null &&
                ` · ~${fmtDuration(p.remainingSecs)} left`}
            </span>
          ) : (
            <span>Starting…</span>
          )}
          {!queued && (
            <span className="scanning__elapsed">
              {fmtDuration(elapsed)} elapsed
            </span>
          )}
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
          Wardmap drives the real nmap binary, which wasn't found on your
          PATH. Install it, then restart Wardmap:
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
