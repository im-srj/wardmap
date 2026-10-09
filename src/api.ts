import { Channel, invoke } from "@tauri-apps/api/core";
import type {
  CmdAnalysis,
  NseScript,
  ScanDiff,
  ScanProgress,
  ScanResult,
  StoredScan,
} from "./types";

export interface RunningScan {
  /** Pass to `cancelScan`. */
  runId: string;
  /** Resolves when nmap finishes (the backend has persisted it by then).
   *  Rejects with the backend's error string — "scan cancelled" after a
   *  cancel, or invalid target / nmap missing / nmap error / parse error. */
  result: Promise<ScanResult>;
}

let runSeq = 0;

/**
 * Start an nmap scan via the Rust backend. `command` is the full command as
 * shown to the user (leading `nmap` optional); the backend re-analyzes it,
 * refuses blocked commands, and adds its own capture flags
 * (`--stats-every 1s -oX -`). `onProgress` fires roughly once a second while
 * nmap reports progress.
 */
export function startScan(
  command: string,
  onProgress: (p: ScanProgress) => void,
): RunningScan {
  const runId = `run-${Date.now()}-${++runSeq}`;
  const channel = new Channel<ScanProgress>();
  channel.onmessage = onProgress;
  return {
    runId,
    result: invoke<ScanResult>("run_nmap_scan", {
      runId,
      command,
      onProgress: channel,
    }),
  };
}

/** Parse a command the way nmap would, plus Cartograph's checks. */
export async function analyzeCommand(command: string): Promise<CmdAnalysis> {
  return invoke<CmdAnalysis>("analyze_command", { command });
}

/** Kill a running scan. Resolves false if it had already finished. */
export async function cancelScan(runId: string): Promise<boolean> {
  return invoke<boolean>("cancel_scan", { runId });
}

/** The installed nmap's version; rejects if nmap can't be run. */
export async function nmapVersion(): Promise<string> {
  return invoke<string>("nmap_version");
}

/** List saved scans, newest first. */
export async function listScans(): Promise<StoredScan[]> {
  return invoke<StoredScan[]>("list_scans");
}

/** Load a saved scan back into a full result (re-parsed from stored XML). */
export async function getScan(id: number): Promise<ScanResult> {
  return invoke<ScanResult>("get_scan", { id });
}

/** Diff two saved scans (old baseline vs newer). */
export async function diffScans(
  oldId: number,
  newId: number,
): Promise<ScanDiff> {
  return invoke<ScanDiff>("diff_scans", { oldId, newId });
}

/** The installed nmap's NSE script catalogue (`nmap --script-help all`). */
export async function listNseScripts(): Promise<NseScript[]> {
  return invoke<NseScript[]>("list_nse_scripts");
}
