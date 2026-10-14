import { Channel, invoke } from "@tauri-apps/api/core";
import type {
  CmdAnalysis,
  ExportFormat,
  ImportReport,
  NseScript,
  Profile,
  ScanDiff,
  ScanOutcome,
  ScanProgress,
  ScanResult,
  StoredScan,
} from "./types";

let runSeq = 0;

/** A fresh id for `startScan` / `cancelScan`. */
export function newRunId(): string {
  return `run-${Date.now()}-${++runSeq}`;
}

/**
 * Start an nmap scan via the Rust backend. `command` is the full command as
 * shown to the user (leading `nmap` optional); the backend re-analyzes it,
 * refuses blocked commands, and adds its own capture flags
 * (`--stats-every 1s -oX -`). `onProgress` fires roughly once a second while
 * nmap reports progress. Resolves when nmap finishes (the backend has saved
 * it by then); rejects with the backend's error string — "scan cancelled"
 * after a cancel, or blocked command / nmap missing / nmap error / parse error.
 */
export function startScan(
  runId: string,
  command: string,
  onProgress: (p: ScanProgress) => void,
): Promise<ScanOutcome> {
  const channel = new Channel<ScanProgress>();
  channel.onmessage = onProgress;
  return invoke<ScanOutcome>("run_nmap_scan", {
    runId,
    command,
    onProgress: channel,
  });
}

/** Parse a command the way nmap would, plus Wardmap's checks. */
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

/** Saved scan profiles, by name. */
export async function listProfiles(): Promise<Profile[]> {
  return invoke<Profile[]>("list_profiles");
}

/** Create (`id` null) or update a profile; only the command's options are
 *  kept. Rejects with a readable message (e.g. the name is taken). */
export async function saveProfile(
  id: number | null,
  name: string,
  description: string,
  command: string,
): Promise<Profile> {
  return invoke<Profile>("save_profile", { id, name, description, command });
}

export async function deleteProfile(id: number): Promise<void> {
  return invoke<void>("delete_profile", { id });
}

/** Pick nmap XML files (native dialog) and add them to history. Null if the
 *  dialog was dismissed. */
export async function importScans(): Promise<ImportReport | null> {
  return invoke<ImportReport | null>("import_scans");
}

/** Pick a Zenmap scan_profile.usp and add its profiles. */
export async function importZenmapProfiles(): Promise<ImportReport | null> {
  return invoke<ImportReport | null>("import_zenmap_profiles");
}

/** Export a saved scan via a native save dialog. Resolves to the saved path,
 *  or null if the dialog was dismissed. */
export async function exportScan(
  id: number,
  format: ExportFormat,
): Promise<string | null> {
  return invoke<string | null>("export_scan", { id, format });
}
