import { invoke } from "@tauri-apps/api/core";
import type { ScanResult, StoredScan } from "./types";

/**
 * Run an nmap scan via the Rust backend. `flags` are the preset flags only;
 * the backend appends `-oX -` itself. The backend also persists the scan.
 * Rejects with the backend's error string on failure (invalid target, nmap
 * not installed, parse error, ...).
 */
export async function runScan(
  target: string,
  flags: string[],
): Promise<ScanResult> {
  return invoke<ScanResult>("run_nmap_scan", { target, flags });
}

/** List saved scans, newest first. */
export async function listScans(): Promise<StoredScan[]> {
  return invoke<StoredScan[]>("list_scans");
}

/** Load a saved scan back into a full result (re-parsed from stored XML). */
export async function getScan(id: number): Promise<ScanResult> {
  return invoke<ScanResult>("get_scan", { id });
}
