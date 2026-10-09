import { invoke } from "@tauri-apps/api/core";
import type { ScanResult } from "./types";

/**
 * Run an nmap scan via the Rust backend. `flags` are the preset flags only;
 * the backend appends `-oX -` itself. Rejects with the backend's error string
 * on failure (invalid target, nmap not installed, parse error, ...).
 */
export async function runScan(
  target: string,
  flags: string[],
): Promise<ScanResult> {
  return invoke<ScanResult>("run_nmap_scan", { target, flags });
}
