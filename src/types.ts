// Mirrors the serde (camelCase) shape returned by the `run_nmap_scan`
// Tauri command in src-tauri/src/scan.rs. Keep these in sync.

export interface Service {
  name: string | null;
  product: string | null;
  version: string | null;
  extrainfo: string | null;
  tunnel: string | null; // "ssl" when wrapped in TLS (HTTPS = http + ssl)
  method: string | null; // "probed" (-sV) or "table" (guessed from port)
}

export interface ScriptOutput {
  id: string;
  output: string;
}

export interface TlsCert {
  sha1: string;
  subjectCn: string | null;
  issuerCn: string | null;
  notBefore: string | null;
  notAfter: string | null;
}

export interface Port {
  protocol: string;
  portid: number;
  state: string;
  reason: string | null;
  service: Service | null;
  scripts: ScriptOutput[];
  cert: TlsCert | null;
}

export interface Address {
  addr: string;
  addrType: string;
  vendor: string | null;
}

export interface Host {
  state: string;
  reason: string | null;
  addresses: Address[];
  hostnames: string[];
  ports: Port[];
  scripts: ScriptOutput[]; // <hostscript> output
  identity: HostIdentity | null; // gathered after the scan (mDNS / ARP)
}

/** Mirrors identify::HostIdentity. */
export interface HostIdentity {
  mdnsName: string | null;
  mac: string | null;
  vendor: string | null;
  macRandomized: boolean;
}

export interface RunStats {
  hostsUp: number;
  hostsDown: number;
  hostsTotal: number;
  elapsedSecs: number | null;
  exit: string | null;
  summary: string | null;
}

export interface ScanResult {
  scanner: string;
  args: string;
  version: string;
  start: number | null;
  hosts: Host[];
  summary: RunStats | null;
}

/** One piece of an nmap command as the backend parsed it (mirrors
 *  cmdline::Item). `tokens` is its canonical argv spelling. */
export interface CmdItem {
  kind: "option" | "target" | "unknown";
  /** `-sS`, `-p`, `-T`, `-PS`, `--min-rate`… or the target/unknown token. */
  name: string;
  value: string | null;
  tokens: string[];
}

export interface CmdIssue {
  /** `block`: Cartograph won't run it. `warn`: runs, but worth knowing. */
  level: "block" | "warn";
  message: string;
}

/** The backend's reading of a command line (mirrors cmdline::Analysis). */
export interface CmdAnalysis {
  sudo: boolean;
  items: CmdItem[];
  issues: CmdIssue[];
}

/** One live progress update while a scan runs (mirrors runner::ScanProgress). */
export interface ScanProgress {
  /** nmap's phase name, e.g. "Connect Scan", "Service scan", "NSE". */
  task: string;
  percent: number;
  remainingSecs: number | null;
}

/** A row in the saved-scan history (mirrors db::StoredScan). */
export interface StoredScan {
  id: number;
  target: string;
  args: string;
  /** The command to run it again (what the user ran, or rebuilt from args
   *  for imported / older scans). */
  command: string;
  createdAt: number; // unix epoch seconds
  hostsUp: number;
  openPorts: number;
  elapsedSecs: number | null;
}

/** A finished scan (mirrors commands::ScanOutcome). */
export interface ScanOutcome {
  scanId: number;
  result: ScanResult;
}

/** A saved scan profile (mirrors commands::Profile). */
export interface Profile {
  id: number;
  name: string;
  description: string;
  /** Its options as typed after `nmap` (never targets). */
  command: string;
  /** The backend's reading of `command`. */
  items: CmdItem[];
}

/** What an import did (mirrors commands::ImportReport). */
export interface ImportReport {
  imported: number;
  /** Already present (same XML / same profile name). */
  skipped: number;
  errors: string[];
}

/** Mirrors export::Format. */
export type ExportFormat =
  "xml" | "json" | "csv" | "normal" | "grepable" | "html";

// --- Diff (mirrors diff::ScanDiff) ---

export interface PortDiff {
  portid: number;
  protocol: string;
  kind: string; // "opened" | "closed" | "service-changed" | "cert-changed" | "cert-new"
  detail: string;
}

export interface HostDiff {
  host: string;
  status: string; // "added" | "removed" | "changed"
  stateChange: string | null;
  ports: PortDiff[];
}

export interface ScanDiff {
  hosts: HostDiff[];
  unchanged: boolean;
}

// --- NSE (mirrors nse::NseScript) ---

export interface NseScript {
  id: string; // the name passed to --script, e.g. "ssl-cert"
  categories: string[];
  description: string;
}
