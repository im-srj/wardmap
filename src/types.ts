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

/** A row in the saved-scan history (mirrors db::StoredScan). */
export interface StoredScan {
  id: number;
  target: string;
  args: string;
  createdAt: number; // unix epoch seconds
  hostsUp: number;
  openPorts: number;
  elapsedSecs: number | null;
}

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
