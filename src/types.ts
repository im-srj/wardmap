// Mirrors the serde (camelCase) shape returned by the `run_nmap_scan`
// Tauri command in src-tauri/src/scan.rs. Keep these in sync.

export interface Service {
  name: string | null;
  product: string | null;
  version: string | null;
  extrainfo: string | null;
}

export interface Port {
  protocol: string;
  portid: number;
  state: string;
  reason: string | null;
  service: Service | null;
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
