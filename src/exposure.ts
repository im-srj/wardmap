// Offline knowledge base behind the exposure map: what common services are,
// which category they belong to, and which deserve a second look. Notes are
// deliberately about the *kind* of service, never about vulnerabilities in a
// specific version — that would need real vulnerability data we don't have.

import type { Host, Port } from "./types";
import { guessDevice, type DeviceGuess } from "./device";

export type Category =
  | "remote"
  | "web"
  | "database"
  | "files"
  | "mail"
  | "print"
  | "naming"
  | "directory"
  | "management"
  | "media"
  | "other";

export const CATEGORIES: Record<Category, { label: string; blurb: string }> = {
  remote: {
    label: "Remote access",
    blurb: "Ways to log in to or control this machine over the network.",
  },
  web: { label: "Web", blurb: "Web servers, admin panels and HTTP APIs." },
  database: {
    label: "Databases",
    blurb:
      "Data stores — usually meant to be reached only by the app that uses them.",
  },
  files: { label: "File sharing", blurb: "Network file access and transfer." },
  mail: { label: "Mail", blurb: "Sending and receiving email." },
  print: { label: "Printing", blurb: "Printers and print servers." },
  naming: {
    label: "Name & discovery",
    blurb: "Name resolution and automatic device discovery.",
  },
  directory: {
    label: "Directory & auth",
    blurb: "Accounts, authentication and Windows domain services.",
  },
  management: {
    label: "Management",
    blurb: "Control planes for containers, hardware and network gear.",
  },
  media: {
    label: "Media & IoT",
    blurb: "Streaming, cameras and smart-device messaging.",
  },
  other: { label: "Other", blurb: "Services Cartograph has no notes for yet." },
};

/** Display order for categories (most security-relevant first). */
export const CATEGORY_ORDER: Category[] = [
  "remote",
  "database",
  "files",
  "directory",
  "management",
  "web",
  "mail",
  "media",
  "print",
  "naming",
  "other",
];

type Flag = "review" | "cleartext";

interface Entry {
  label: string;
  category: Category;
  note: string;
  flags?: Flag[];
}

// Keyed by nmap's service name (as in nmap-services / -sV output).
const CATALOGUE: Record<string, Entry> = {
  // Remote access
  ssh: {
    label: "SSH",
    category: "remote",
    note: "Encrypted remote shell and file transfer. Normal on servers; confirm it should be reachable from here and that password logins are restricted.",
  },
  telnet: {
    label: "Telnet",
    category: "remote",
    flags: ["review", "cleartext"],
    note: "Unencrypted remote login — usernames and passwords cross the network in plain text. Usually replaceable with SSH.",
  },
  "ms-wbt-server": {
    label: "Remote Desktop (RDP)",
    category: "remote",
    flags: ["review"],
    note: "Windows remote desktop. A frequent target for password guessing; normally kept off untrusted networks or behind a VPN.",
  },
  vnc: {
    label: "VNC",
    category: "remote",
    flags: ["review", "cleartext"],
    note: "Remote screen sharing. Classic VNC doesn't encrypt the session and is often set up with weak passwords.",
  },
  x11: {
    label: "X11 display",
    category: "remote",
    flags: ["review"],
    note: "Remote graphical display. An open X server can let others watch the screen or inject keystrokes.",
  },
  wsman: {
    label: "WinRM",
    category: "remote",
    flags: ["review"],
    note: "Windows remote management (PowerShell remoting). Powerful admin access; keep it to management networks.",
  },
  login: {
    label: "rlogin",
    category: "remote",
    flags: ["review", "cleartext"],
    note: "Legacy Unix remote login with host-based trust and no encryption. Superseded by SSH.",
  },
  shell: {
    label: "rsh",
    category: "remote",
    flags: ["review", "cleartext"],
    note: "Legacy Unix remote shell with host-based trust and no encryption. Superseded by SSH.",
  },

  // Web
  http: {
    label: "HTTP",
    category: "web",
    flags: ["cleartext"],
    note: "Unencrypted web traffic. Fine for public pages or redirects to HTTPS; logins or admin pages over plain HTTP expose credentials.",
  },
  https: {
    label: "HTTPS",
    category: "web",
    note: "Encrypted web traffic. Check what it serves — admin panels deserve the same scrutiny as any login.",
  },
  "http-proxy": {
    label: "Web (alt port)",
    category: "web",
    note: "A web server or proxy on an alternate port — often an app server, dev server or admin panel. Worth opening to see what it is.",
  },
  "http-alt": {
    label: "Web (alt port)",
    category: "web",
    note: "A web server on an alternate port — often an app server, dev server or admin panel.",
  },
  "https-alt": {
    label: "HTTPS (alt port)",
    category: "web",
    note: "Encrypted web on an alternate port — often an admin console or app server.",
  },

  // Databases
  mysql: {
    label: "MySQL / MariaDB",
    category: "database",
    flags: ["review"],
    note: "Relational database. Rarely needs to be reachable beyond the application server that uses it.",
  },
  postgresql: {
    label: "PostgreSQL",
    category: "database",
    flags: ["review"],
    note: "Relational database. Rarely needs to be reachable beyond the application server that uses it.",
  },
  "ms-sql-s": {
    label: "Microsoft SQL Server",
    category: "database",
    flags: ["review"],
    note: "Relational database and a common target for password guessing. Keep it off general networks.",
  },
  "oracle-tns": {
    label: "Oracle DB listener",
    category: "database",
    flags: ["review"],
    note: "Oracle database listener. Usually restricted to application servers.",
  },
  mongodb: {
    label: "MongoDB",
    category: "database",
    flags: ["review"],
    note: "Document database. Older default installs accepted connections without authentication.",
  },
  redis: {
    label: "Redis",
    category: "database",
    flags: ["review"],
    note: "In-memory data store. Older defaults had no password; anyone who can reach it may read or write its data.",
  },
  memcache: {
    label: "Memcached",
    category: "database",
    flags: ["review"],
    note: "Cache with no built-in authentication; exposed instances have also been abused for traffic amplification.",
  },
  elasticsearch: {
    label: "Elasticsearch",
    category: "database",
    flags: ["review"],
    note: "Search database with an HTTP API. Unprotected instances have caused many data leaks.",
  },
  couchdb: {
    label: "CouchDB",
    category: "database",
    flags: ["review"],
    note: "Document database with an HTTP API. Check that an admin password is set.",
  },

  // File sharing
  "microsoft-ds": {
    label: "SMB file sharing",
    category: "files",
    flags: ["review"],
    note: "Windows / Samba file and printer sharing. Normal on a LAN; should never be exposed to the internet.",
  },
  "netbios-ssn": {
    label: "NetBIOS session",
    category: "files",
    flags: ["review"],
    note: "Legacy transport for SMB file sharing. Usually seen alongside port 445.",
  },
  ftp: {
    label: "FTP",
    category: "files",
    flags: ["review", "cleartext"],
    note: "Unencrypted file transfer; passwords are sent in plain text. Worth checking for anonymous login (the ftp-anon script).",
  },
  tftp: {
    label: "TFTP",
    category: "files",
    flags: ["review", "cleartext"],
    note: "Trivial file transfer with no authentication. Used for network-boot and device configs.",
  },
  nfs: {
    label: "NFS",
    category: "files",
    flags: ["review"],
    note: "Unix network file system. Check which directories are exported and to whom (the nfs-showmount script).",
  },
  rpcbind: {
    label: "RPC portmapper",
    category: "files",
    flags: ["review"],
    note: "Directory of Unix RPC services, often alongside NFS. Reveals which RPC services are running.",
  },
  afp: {
    label: "Apple file sharing",
    category: "files",
    note: "Apple Filing Protocol — macOS file sharing or a NAS.",
  },
  rsync: {
    label: "rsync",
    category: "files",
    flags: ["review"],
    note: "File synchronisation daemon. Modules can be readable without a password.",
  },

  // Mail
  smtp: {
    label: "SMTP",
    category: "mail",
    note: "Mail transfer. Expected on mail servers; on other machines it may be unintended.",
  },
  submission: {
    label: "Mail submission",
    category: "mail",
    note: "Authenticated mail sending for email clients.",
  },
  submissions: {
    label: "Mail submission (TLS)",
    category: "mail",
    note: "Authenticated, encrypted mail sending for email clients.",
  },
  pop3: {
    label: "POP3",
    category: "mail",
    flags: ["cleartext"],
    note: "Mail download. Without STARTTLS, passwords travel unencrypted.",
  },
  pop3s: {
    label: "POP3 (TLS)",
    category: "mail",
    note: "Encrypted mail download.",
  },
  imap: {
    label: "IMAP",
    category: "mail",
    flags: ["cleartext"],
    note: "Mailbox access. Without STARTTLS, passwords travel unencrypted.",
  },
  imaps: {
    label: "IMAP (TLS)",
    category: "mail",
    note: "Encrypted mailbox access.",
  },

  // Printing
  ipp: {
    label: "IPP printing",
    category: "print",
    note: "Internet Printing Protocol — a network printer or a CUPS print server.",
  },
  printer: {
    label: "LPD printing",
    category: "print",
    note: "Legacy Unix print spooler.",
  },
  jetdirect: {
    label: "Raw printing",
    category: "print",
    note: "Accepts print jobs directly, with no authentication (HP JetDirect / port 9100).",
  },

  // Name & discovery
  domain: {
    label: "DNS",
    category: "naming",
    note: "Name resolution. Expected on routers and DNS servers; elsewhere it's unusual.",
  },
  "netbios-ns": {
    label: "NetBIOS names",
    category: "naming",
    note: "Legacy Windows name service; leaks machine and workgroup names.",
  },
  mdns: {
    label: "mDNS / Bonjour",
    category: "naming",
    note: "Zero-config local discovery (printers, AirPlay, Chromecast…).",
  },
  upnp: {
    label: "UPnP",
    category: "naming",
    flags: ["review"],
    note: "Lets devices reconfigure the network automatically (e.g. open router ports). Port 5000 is also common for dev servers — confirm with Service + version.",
  },

  // Directory & auth
  ldap: {
    label: "LDAP",
    category: "directory",
    flags: ["review", "cleartext"],
    note: "Directory lookups (users, groups). Plain LDAP is unencrypted and often reveals account information.",
  },
  ldaps: {
    label: "LDAP (TLS)",
    category: "directory",
    note: "Encrypted directory lookups.",
  },
  "kerberos-sec": {
    label: "Kerberos",
    category: "directory",
    note: "Authentication for Windows domains — usually means a domain controller.",
  },
  msrpc: {
    label: "Microsoft RPC",
    category: "directory",
    flags: ["review"],
    note: "Windows RPC endpoint mapper. Normal inside Windows networks; not something to expose beyond them.",
  },

  // Management
  snmp: {
    label: "SNMP",
    category: "management",
    flags: ["review", "cleartext"],
    note: "Device monitoring. v1/v2c use plaintext community strings, frequently left as 'public'.",
  },
  docker: {
    label: "Docker API",
    category: "management",
    flags: ["review"],
    note: "The Docker daemon API. Without TLS it grants full control of the host to anyone who can reach it.",
  },
  kubernetes: {
    label: "Kubernetes API",
    category: "management",
    flags: ["review"],
    note: "Cluster control plane. Should only be reachable by administrators.",
  },
  kubelet: {
    label: "Kubelet API",
    category: "management",
    flags: ["review"],
    note: "Per-node Kubernetes agent. Misconfigured kubelets allow running commands in containers.",
  },
  ntp: { label: "NTP", category: "management", note: "Time synchronisation." },

  // Media & IoT
  rtsp: {
    label: "RTSP streaming",
    category: "media",
    flags: ["review"],
    note: "Camera and media streams. Many IP cameras ship with default credentials.",
  },
  mqtt: {
    label: "MQTT",
    category: "media",
    flags: ["review", "cleartext"],
    note: "IoT messaging. Brokers often allow anonymous publish/subscribe.",
  },
  sip: {
    label: "SIP (VoIP)",
    category: "media",
    note: "Voice-over-IP signalling — a phone, PBX or VoIP gateway.",
  },
};

// When nmap gives no (or an unhelpful) name, fall back on well-known ports.
const PORT_FALLBACK: Record<number, string> = {
  21: "ftp",
  22: "ssh",
  23: "telnet",
  25: "smtp",
  53: "domain",
  80: "http",
  88: "kerberos-sec",
  110: "pop3",
  111: "rpcbind",
  135: "msrpc",
  139: "netbios-ssn",
  143: "imap",
  161: "snmp",
  389: "ldap",
  443: "https",
  445: "microsoft-ds",
  465: "submissions",
  515: "printer",
  548: "afp",
  554: "rtsp",
  587: "submission",
  631: "ipp",
  636: "ldaps",
  873: "rsync",
  993: "imaps",
  995: "pop3s",
  1433: "ms-sql-s",
  1521: "oracle-tns",
  1883: "mqtt",
  2049: "nfs",
  2375: "docker",
  3306: "mysql",
  3389: "ms-wbt-server",
  5432: "postgresql",
  5900: "vnc",
  5984: "couchdb",
  5985: "wsman",
  6379: "redis",
  6443: "kubernetes",
  8080: "http-proxy",
  8443: "https-alt",
  9100: "jetdirect",
  9200: "elasticsearch",
  10250: "kubelet",
  11211: "memcache",
  27017: "mongodb",
};

export interface ServiceInfo {
  port: Port;
  key: string | null; // catalogue key, if known
  label: string;
  category: Category;
  note: string;
  review: boolean;
  cleartext: boolean;
  tls: boolean;
  /** nmap named it from the port-number table, not by talking to it. */
  guessed: boolean;
}

export function describeService(port: Port): ServiceInfo {
  const svc = port.service;
  const name = svc?.name ?? null;
  const key =
    name && CATALOGUE[name] ? name : (PORT_FALLBACK[port.portid] ?? null);
  const entry = key ? CATALOGUE[key] : null;
  const tls = svc?.tunnel === "ssl" || port.cert !== null;
  let label = entry?.label ?? name ?? "unknown";
  let note = entry?.note ?? CATEGORIES.other.blurb;
  let cleartext = entry?.flags?.includes("cleartext") ?? false;
  if (tls && cleartext) {
    // e.g. -sV's name="http" tunnel="ssl": the transport is encrypted.
    cleartext = false;
    label = `${label} over TLS`;
    note =
      entry?.category === "web"
        ? CATALOGUE.https.note
        : "Wrapped in TLS, so traffic to it is encrypted.";
  }
  return {
    port,
    key,
    label,
    category: entry?.category ?? "other",
    note,
    review: entry?.flags?.includes("review") ?? false,
    cleartext,
    tls,
    guessed: svc == null || svc.method === "table",
  };
}

// --- Per-host model -------------------------------------------------------

export interface HostExposure {
  host: Host;
  addr: string;
  /** Best display name: nmap's reverse DNS, else the mDNS name. */
  name: string | null;
  mdnsName: string | null;
  mac: string | null;
  /** Where the MAC came from: nmap itself (root scans) or the OS ARP cache. */
  macSource: "nmap" | "arp" | null;
  vendor: string | null;
  macRandomized: boolean;
  subnet: string;
  services: ServiceInfo[]; // open ports only
  hiddenPorts: number; // closed / filtered, not shown on the map
  device: DeviceGuess;
  reviewCount: number;
  cleartextCount: number;
}

/** /24 for IPv4, else a catch-all group. */
export function subnetOf(addr: string): string {
  if (/^127\./.test(addr) || addr === "::1") return "This computer (loopback)";
  const m = addr.match(/^(\d+)\.(\d+)\.(\d+)\.\d+$/);
  return m ? `${m[1]}.${m[2]}.${m[3]}.0/24` : "Other addresses";
}

/** Numeric sort key for IPv4 addresses (others sort after, by string). */
export function addrSortKey(addr: string): number {
  const m = addr.match(/^(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  if (!m) return Number.MAX_SAFE_INTEGER;
  return ((+m[1] * 256 + +m[2]) * 256 + +m[3]) * 256 + +m[4];
}

export function hostExposure(h: Host): HostExposure {
  const v4 = h.addresses.find((a) => a.addrType === "ipv4");
  const addr =
    (v4 ?? h.addresses.find((a) => a.addrType !== "mac") ?? h.addresses[0])
      ?.addr ?? "(unknown)";
  const nmapMac = h.addresses.find((a) => a.addrType === "mac");
  const id = h.identity;
  const mac = nmapMac?.addr ?? id?.mac ?? null;
  const vendor = nmapMac?.vendor ?? id?.vendor ?? null;
  const macRandomized = id?.macRandomized ?? false;
  const mdnsName = id?.mdnsName ?? null;
  const services = h.ports
    .filter((p) => p.state === "open")
    .sort((a, b) => a.portid - b.portid)
    .map(describeService);
  const names = [...h.hostnames, ...(mdnsName ? [mdnsName] : [])];
  return {
    host: h,
    addr,
    name: names[0] ?? null,
    mdnsName,
    mac,
    macSource: nmapMac ? "nmap" : id?.mac ? "arp" : null,
    vendor,
    macRandomized,
    subnet: subnetOf(addr),
    services,
    hiddenPorts: h.ports.length - services.length,
    device: guessDevice({ addr, names, vendor, macRandomized, services }),
    reviewCount: services.filter((s) => s.review).length,
    cleartextCount: services.filter((s) => s.cleartext).length,
  };
}
