// Device-type guessing. Two independent questions:
//   what is it?   — hardware, from its names (rDNS / mDNS), MAC vendor, or a
//                   randomized MAC
//   what does it do? — role, from its open services
// The label shows the most specific answer; when both are known the role is
// shown alongside ("Desktop / laptop · Database server"). Everything here is a
// heuristic and the UI must always present it as a guess.

import type { ServiceInfo } from "./exposure";

export type DeviceKind =
  | "self"
  | "router"
  | "printer"
  | "domain-controller"
  | "windows"
  | "computer"
  | "apple"
  | "phone"
  | "tv"
  | "iot"
  | "camera"
  | "database"
  | "nas"
  | "mail"
  | "web"
  | "server"
  | "vm"
  | "unknown";

export interface DeviceGuess {
  kind: DeviceKind;
  label: string;
  /** What it does, when that's different from what it is. */
  role: string | null;
  /** Short human reason, e.g. `mDNS name "Johns-iPhone.local"`. */
  because: string | null;
}

interface Clue {
  kind: DeviceKind;
  label: string;
  because: string;
}

export interface DeviceInput {
  addr: string;
  names: string[]; // rDNS hostnames + mDNS name
  vendor: string | null;
  macRandomized: boolean;
  services: ServiceInfo[];
}

// --- Hardware clues ---------------------------------------------------------

// Patterns are matched against lowercased host names. First match wins, so
// specific products come before generic words.
const NAME_PATTERNS: [RegExp, DeviceKind, string][] = [
  [/iphone/, "phone", "iPhone"],
  [/ipad/, "phone", "iPad"],
  [/macbook|imac|mac-?mini|mac-?pro|mac-?studio/, "apple", "Mac"],
  [/apple-?tv/, "tv", "Apple TV"],
  [/homepod/, "tv", "HomePod speaker"],
  [
    /chromecast|google-?tv|google-?home|google-?nest|\bnest-/,
    "tv",
    "Google Cast / Nest device",
  ],
  [
    /roku|fire-?tv|firestick|bravia|webos|lg-?tv|samsung-?tv|tizen|android-?tv|smart-?tv|(^|[-_])tv([-_.]|$)/,
    "tv",
    "Smart TV / streamer",
  ],
  [/(^|[-_])echo([-_.\d]|$)|alexa|kindle/, "iot", "Amazon Echo / Kindle"],
  [/sonos/, "tv", "Sonos speaker"],
  [
    /android|pixel|galaxy|oneplus|redmi|xiaomi|(^|[-_])(poco|oppo|vivo|honor)([-_.\d]|$)|realme|motorola|moto-g|huawei/,
    "phone",
    "Android phone or tablet",
  ],
  [
    /laserjet|officejet|deskjet|epson|brother|canon|printer|mfc-?\d/,
    "printer",
    "Printer",
  ],
  [/raspberrypi|raspberry/, "iot", "Raspberry Pi"],
  [
    /^esp[-_]|esp32|esp8266|tasmota|shelly|sonoff|tuya|wled/,
    "iot",
    "Smart-home / IoT device",
  ],
  [
    /synology|diskstation|qnap|truenas|unraid|(^|[-_])nas([-_.]|$)/,
    "nas",
    "NAS",
  ],
  [
    /openwrt|router|gateway|(^|[-_])ap([-_.\d]|$)/,
    "router",
    "Router / access point",
  ],
  // Linux installers default the hostname to "<user>-<motherboard model>",
  // e.g. "raj-MS-7E44", "user-H410M-H", "zeb-All-Series".
  [
    /ms-7[0-9a-z]{3}|(^|[-_])[abhxz]\d{2,3}m?(-[a-z0-9]+)?([.]|$)|all-series|system-product-name|to-be-filled-by-o-e-m|-desktop([.]|$)/,
    "computer",
    "Desktop PC",
  ],
  // Windows' default hostnames: DESKTOP-XXXXXXX / LAPTOP-XXXXXXXX.
  [/^(desktop|laptop)-[a-z0-9]{7,8}\b/, "windows", "Windows computer"],
];

const VENDOR_PATTERNS: [RegExp, DeviceKind, string][] = [
  [/^apple/i, "apple", "Apple device"],
  [
    /espressif|tuya|shelly|itead|particle|signify|philips lighting|lifx|wiz/i,
    "iot",
    "Smart-home / IoT device",
  ],
  [/raspberry pi/i, "iot", "Raspberry Pi"],
  [/amazon/i, "iot", "Amazon device (Echo / Fire / Kindle)"],
  [/^google/i, "tv", "Google device (Cast / Nest / Pixel)"],
  [/sonos/i, "tv", "Sonos speaker"],
  [/roku/i, "tv", "Roku streamer"],
  [
    /seiko epson|brother industries|canon|lexmark|kyocera|xerox|ricoh/i,
    "printer",
    "Printer",
  ],
  [/synology|qnap/i, "nas", "NAS"],
  [/hikvision|dahua|axis comm|reolink|wyze/i, "camera", "IP camera"],
  [
    /ubiquiti|mikrotik|routerboard|tp-?link|netgear|cisco|linksys|aruba|juniper|zyxel|d-link|draytek/i,
    "router",
    "Network device (router / AP / switch)",
  ],
  [
    /samsung|xiaomi|oneplus|oppo|vivo|huawei|motorola|realme|zte|honor/i,
    "phone",
    "Phone or tablet",
  ],
  [
    /vmware|qemu|pcs systemtechnik|parallels|xensource|nutanix/i,
    "vm",
    "Virtual machine",
  ],
  // Network chips that almost always mean a PC motherboard or laptop.
  [
    /giga-?byte|asustek|micro-star|asrock|elitegroup|realtek|intel corporate|dell|lenovo|liteon|azurewave|foxconn|pegatron|biostar/i,
    "computer",
    "Desktop / laptop",
  ],
];

function nameClue(names: string[]): Clue | null {
  for (const raw of names) {
    const n = raw.toLowerCase();
    for (const [re, kind, label] of NAME_PATTERNS) {
      if (re.test(n)) return { kind, label, because: `name “${raw}”` };
    }
  }
  return null;
}

function vendorClue(vendor: string | null): Clue | null {
  if (!vendor) return null;
  for (const [re, kind, label] of VENDOR_PATTERNS) {
    if (re.test(vendor)) {
      const because =
        kind === "computer" ? `${vendor} network chip` : `${vendor} hardware`;
      return { kind, label, because };
    }
  }
  return null;
}

// --- Role clues (from services) -------------------------------------------

function isGatewayAddr(addr: string): boolean {
  return /^\d+\.\d+\.\d+\.(1|254)$/.test(addr);
}

/** Roles that also say what the box *is* (a printer is a printer). */
function strongRole(input: DeviceInput, hw: Clue | null): Clue | null {
  const { services, addr } = input;
  const has = (...keys: string[]) =>
    services.find((s) => s.key !== null && keys.includes(s.key));
  const on = (s: ServiceInfo) => `${s.label} on ${s.port.portid}`;

  const print = has("ipp", "printer", "jetdirect");
  if (print) return { kind: "printer", label: "Printer", because: on(print) };

  const dns = has("domain") ?? has("upnp");
  if (dns && (isGatewayAddr(addr) || hw?.kind === "router")) {
    return {
      kind: "router",
      label: "Router / gateway",
      because: `${on(dns)} at ${isGatewayAddr(addr) ? "a gateway address" : "network hardware"}`,
    };
  }
  if (has("kerberos-sec") && has("ldap", "ldaps")) {
    return {
      kind: "domain-controller",
      label: "Windows domain controller",
      because: "Kerberos + LDAP",
    };
  }
  const rdp = has("ms-wbt-server");
  if ((rdp && !rdp.guessed) || (has("msrpc") && has("microsoft-ds"))) {
    return {
      kind: "windows",
      label: "Windows computer",
      because: rdp && !rdp.guessed ? on(rdp) : "Microsoft RPC + SMB",
    };
  }
  const cam = has("rtsp");
  if (cam)
    return { kind: "camera", label: "Camera / media device", because: on(cam) };
  return null;
}

/** Roles that describe what a box does, not what it is. */
function weakRole(services: ServiceInfo[]): Clue | null {
  const on = (s: ServiceInfo) => `${s.label} on ${s.port.portid}`;
  const first = (pred: (s: ServiceInfo) => boolean) => services.find(pred);
  const db = first((s) => s.category === "database");
  if (db)
    return { kind: "database", label: "Database server", because: on(db) };
  const files = first(
    (s) => s.key === "microsoft-ds" || s.key === "nfs" || s.key === "afp",
  );
  if (files) return { kind: "nas", label: "File server", because: on(files) };
  const mail = first((s) => s.category === "mail");
  if (mail) return { kind: "mail", label: "Mail server", because: on(mail) };
  const web = first((s) => s.category === "web");
  if (web) return { kind: "web", label: "Web server", because: on(web) };
  const ssh = first((s) => s.key === "ssh");
  if (ssh) return { kind: "server", label: "SSH server", because: on(ssh) };
  return null;
}

// --- Combine ----------------------------------------------------------------

export function guessDevice(input: DeviceInput): DeviceGuess {
  const { addr, names, vendor, macRandomized, services } = input;
  if (/^127\./.test(addr) || addr === "::1") {
    return {
      kind: "self",
      label: "This computer",
      role: null,
      because: "loopback address",
    };
  }

  const byName = nameClue(names);
  const byVendor = vendorClue(vendor);
  const strong = strongRole(input, byName ?? byVendor);
  const weak = weakRole(services);

  // Most specific identity first: a recognisable name beats services, which
  // beat a vendor (a Realtek chip could be in anything), which beat nothing.
  // Exception: on PC hardware, printer/camera services are something the PC
  // *does* (e.g. a desktop sharing a printer via CUPS), not what it *is*.
  const pcHardware = ["computer", "apple", "vm"].includes(byVendor?.kind ?? "");
  const strongIsIdentity =
    strong &&
    !(pcHardware && (strong.kind === "printer" || strong.kind === "camera"));
  const what: Clue | null =
    byName ??
    (strongIsIdentity ? strong : null) ??
    byVendor ??
    (macRandomized
      ? {
          kind: "phone",
          label: "Phone, tablet or laptop",
          because: "private (randomized) Wi-Fi address",
        }
      : null);

  if (!what) {
    if (weak) return { ...weak, role: null };
    return {
      kind: "unknown",
      label: "Unknown device",
      role: null,
      because: null,
    };
  }

  // Show what it does alongside, unless that just repeats what it is.
  // Demoted printer/camera roles on PC hardware read as services it offers.
  const asRole = (r: Clue | null): Clue | null =>
    r && r === strong && !strongIsIdentity
      ? { ...r, label: r.kind === "printer" ? "Print server" : "Media server" }
      : r;
  // Routers and printers serve web/SSH for their own admin UI — not a role.
  const appliance = what.kind === "router" || what.kind === "printer";
  const doing =
    [asRole(strong), appliance ? null : weak].find(
      (r) => r && r.kind !== what.kind,
    ) ?? null;
  const because = [what.because, doing?.because].filter(Boolean).join("; ");
  return {
    kind: what.kind,
    label: what.label,
    role: doing?.label ?? null,
    because,
  };
}
