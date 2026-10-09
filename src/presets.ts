import { findOption, makeItem } from "./options";
import type { IconName } from "./components/Icon";
import type { CmdItem } from "./types";

/** A built-in scan profile. Applying a profile (built-in or saved) replaces
 *  the whole option set; the target is kept. */
export interface Preset {
  id: string;
  label: string;
  /** Shown under the label so the user learns what the flags do. */
  description: string;
  icon: IconName;
  /** The options this profile sets, as canonical items. */
  items: CmdItem[];
}

function opt(name: string, value: string | null = null): CmdItem {
  const def = findOption(name);
  if (!def) throw new Error(`preset uses unknown option ${name}`);
  return makeItem(def, value);
}

// Root-only ones (Intense, UDP) tick "Run as root" by themselves.
export const PRESETS: Preset[] = [
  {
    id: "quick",
    label: "Quick",
    description: "Top 100 ports — fastest",
    icon: "zap",
    items: [opt("-F")],
  },
  {
    id: "regular",
    label: "Regular",
    description: "Top 1000 ports — nmap default",
    icon: "layers",
    items: [],
  },
  {
    id: "version",
    label: "Service + version",
    description: "Identify service & version on open ports",
    icon: "fingerprint",
    items: [opt("-sV")],
  },
  {
    id: "intense",
    label: "Intense",
    description: "OS, versions, default scripts, traceroute (root)",
    icon: "cpu",
    items: [opt("-T", "4"), opt("-A")],
  },
  {
    id: "ping",
    label: "Ping sweep",
    description: "Which hosts are up — no port scan",
    icon: "globe",
    items: [opt("-sn")],
  },
  {
    id: "udp",
    label: "UDP top 100",
    description: "Most common UDP ports — slow (root)",
    icon: "server",
    items: [opt("-sU"), opt("--top-ports", "100")],
  },
  {
    id: "full",
    label: "Full TCP",
    description: "All 65,535 TCP ports — slow",
    icon: "list",
    items: [opt("-p", "-")],
  },
  {
    id: "vuln",
    label: "Vuln scripts",
    description: "Versions + NSE vuln checks — intrusive",
    icon: "shield",
    items: [opt("-sV"), opt("--script", "vuln")],
  },
];

/** The same options, ignoring order (what "this profile is active" means). */
export function sameOptions(a: CmdItem[], b: CmdItem[]): boolean {
  const key = (xs: CmdItem[]) =>
    xs
      .map((i) => i.tokens.join(" "))
      .sort()
      .join("\u0000");
  return key(a) === key(b);
}
