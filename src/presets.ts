export interface Preset {
  id: string;
  label: string;
  /** Shown under the label so the user learns what the flags do. */
  description: string;
  /** nmap flags for this preset. The backend appends `-oX -`. */
  flags: string[];
}

// Deliberately root-free presets: Cartograph runs unprivileged, so no -sS/-O/-A
// (which need raw sockets / root). These all work as an ordinary user.
export const PRESETS: Preset[] = [
  {
    id: "quick",
    label: "Quick",
    description: "Top 100 ports — fastest (-F)",
    flags: ["-F"],
  },
  {
    id: "regular",
    label: "Regular",
    description: "Top 1000 ports — nmap default",
    flags: [],
  },
  {
    id: "version",
    label: "Service + version",
    description: "Identify service & version on open ports (-sV)",
    flags: ["-sV"],
  },
];

/** The literal nmap command the user would type — our `-oX -` capture flag is
 *  intentionally omitted so the shown command is reproducible in a terminal. */
export function buildCommand(flags: string[], target: string): string {
  return ["nmap", ...flags, target.trim() || "<target>"].join(" ");
}
