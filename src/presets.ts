import { findOption, makeItem, setOption } from "./options";
import type { CmdItem } from "./types";

export interface Preset {
  id: string;
  label: string;
  /** Shown under the label so the user learns what the flags do. */
  description: string;
  /** The options this preset sets, as canonical items. */
  items: CmdItem[];
}

function opt(name: string, value: string | null = null): CmdItem {
  const def = findOption(name);
  if (!def) throw new Error(`preset uses unknown option ${name}`);
  return makeItem(def, value);
}

// Deliberately root-free presets: Cartograph runs unprivileged, so no -sS/-O/-A
// (which need raw sockets / root). These all work as an ordinary user.
export const PRESETS: Preset[] = [
  {
    id: "quick",
    label: "Quick",
    description: "Top 100 ports — fastest (-F)",
    items: [opt("-F")],
  },
  {
    id: "regular",
    label: "Regular",
    description: "Top 1000 ports — nmap default",
    items: [],
  },
  {
    id: "version",
    label: "Service + version",
    description: "Identify service & version on open ports (-sV)",
    items: [opt("-sV")],
  },
];

/** Option names any preset manages. Presets only swap these; everything else
 *  the user set (scripts, timing, …) survives a preset change. */
const PRESET_NAMES = new Set(PRESETS.flatMap((p) => p.items.map((i) => i.name)));

export function applyPreset(items: CmdItem[], preset: Preset): CmdItem[] {
  let next = items.filter((i) => !PRESET_NAMES.has(i.name));
  for (const item of preset.items)
    next = setOption(next, findOption(item.name)!, item.value);
  return next;
}

/** The preset whose managed options are exactly the ones currently set. */
export function matchingPreset(items: CmdItem[]): Preset | undefined {
  const set = (xs: CmdItem[]) =>
    xs
      .filter((i) => PRESET_NAMES.has(i.name))
      .map((i) => i.tokens.join(" "))
      .sort()
      .join("\u0000");
  const current = set(items);
  return PRESETS.find((p) => set(p.items) === current);
}
