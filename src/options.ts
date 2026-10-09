import catalogue from "./nmap-options.json";
import type { CmdItem } from "./types";

/** How an option is written: a bare flag, `-x value`, or `-xVALUE`. */
export type OptionForm = "flag" | "value" | "attached";

export interface OptionArg {
  kind: "ports" | "int" | "float" | "time" | "text" | "file" | "hosts" | "choice";
  placeholder?: string;
  /** The value may be omitted (e.g. `-PS` alone pings port 80). */
  optional?: boolean;
  /** `[value, label]` pairs for `choice`. */
  choices?: [string, string][];
}

export interface OptionDef {
  /** Canonical spelling, exactly as the backend's parser names it. */
  name: string;
  form: OptionForm;
  arg?: OptionArg;
  summary: string;
  detail?: string;
  /** Needs raw-socket privileges (root / admin). */
  root?: boolean;
  risk?: "noisy" | "evasion" | "spoofing";
  /** Options in the same group are mutually exclusive (one TCP scan type,
   *  -p vs -F, …); choosing one removes the others. */
  group?: string;
}

export interface OptionSection {
  id: string;
  title: string;
  options: OptionDef[];
}

/** Every scanning-relevant nmap option, in nmap's own section order. The
 *  backend test `ui_catalogue_matches_the_parser` checks each entry parses
 *  back to itself. */
export const SECTIONS = catalogue.sections as OptionSection[];

const BY_NAME = new Map(
  SECTIONS.flatMap((s) => s.options.map((o) => [o.name, o] as const)),
);

export function findOption(name: string): OptionDef | undefined {
  return BY_NAME.get(name);
}

/** The canonical item for a catalogue option — same tokens the backend's
 *  parser would produce (mirrored in the Rust catalogue test). */
export function makeItem(def: OptionDef, value: string | null): CmdItem {
  const v = value ?? "";
  let tokens: string[];
  if (def.form === "flag") tokens = [def.name];
  else if (def.form === "attached") tokens = [def.name + v];
  else if (!def.name.startsWith("--") && v.startsWith("-"))
    tokens = [def.name + v]; // e.g. -p- (all ports)
  else tokens = [def.name, v];
  return { kind: "option", name: def.name, value, tokens };
}

/**
 * Set (or with `value === undefined`, remove) an option in a list of option
 * items. Other options in the same exclusive group are removed. The option
 * keeps its position if it was already present, so editing a value doesn't
 * reshuffle the command.
 */
export function setOption(
  items: CmdItem[],
  def: OptionDef,
  value?: string | null,
): CmdItem[] {
  const clash = (i: CmdItem) => {
    if (i.name === def.name) return true;
    const other = findOption(i.name);
    return !!def.group && other?.group === def.group;
  };
  const at = items.findIndex(clash);
  const kept = items.filter((i) => !clash(i));
  if (value === undefined) return kept;
  const item = makeItem(def, value);
  const pos = at === -1 ? kept.length : Math.min(at, kept.length);
  return [...kept.slice(0, pos), item, ...kept.slice(pos)];
}

/** Quote one argv token for display/copy the way a POSIX shell reads it. */
export function quoteArg(tok: string): string {
  if (/^[A-Za-z0-9_@%+=:,./-]+$/.test(tok)) return tok;
  return `'${tok.replace(/'/g, `'\\''`)}'`;
}

/** The full command line: options, then the target text exactly as typed
 *  (it may hold several space-separated targets). */
export function commandText(items: CmdItem[], target: string): string {
  const opts = items.flatMap((i) => i.tokens).map(quoteArg);
  return ["nmap", ...opts, target.trim()].filter(Boolean).join(" ");
}
