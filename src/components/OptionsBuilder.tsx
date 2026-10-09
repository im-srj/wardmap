import { useMemo, useState } from "react";
import {
  SECTIONS,
  findOption,
  setOption,
  type OptionDef,
} from "../options";
import type { CmdItem } from "../types";
import { Icon } from "./Icon";

interface Props {
  /** The command's options (no targets), as canonical items. */
  items: CmdItem[];
  onChange: (items: CmdItem[]) => void;
  /** Hide the panel (ScanForm's collapsed state); chips stay hidden too. */
  collapsed?: boolean;
}

const RISK_LABEL: Record<NonNullable<OptionDef["risk"]>, string> = {
  noisy: "noisy",
  evasion: "evasion",
  spoofing: "spoofing",
};

function matches(def: OptionDef, q: string): boolean {
  return (
    def.name.toLowerCase().includes(q) ||
    def.summary.toLowerCase().includes(q) ||
    (def.detail ?? "").toLowerCase().includes(q)
  );
}

/**
 * Every nmap option, browsable by nmap's own sections and searchable by flag
 * or meaning. Edits go straight into the command's option items, so the
 * command preview (and the run) always reflect exactly what's ticked here.
 * Options the catalogue doesn't cover — typed in the command line — still
 * show as chips and can be removed.
 */
export function OptionsBuilder({ items, onChange, collapsed = false }: Props) {
  const [open, setOpen] = useState(false);
  const [query, setQuery] = useState("");
  const [openSections, setOpenSections] = useState<Set<string>>(
    () => new Set(["technique"]),
  );

  const q = query.trim().toLowerCase();
  const results = useMemo(
    () =>
      q === ""
        ? []
        : SECTIONS.flatMap((s) => s.options.filter((o) => matches(o, q))),
    [q],
  );

  if (collapsed) return null;

  const set = (def: OptionDef, value?: string | null) =>
    onChange(setOption(items, def, value));

  function toggleSection(id: string) {
    setOpenSections((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id);
      else next.add(id);
      return next;
    });
  }

  const row = (def: OptionDef) => (
    <OptionRow
      key={def.name}
      def={def}
      item={items.find((i) => i.name === def.name)}
      onSet={(v) => set(def, v)}
    />
  );

  return (
    <div className="nse">
      <div className="nse__bar">
        <button
          type="button"
          className={"nse__toggle" + (open ? " nse__toggle--open" : "")}
          onClick={() => setOpen((o) => !o)}
          aria-expanded={open}
        >
          <Icon
            name={open ? "chevronDown" : "chevronRight"}
            size={14}
            className="nse__caret"
          />
          <Icon name="layers" size={15} />
          All options
          {items.length > 0 && (
            <span className="nse__count">{items.length} set</span>
          )}
          <span className="nse__hint">ports, timing, discovery, evasion…</span>
        </button>
        {items.map((item, i) => {
          const known = item.kind === "option";
          return (
            <span
              key={`${i}-${item.tokens.join(" ")}`}
              className={"nse-chip" + (known ? "" : " nse-chip--unknown")}
              title={
                known
                  ? findOption(item.name)?.summary
                  : "Not an nmap 7.94 option"
              }
            >
              <span className="mono">{item.tokens.join(" ")}</span>
              <button
                type="button"
                className="nse-chip__remove"
                onClick={() => onChange(items.filter((_, j) => j !== i))}
                aria-label={`Remove ${item.tokens.join(" ")}`}
              >
                <Icon name="x" size={12} />
              </button>
            </span>
          );
        })}
      </div>

      {open && (
        <div className="nse__panel">
          <label className="inline-search nse__search">
            <Icon name="search" size={14} />
            <input
              type="search"
              placeholder="Search options by flag or what they do — e.g. “udp”, “-Pn”, “timeout”…"
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              spellCheck={false}
              aria-label="Search nmap options"
            />
          </label>

          {q !== "" ? (
            <ul className="nse__list opt-list">
              {results.length === 0 && (
                <li className="muted nse__empty">No options match.</li>
              )}
              {results.map(row)}
            </ul>
          ) : (
            <div className="opt-sections">
              {SECTIONS.map((s) => {
                const isOpen = openSections.has(s.id);
                const active = s.options.filter((o) =>
                  items.some((i) => i.name === o.name),
                ).length;
                return (
                  <section key={s.id} className="opt-section">
                    <button
                      type="button"
                      className="opt-section__head"
                      onClick={() => toggleSection(s.id)}
                      aria-expanded={isOpen}
                    >
                      <Icon
                        name={isOpen ? "chevronDown" : "chevronRight"}
                        size={13}
                        className="nse__caret"
                      />
                      {s.title}
                      <span className="opt-section__n">
                        {active > 0
                          ? `${active} of ${s.options.length}`
                          : s.options.length}
                      </span>
                    </button>
                    {isOpen && (
                      <ul className="nse__list opt-list">
                        {s.options.map(row)}
                      </ul>
                    )}
                  </section>
                );
              })}
            </div>
          )}
          <p className="opt-footnote">
            Output options (-oX, -oN…) are handled by Cartograph: it always
            captures nmap's XML itself. Anything not listed here can be typed
            straight into the command line below.
          </p>
        </div>
      )}
    </div>
  );
}

function OptionRow({
  def,
  item,
  onSet,
}: {
  def: OptionDef;
  item: CmdItem | undefined;
  /** A value (or null for a bare optional flag) sets it; undefined clears. */
  onSet: (value?: string | null) => void;
}) {
  const [draft, setDraft] = useState("");
  const [showDetail, setShowDetail] = useState(false);
  const arg = def.arg;
  const on = item !== undefined;
  const shown = on ? (item.value ?? "") : draft;

  function onToggle() {
    if (on) onSet(undefined);
    else if (!arg) onSet(null);
    else if (draft || arg.optional) onSet(draft || null);
    // A required value with nothing typed: wait for the user to type one.
  }

  function onType(v: string) {
    setDraft(v);
    if (v) onSet(v);
    else if (arg?.optional && on) onSet(null);
    else if (on) onSet(undefined);
  }

  return (
    <li className={"nse-item opt-row" + (on ? " nse-item--selected" : "")}>
      <div className="opt-row__main">
        {arg?.kind === "choice" ? (
          <select
            className="opt-row__select"
            value={on ? (item.value ?? "") : ""}
            onChange={(e) =>
              e.target.value ? onSet(e.target.value) : onSet(undefined)
            }
            aria-label={def.name}
          >
            <option value="">{def.name} —</option>
            {arg.choices?.map(([v, label]) => (
              <option key={v} value={v}>
                {label}
              </option>
            ))}
          </select>
        ) : (
          <label className="nse-item__pick opt-row__pick">
            <input type="checkbox" checked={on} onChange={onToggle} />
            <span className="mono nse-item__id">{def.name}</span>
          </label>
        )}
        {arg && arg.kind !== "choice" && (
          <input
            className="opt-row__input mono"
            type="text"
            value={shown}
            placeholder={
              (arg.optional ? "optional: " : "") + (arg.placeholder ?? "")
            }
            onChange={(e) => onType(e.target.value)}
            spellCheck={false}
            aria-label={`${def.name} value`}
          />
        )}
        <span className="opt-row__summary">{def.summary}</span>
        <span className="nse-item__tags opt-row__tags">
          {def.root && (
            <span
              className="nse-tag nse-tag--risky"
              title="Needs root/administrator privileges"
            >
              root
            </span>
          )}
          {def.risk && (
            <span className="nse-tag nse-tag--risky">
              {RISK_LABEL[def.risk]}
            </span>
          )}
        </span>
        {def.detail && (
          <button
            type="button"
            className="nse-item__more"
            onClick={() => setShowDetail((d) => !d)}
            aria-expanded={showDetail}
          >
            {showDetail ? "less" : "more"}
          </button>
        )}
      </div>
      {showDetail && def.detail && (
        <p className="nse-item__desc nse-item__desc--full">{def.detail}</p>
      )}
    </li>
  );
}
