import { useMemo, useState } from "react";
import { listNseScripts } from "../api";
import {
  SCRIPT_SECTION,
  findOption,
  isScriptOption,
  setOption,
} from "../options";
import type { CmdItem, NseScript } from "../types";
import { Icon } from "./Icon";
import { OptionRow } from "./OptionsBuilder";

interface Props {
  /** The command's options; this panel edits nmap's Scripts (NSE) ones. */
  items: CmdItem[];
  onChange: (items: CmdItem[]) => void;
  /** Hide the picker but keep the intrusive-script warning (and this
   *  component's loaded catalogue) — see ScanForm's collapsible options. */
  collapsed?: boolean;
}

const SCRIPT_DEF = findOption("--script")!;
/** The section's other options (-sC, --script-args…); --script itself is
 *  what the picker edits. */
const SETTINGS = SCRIPT_SECTION.options.filter((o) => o !== SCRIPT_DEF);

/** Categories whose scripts can crash services, lock accounts, or trip IDS —
 *  selecting one shows a warning. */
const RISKY = new Set(["intrusive", "brute", "dos", "exploit"]);

/** First paragraph of an NSEDoc description, unwrapped to one line. */
function summary(description: string): string {
  return description.split(/\n\s*\n/)[0].replace(/\s+/g, " ");
}

/** Searchable, categorized picker over the installed nmap's NSE scripts,
 *  plus the rest of nmap's script options — the one place they're edited.
 *  The catalogue is loaded from nmap the first time the panel is opened. */
export function ScriptBrowser({
  items,
  onChange,
  collapsed = false,
}: Props) {
  const [open, setOpen] = useState(false);
  const [scripts, setScripts] = useState<NseScript[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [category, setCategory] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<string | null>(null);
  const [showSettings, setShowSettings] = useState(false);

  async function toggleOpen() {
    const next = !open;
    setOpen(next);
    if (next && scripts === null) {
      setError(null);
      try {
        setScripts(await listNseScripts());
      } catch (e) {
        setError(String(e));
      }
    }
  }

  // The picker edits --script's comma list. Categories or expressions (added
  // here as a whole category, or typed into the command line) ride along as
  // entries of their own.
  const selected = (items.find((i) => i.name === "--script")?.value ?? "")
    .split(",")
    .filter(Boolean);
  const settings = items
    .map((item, i) => ({ item, i }))
    .filter(
      ({ item }) => isScriptOption(item.name) && item.name !== SCRIPT_DEF.name,
    );
  function setSelected(ids: string[]) {
    onChange(
      setOption(items, SCRIPT_DEF, ids.length ? ids.join(",") : undefined),
    );
  }

  const categories = useMemo(() => {
    const counts = new Map<string, number>();
    for (const s of scripts ?? [])
      for (const c of s.categories) counts.set(c, (counts.get(c) ?? 0) + 1);
    return [...counts.entries()].sort(([a], [b]) => a.localeCompare(b));
  }, [scripts]);

  const visible = useMemo(() => {
    const q = query.trim().toLowerCase();
    return (scripts ?? []).filter(
      (s) =>
        (category === null || s.categories.includes(category)) &&
        (q === "" ||
          s.id.toLowerCase().includes(q) ||
          s.description.toLowerCase().includes(q)),
    );
  }, [scripts, query, category]);

  const byId = useMemo(
    () => new Map((scripts ?? []).map((s) => [s.id, s])),
    [scripts],
  );
  const risky = selected.filter(
    (id) =>
      RISKY.has(id) || byId.get(id)?.categories.some((c) => RISKY.has(c)),
  );
  const nSet = settings.length;

  function toggle(id: string) {
    setSelected(
      selected.includes(id)
        ? selected.filter((s) => s !== id)
        : [...selected, id].sort(),
    );
  }

  return (
    <div className="nse">
      {!collapsed && (
        <div className="nse__bar">
          <button
            type="button"
            className={"nse__toggle" + (open ? " nse__toggle--open" : "")}
            onClick={toggleOpen}
            aria-expanded={open}
          >
            <Icon
              name={open ? "chevronDown" : "chevronRight"}
              size={14}
              className="nse__caret"
            />
            <Icon name="code" size={15} />
            {selected.length + nSet > 0 ? "NSE scripts" : "Add NSE scripts"}
            {selected.length > 0 && (
              <span className="nse__count">{selected.length} selected</span>
            )}
            <span className="nse__hint">titles, certs, vuln checks…</span>
          </button>
          {selected.map((id) => (
            <span key={id} className="nse-chip">
              <span className="mono">{id}</span>
              <button
                type="button"
                className="nse-chip__remove"
                onClick={() => toggle(id)}
                aria-label={`Remove ${id}`}
              >
                <Icon name="x" size={12} />
              </button>
            </span>
          ))}
          {settings.map(({ item, i }) => (
            <span
              key={`${i}-${item.tokens.join(" ")}`}
              className="nse-chip"
              title={findOption(item.name)?.summary}
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
          ))}
          {selected.length + nSet > 1 && (
            <button
              type="button"
              className="nse__clear"
              onClick={() =>
                onChange(items.filter((i) => !isScriptOption(i.name)))
              }
            >
              clear
            </button>
          )}
        </div>
      )}

      {risky.length > 0 && (
        <div className="nse__warn" role="note">
          <Icon name="alert" size={16} />
          <span>
            <strong>{risky.join(", ")}</strong>{" "}
            {risky.length === 1 ? "is" : "are"} intrusive (brute force, DoS or
            exploit): {risky.length === 1 ? "it" : "they"} can crash services,
            lock accounts or trigger alerts. Only run against targets you own or
            are authorized to test.
          </span>
        </div>
      )}

      {open && !collapsed && (
        <div className="nse__panel">
          {error && (
            <div className="error-banner" role="alert">
              {error}
            </div>
          )}
          {!error && scripts === null && (
            <p className="placeholder placeholder--busy">Loading scripts</p>
          )}
          {scripts && (
            <>
              <label className="inline-search nse__search">
                <Icon name="search" size={14} />
                <input
                  type="search"
                  placeholder={`Search ${scripts.length} scripts by name or description…`}
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  spellCheck={false}
                  aria-label="Search NSE scripts"
                />
              </label>
              <div className="nse__cats" role="group" aria-label="Category">
                <button
                  type="button"
                  className={
                    "nse-cat" + (category === null ? " nse-cat--active" : "")
                  }
                  onClick={() => setCategory(null)}
                >
                  all <span className="nse-cat__n">{scripts.length}</span>
                </button>
                {categories.map(([c, n]) => (
                  <button
                    key={c}
                    type="button"
                    className={
                      "nse-cat" +
                      (category === c ? " nse-cat--active" : "") +
                      (RISKY.has(c) ? " nse-cat--risky" : "")
                    }
                    onClick={() => setCategory(category === c ? null : c)}
                  >
                    {c} <span className="nse-cat__n">{n}</span>
                  </button>
                ))}
              </div>
              {category !== null && (
                <label className="nse__whole">
                  <input
                    type="checkbox"
                    checked={selected.includes(category)}
                    onChange={() => toggle(category)}
                  />
                  Run the whole <strong>{category}</strong> category
                  <span className="mono muted">--script={category}</span>
                  <span className="muted">
                    — includes scripts added in later nmap versions
                  </span>
                </label>
              )}

              <ul className="nse__list">
                {visible.length === 0 && (
                  <li className="muted nse__empty">No scripts match.</li>
                )}
                {visible.map((s) => {
                  const isOpen = expanded === s.id;
                  return (
                    <li
                      key={s.id}
                      className={
                        "nse-item" +
                        (selected.includes(s.id) ? " nse-item--selected" : "")
                      }
                    >
                      <div className="nse-item__head">
                        <label className="nse-item__pick">
                          <input
                            type="checkbox"
                            checked={selected.includes(s.id)}
                            onChange={() => toggle(s.id)}
                          />
                          <span className="mono nse-item__id">{s.id}</span>
                        </label>
                        <span className="nse-item__tags">
                          {s.categories.map((c) => (
                            <span
                              key={c}
                              className={
                                "nse-tag" +
                                (RISKY.has(c) ? " nse-tag--risky" : "")
                              }
                            >
                              {c}
                            </span>
                          ))}
                        </span>
                        <button
                          type="button"
                          className="nse-item__more"
                          onClick={() => setExpanded(isOpen ? null : s.id)}
                          aria-expanded={isOpen}
                        >
                          {isOpen ? "less" : "more"}
                        </button>
                      </div>
                      {isOpen ? (
                        <p className="nse-item__desc nse-item__desc--full">
                          {s.description || "No description."}
                        </p>
                      ) : (
                        <p className="nse-item__desc">
                          {summary(s.description)}
                        </p>
                      )}
                    </li>
                  );
                })}
              </ul>
            </>
          )}

          <section className="opt-section">
            <button
              type="button"
              className="opt-section__head"
              onClick={() => setShowSettings((s) => !s)}
              aria-expanded={showSettings}
            >
              <Icon
                name={showSettings ? "chevronDown" : "chevronRight"}
                size={13}
                className="nse__caret"
              />
              Script settings
              <span className="nse__hint">
                default set (-sC), arguments, timeout, trace
              </span>
              <span className="opt-section__n">
                {nSet > 0 ? `${nSet} of ${SETTINGS.length}` : SETTINGS.length}
              </span>
            </button>
            {showSettings && (
              <ul className="nse__list opt-list">
                {SETTINGS.map((def) => (
                  <OptionRow
                    key={def.name}
                    def={def}
                    item={items.find((i) => i.name === def.name)}
                    onSet={(v) => onChange(setOption(items, def, v))}
                  />
                ))}
              </ul>
            )}
          </section>
        </div>
      )}
    </div>
  );
}
