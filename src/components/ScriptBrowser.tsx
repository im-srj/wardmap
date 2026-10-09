import { useMemo, useState } from "react";
import { listNseScripts } from "../api";
import type { NseScript } from "../types";

interface Props {
  selected: string[];
  onChange: (ids: string[]) => void;
}

/** Categories whose scripts can crash services, lock accounts, or trip IDS —
 *  selecting one shows a warning. */
const RISKY = new Set(["intrusive", "brute", "dos", "exploit"]);

/** First paragraph of an NSEDoc description, unwrapped to one line. */
function summary(description: string): string {
  return description.split(/\n\s*\n/)[0].replace(/\s+/g, " ");
}

/** Searchable, categorized picker over the installed nmap's NSE scripts.
 *  The catalogue is loaded from nmap the first time the panel is opened. */
export function ScriptBrowser({ selected, onChange }: Props) {
  const [open, setOpen] = useState(false);
  const [scripts, setScripts] = useState<NseScript[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [query, setQuery] = useState("");
  const [category, setCategory] = useState<string | null>(null);
  const [expanded, setExpanded] = useState<string | null>(null);

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
  const risky = selected.filter((id) =>
    byId.get(id)?.categories.some((c) => RISKY.has(c)),
  );

  function toggle(id: string) {
    onChange(
      selected.includes(id)
        ? selected.filter((s) => s !== id)
        : [...selected, id].sort(),
    );
  }

  return (
    <div className="nse">
      <div className="nse__bar">
        <button
          type="button"
          className={"nse__toggle" + (open ? " nse__toggle--open" : "")}
          onClick={toggleOpen}
          aria-expanded={open}
        >
          <span className="nse__caret">{open ? "▾" : "▸"}</span>
          {selected.length > 0 ? "NSE scripts" : "Add NSE scripts"}
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
              ×
            </button>
          </span>
        ))}
        {selected.length > 1 && (
          <button
            type="button"
            className="nse__clear"
            onClick={() => onChange([])}
          >
            clear
          </button>
        )}
      </div>

      {risky.length > 0 && (
        <div className="nse__warn" role="note">
          <strong>{risky.join(", ")}</strong>{" "}
          {risky.length === 1 ? "is" : "are"} intrusive (brute force, DoS or
          exploit): {risky.length === 1 ? "it" : "they"} can crash services,
          lock accounts or trigger alerts. Only run against targets you own or
          are authorized to test.
        </div>
      )}

      {open && (
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
              <input
                className="field__input nse__search"
                type="search"
                placeholder={`Search ${scripts.length} scripts by name or description…`}
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                spellCheck={false}
              />
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
                                "nse-tag" + (RISKY.has(c) ? " nse-tag--risky" : "")
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
        </div>
      )}
    </div>
  );
}
