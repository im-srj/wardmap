import { useMemo, useState } from "react";
import type { StoredScan } from "../types";
import { Icon } from "./Icon";

interface Props {
  scans: StoredScan[];
  selectedId: number | null;
  onSelect: (scan: StoredScan) => void;
}

/** "just now", "5m ago", "3h ago", "2d ago", then a short date. */
export function relativeTime(epochSecs: number): string {
  const secs = Math.max(0, Date.now() / 1000 - epochSecs);
  if (secs < 45) return "just now";
  if (secs < 3600) return `${Math.round(secs / 60)}m ago`;
  if (secs < 86400) return `${Math.round(secs / 3600)}h ago`;
  if (secs < 7 * 86400) return `${Math.round(secs / 86400)}d ago`;
  return new Date(epochSecs * 1000).toLocaleDateString();
}

export function HistoryList({ scans, selectedId, onSelect }: Props) {
  const [query, setQuery] = useState("");

  const visible = useMemo(() => {
    const q = query.trim().toLowerCase();
    if (!q) return scans;
    return scans.filter(
      (s) =>
        s.target.toLowerCase().includes(q) || s.args.toLowerCase().includes(q),
    );
  }, [scans, query]);

  if (scans.length === 0) {
    return (
      <div className="history__empty">
        <Icon name="history" size={20} />
        <span>No saved scans yet.</span>
        <span className="history__empty-hint">
          Every scan you run is stored here.
        </span>
      </div>
    );
  }

  return (
    <>
      <label className="history__search">
        <Icon name="search" size={14} />
        <input
          type="search"
          placeholder="Filter history"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          spellCheck={false}
          aria-label="Filter scan history"
        />
      </label>
      <ul className="history__list">
        {visible.length === 0 && <li className="history__none">No matches.</li>}
        {visible.map((s) => (
          <li key={s.id}>
            <button
              type="button"
              className={
                "history__item" +
                (s.id === selectedId ? " history__item--active" : "")
              }
              onClick={() => onSelect(s)}
              title={new Date(s.createdAt * 1000).toLocaleString()}
            >
              <span className="history__row">
                <span
                  className={
                    "history__dot" + (s.hostsUp > 0 ? " history__dot--up" : "")
                  }
                />
                <span className="history__target">{s.target}</span>
                <span className="history__time">
                  {relativeTime(s.createdAt)}
                </span>
              </span>
              <span className="history__meta">
                <span className="history__open">{s.openPorts} open</span>
                <span>
                  {s.hostsUp} host{s.hostsUp === 1 ? "" : "s"}
                </span>
                {s.elapsedSecs != null && (
                  <span>{s.elapsedSecs.toFixed(1)}s</span>
                )}
              </span>
            </button>
          </li>
        ))}
      </ul>
    </>
  );
}
