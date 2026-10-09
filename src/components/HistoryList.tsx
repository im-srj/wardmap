import type { StoredScan } from "../types";

interface Props {
  scans: StoredScan[];
  selectedId: number | null;
  onSelect: (scan: StoredScan) => void;
}

function formatTime(epochSecs: number): string {
  return new Date(epochSecs * 1000).toLocaleString();
}

export function HistoryList({ scans, selectedId, onSelect }: Props) {
  if (scans.length === 0) {
    return <p className="history__empty">No saved scans yet.</p>;
  }

  return (
    <ul className="history__list">
      {scans.map((s) => (
        <li key={s.id}>
          <button
            type="button"
            className={
              "history__item" +
              (s.id === selectedId ? " history__item--active" : "")
            }
            onClick={() => onSelect(s)}
          >
            <span className="history__target">{s.target}</span>
            <span className="history__meta">
              {s.openPorts} open · {formatTime(s.createdAt)}
            </span>
          </button>
        </li>
      ))}
    </ul>
  );
}
