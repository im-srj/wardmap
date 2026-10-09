import { useState } from "react";
import type { StoredScan } from "../types";
import { Icon } from "./Icon";

interface Props {
  history: StoredScan[];
  onCompare: (oldScan: StoredScan, newScan: StoredScan) => void;
}

function label(s: StoredScan): string {
  const time = new Date(s.createdAt * 1000).toLocaleString();
  return `${s.target} · ${time} (${s.openPorts} open)`;
}

/** Pick two saved scans to diff. Defaults to the two most recent. */
export function CompareBar({ history, onCompare }: Props) {
  const [oldId, setOldId] = useState<number | null>(null);
  const [newId, setNewId] = useState<number | null>(null);

  // Need at least two scans to compare.
  if (history.length < 2) return null;

  const effOld = oldId ?? history[1].id; // second newest
  const effNew = newId ?? history[0].id; // newest

  function run() {
    const o = history.find((s) => s.id === effOld);
    const n = history.find((s) => s.id === effNew);
    if (o && n) onCompare(o, n);
  }

  return (
    <div className="card compare-bar">
      <span className="compare-bar__label">
        <Icon name="compare" size={15} />
        Compare
      </span>
      <select
        className="select compare-bar__select"
        value={effOld}
        onChange={(e) => setOldId(Number(e.target.value))}
        aria-label="Baseline (older) scan"
      >
        {history.map((s) => (
          <option key={s.id} value={s.id}>
            {label(s)}
          </option>
        ))}
      </select>
      <Icon name="arrowRight" size={15} className="compare-bar__arrow" />
      <select
        className="select compare-bar__select"
        value={effNew}
        onChange={(e) => setNewId(Number(e.target.value))}
        aria-label="Newer scan"
      >
        {history.map((s) => (
          <option key={s.id} value={s.id}>
            {label(s)}
          </option>
        ))}
      </select>
      <button
        type="button"
        className="btn btn--secondary"
        onClick={run}
        disabled={effOld === effNew}
        title={effOld === effNew ? "Pick two different scans" : undefined}
      >
        Show diff
      </button>
    </div>
  );
}
