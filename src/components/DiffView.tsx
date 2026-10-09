import type { ScanDiff } from "../types";

interface Props {
  diff: ScanDiff;
  oldLabel: string;
  newLabel: string;
  onClose: () => void;
}

function sign(kind: string): string {
  if (kind === "opened") return "+";
  if (kind === "closed") return "−";
  return "~"; // service-changed
}

export function DiffView({ diff, oldLabel, newLabel, onClose }: Props) {
  return (
    <div className="diff">
      <div className="diff__header">
        <span className="diff__title">Diff</span>
        <span className="diff__labels">
          <span className="muted">{oldLabel}</span>
          <span className="diff__arrow"> → </span>
          <span className="muted">{newLabel}</span>
        </span>
        <button type="button" className="btn btn--ghost" onClick={onClose}>
          Close
        </button>
      </div>

      {diff.unchanged ? (
        <p className="placeholder">No changes between these two scans.</p>
      ) : (
        <div className="diff__hosts">
          {diff.hosts.map((h) => (
            <div key={h.host} className="diff-host">
              <div className="diff-host__head">
                <span className="mono">{h.host}</span>
                <span className={`diff-badge diff-badge--${h.status}`}>
                  {h.status}
                </span>
                {h.stateChange && (
                  <span className="diff-host__state">{h.stateChange}</span>
                )}
              </div>
              {h.ports.length > 0 && (
                <ul className="diff-ports">
                  {h.ports.map((p) => (
                    <li
                      key={`${p.protocol}-${p.portid}`}
                      className={`diff-port diff-port--${p.kind}`}
                    >
                      <span className="diff-port__sign">{sign(p.kind)}</span>
                      <span className="mono diff-port__port">
                        {p.portid}/{p.protocol}
                      </span>
                      <span className="diff-port__kind">{p.kind}</span>
                      <span className="diff-port__detail">{p.detail}</span>
                    </li>
                  ))}
                </ul>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
