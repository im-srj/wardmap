import type { ScanDiff } from "../types";
import { Icon } from "./Icon";

interface Props {
  diff: ScanDiff;
  oldLabel: string;
  newLabel: string;
  onClose: () => void;
}

function sign(kind: string): string {
  if (kind === "opened" || kind === "cert-new") return "+";
  if (kind === "closed") return "−";
  return "~"; // service-changed, cert-changed
}

const KIND_LABEL: Record<string, string> = {
  opened: "opened",
  closed: "closed",
  "service-changed": "service changed",
  "cert-changed": "cert changed",
  "cert-new": "new cert",
};

export function DiffView({ diff, oldLabel, newLabel, onClose }: Props) {
  const ports = diff.hosts.flatMap((h) => h.ports);
  const count = (pred: (k: string) => boolean) =>
    ports.filter((p) => pred(p.kind)).length;
  const stats = [
    { n: count((k) => k === "opened"), label: "ports opened", tone: "ok" },
    { n: count((k) => k === "closed"), label: "ports closed", tone: "bad" },
    {
      n: count((k) => k !== "opened" && k !== "closed"),
      label: "services / certs changed",
      tone: "warn",
    },
    {
      n: diff.hosts.filter((h) => h.status !== "changed").length,
      label: "hosts added / removed",
      tone: "accent",
    },
  ];

  return (
    <div className="diff">
      <div className="card diff__header">
        <div className="diff__labels">
          <span className="diff__side">
            <span className="section-label">Baseline</span>
            <span className="diff__scan">{oldLabel}</span>
          </span>
          <Icon name="arrowRight" size={18} className="diff__arrow" />
          <span className="diff__side">
            <span className="section-label">Compared</span>
            <span className="diff__scan">{newLabel}</span>
          </span>
        </div>
        <button type="button" className="btn btn--secondary" onClick={onClose}>
          <Icon name="x" size={14} />
          Close diff
        </button>
      </div>

      {diff.unchanged ? (
        <div className="card empty empty--compact">
          <span className="empty__icon empty__icon--ok">
            <Icon name="check" size={22} />
          </span>
          <div className="empty__title">No changes</div>
          <p className="empty__text">
            These two scans report identical hosts, ports and services.
          </p>
        </div>
      ) : (
        <>
          <div className="stats">
            {stats.map((s) => (
              <div key={s.label} className={`stat stat--bar stat--${s.tone}`}>
                <span className="stat__value">{s.n}</span>
                <span className="stat__label">{s.label}</span>
              </div>
            ))}
          </div>

          <div className="diff__hosts">
            {diff.hosts.map((h) => (
              <div key={h.host} className="card diff-host">
                <div className="diff-host__head">
                  <Icon name="server" size={15} className="muted" />
                  <span className="mono diff-host__addr">{h.host}</span>
                  <span className={`badge badge--${h.status}`}>{h.status}</span>
                  {h.stateChange && (
                    <span className="diff-host__state">{h.stateChange}</span>
                  )}
                </div>
                {h.ports.length > 0 && (
                  <ul className="diff-ports">
                    {h.ports.map((p) => (
                      <li
                        key={`${p.protocol}-${p.portid}-${p.kind}`}
                        className={`diff-port diff-port--${p.kind}`}
                      >
                        <span className="diff-port__sign">{sign(p.kind)}</span>
                        <span className="mono diff-port__port">
                          {p.portid}/{p.protocol}
                        </span>
                        <span className="diff-port__kind">
                          {KIND_LABEL[p.kind] ?? p.kind}
                        </span>
                        <span className="diff-port__detail">{p.detail}</span>
                      </li>
                    ))}
                  </ul>
                )}
              </div>
            ))}
          </div>
        </>
      )}
    </div>
  );
}
