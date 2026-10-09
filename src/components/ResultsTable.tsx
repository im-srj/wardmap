import { Fragment, useMemo, useState } from "react";
import type { Host, ScanResult, ScriptOutput, Service } from "../types";
import { Icon } from "./Icon";

interface Row {
  host: string;
  hostname: string | null;
  portid: number;
  protocol: string;
  state: string;
  service: string;
  svc: Service | null;
  scripts: ScriptOutput[];
}

type SortKey = Exclude<keyof Row, "scripts" | "svc">;
type Dir = "asc" | "desc";

const COLUMNS: { key: SortKey; label: string; numeric?: boolean }[] = [
  { key: "host", label: "Host" },
  { key: "hostname", label: "Hostname" },
  { key: "portid", label: "Port", numeric: true },
  { key: "protocol", label: "Proto" },
  { key: "state", label: "State" },
  { key: "service", label: "Service" },
];

/** Prefer the IPv4 address for display, else the first address. */
function hostLabel(h: Host): string {
  const v4 = h.addresses.find((a) => a.addrType === "ipv4");
  return (v4 ?? h.addresses[0])?.addr ?? "(unknown)";
}

function serviceLabel(svc: Service | null): string {
  if (!svc) return "";
  return [svc.name, svc.product, svc.version].filter(Boolean).join(" ");
}

function toRows(result: ScanResult): Row[] {
  const rows: Row[] = [];
  for (const h of result.hosts) {
    const host = hostLabel(h);
    const hostname = h.hostnames[0] ?? h.identity?.mdnsName ?? null;
    for (const p of h.ports) {
      rows.push({
        host,
        hostname,
        portid: p.portid,
        protocol: p.protocol,
        state: p.state,
        service: serviceLabel(p.service),
        svc: p.service,
        scripts: p.scripts,
      });
    }
  }
  return rows;
}

/** Headline numbers for a scan, shown above both the table and the map. */
export function ResultStats({ result }: { result: ScanResult }) {
  const s = result.summary;
  const ports = result.hosts.flatMap((h) => h.ports);
  const open = ports.filter((p) => p.state === "open").length;
  const stats = [
    {
      icon: "server" as const,
      value: s?.hostsUp ?? "—",
      label: "hosts up",
      sub: s && s.hostsDown > 0 ? `${s.hostsDown} down` : null,
      tone: "accent",
    },
    {
      icon: "door" as const,
      value: open,
      label: "open ports",
      sub: null,
      tone: "ok",
    },
    {
      icon: "list" as const,
      value: ports.length,
      label: "ports reported",
      sub: null,
      tone: "neutral",
    },
    {
      icon: "clock" as const,
      value: s?.elapsedSecs != null ? `${s.elapsedSecs.toFixed(2)}s` : "—",
      label: "duration",
      sub: null,
      tone: "neutral",
    },
  ];
  return (
    <div className="stats">
      {stats.map((st) => (
        <div key={st.label} className={`stat stat--${st.tone}`}>
          <span className="stat__icon">
            <Icon name={st.icon} size={16} />
          </span>
          <span className="stat__value">{st.value}</span>
          <span className="stat__label">
            {st.label}
            {st.sub && <span className="stat__sub"> · {st.sub}</span>}
          </span>
        </div>
      ))}
    </div>
  );
}

export function ResultsTable({ result }: { result: ScanResult }) {
  const [sortKey, setSortKey] = useState<SortKey>("portid");
  const [dir, setDir] = useState<Dir>("asc");
  const [openRow, setOpenRow] = useState<string | null>(null);
  const [filter, setFilter] = useState("");

  const rows = useMemo(() => toRows(result), [result]);

  const sorted = useMemo(() => {
    const col = COLUMNS.find((c) => c.key === sortKey);
    const q = filter.trim().toLowerCase();
    const copy = q
      ? rows.filter((r) =>
          [
            r.host,
            r.hostname ?? "",
            String(r.portid),
            r.protocol,
            r.state,
            r.service,
          ].some((v) => v.toLowerCase().includes(q)),
        )
      : [...rows];
    copy.sort((a, b) => {
      let cmp: number;
      if (col?.numeric) {
        cmp = (a[sortKey] as number) - (b[sortKey] as number);
      } else {
        cmp = String(a[sortKey] ?? "").localeCompare(String(b[sortKey] ?? ""));
      }
      return dir === "asc" ? cmp : -cmp;
    });
    return copy;
  }, [rows, sortKey, dir, filter]);

  function toggleSort(key: SortKey) {
    if (key === sortKey) {
      setDir((d) => (d === "asc" ? "desc" : "asc"));
    } else {
      setSortKey(key);
      setDir("asc");
    }
  }

  const hostScripts = result.hosts.filter((h) => h.scripts.length > 0);

  if (rows.length === 0) {
    return (
      <div className="card empty empty--compact">
        <span className="empty__icon">
          <Icon name="door" size={22} />
        </span>
        <div className="empty__title">No ports reported</div>
        <p className="empty__text">
          nmap found no open, closed or filtered ports worth listing for this
          target with the selected profile.
        </p>
      </div>
    );
  }

  return (
    <div className="results">
      <div className="card table-card">
        <div className="table-card__bar">
          <label className="inline-search">
            <Icon name="search" size={14} />
            <input
              type="search"
              placeholder="Filter by host, port, state or service"
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              spellCheck={false}
              aria-label="Filter results"
            />
          </label>
          <span className="table-card__count">
            {sorted.length === rows.length
              ? `${rows.length} row${rows.length === 1 ? "" : "s"}`
              : `${sorted.length} of ${rows.length}`}
          </span>
        </div>
        <div className="table-scroll">
          <table className="results__table">
            <thead>
              <tr>
                {COLUMNS.map((c) => (
                  <th
                    key={c.key}
                    className={
                      "th-sort" + (c.key === sortKey ? ` th-sort--${dir}` : "")
                    }
                    aria-sort={
                      c.key === sortKey
                        ? dir === "asc"
                          ? "ascending"
                          : "descending"
                        : "none"
                    }
                  >
                    <button type="button" onClick={() => toggleSort(c.key)}>
                      {c.label}
                      <span className="th-sort__caret" aria-hidden="true">
                        {c.key === sortKey ? (dir === "asc" ? "▲" : "▼") : ""}
                      </span>
                    </button>
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {sorted.length === 0 && (
                <tr>
                  <td colSpan={COLUMNS.length} className="results__none">
                    No rows match “{filter}”.
                  </td>
                </tr>
              )}
              {sorted.map((r) => {
                const key = `${r.host}-${r.protocol}-${r.portid}`;
                const isOpen = openRow === key;
                const detail = [r.svc?.product, r.svc?.version]
                  .filter(Boolean)
                  .join(" ");
                return (
                  <Fragment key={key}>
                    <tr className={isOpen ? "row--expanded" : undefined}>
                      <td className="mono">{r.host}</td>
                      <td className="muted">{r.hostname ?? "—"}</td>
                      <td className="mono results__port">{r.portid}</td>
                      <td className="muted mono">{r.protocol}</td>
                      <td>
                        <span
                          className={`state state--${r.state.split("|")[0]}`}
                        >
                          {r.state}
                        </span>
                      </td>
                      <td>
                        <span className="svc">
                          {r.svc?.name ? (
                            <span className="svc__name">{r.svc.name}</span>
                          ) : (
                            <span className="muted">—</span>
                          )}
                          {detail && (
                            <span className="svc__detail">{detail}</span>
                          )}
                          {r.scripts.length > 0 && (
                            <button
                              type="button"
                              className={
                                "script-toggle" +
                                (isOpen ? " script-toggle--open" : "")
                              }
                              onClick={() => setOpenRow(isOpen ? null : key)}
                              aria-expanded={isOpen}
                            >
                              <Icon
                                name={isOpen ? "chevronDown" : "chevronRight"}
                                size={12}
                              />
                              {r.scripts.length} script
                              {r.scripts.length === 1 ? "" : "s"}
                            </button>
                          )}
                        </span>
                      </td>
                    </tr>
                    {isOpen && (
                      <tr className="script-row">
                        <td colSpan={COLUMNS.length}>
                          <ScriptOutputs scripts={r.scripts} />
                        </td>
                      </tr>
                    )}
                  </Fragment>
                );
              })}
            </tbody>
          </table>
        </div>
      </div>

      {hostScripts.map((h) => (
        <div key={hostLabel(h)} className="card host-scripts">
          <div className="host-scripts__title">
            <Icon name="code" size={14} />
            Host scripts · <span className="mono">{hostLabel(h)}</span>
          </div>
          <ScriptOutputs scripts={h.scripts} />
        </div>
      ))}
    </div>
  );
}

function ScriptOutputs({ scripts }: { scripts: ScriptOutput[] }) {
  return (
    <div className="script-outputs">
      {scripts.map((sc, i) => (
        <div key={`${sc.id}-${i}`} className="script-output">
          <div className="script-output__id mono">{sc.id}</div>
          <pre className="script-output__text">{sc.output.trim()}</pre>
        </div>
      ))}
    </div>
  );
}
