import { useMemo, useState } from "react";
import type { Host, ScanResult } from "../types";

interface Row {
  host: string;
  hostname: string | null;
  portid: number;
  protocol: string;
  state: string;
  service: string;
}

type SortKey = keyof Row;
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

function serviceLabel(
  svc: { name: string | null; product: string | null; version: string | null } | null,
): string {
  if (!svc) return "";
  return [svc.name, svc.product, svc.version].filter(Boolean).join(" ");
}

function toRows(result: ScanResult): Row[] {
  const rows: Row[] = [];
  for (const h of result.hosts) {
    const host = hostLabel(h);
    const hostname = h.hostnames[0] ?? null;
    for (const p of h.ports) {
      rows.push({
        host,
        hostname,
        portid: p.portid,
        protocol: p.protocol,
        state: p.state,
        service: serviceLabel(p.service),
      });
    }
  }
  return rows;
}

export function ResultsTable({ result }: { result: ScanResult }) {
  const [sortKey, setSortKey] = useState<SortKey>("portid");
  const [dir, setDir] = useState<Dir>("asc");

  const rows = useMemo(() => toRows(result), [result]);

  const sorted = useMemo(() => {
    const col = COLUMNS.find((c) => c.key === sortKey);
    const copy = [...rows];
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
  }, [rows, sortKey, dir]);

  function toggleSort(key: SortKey) {
    if (key === sortKey) {
      setDir((d) => (d === "asc" ? "desc" : "asc"));
    } else {
      setSortKey(key);
      setDir("asc");
    }
  }

  const openCount = rows.filter((r) => r.state === "open").length;
  const s = result.summary;

  if (rows.length === 0) {
    return (
      <div className="results">
        <div className="results__summary">
          No ports reported.
          {s ? ` ${s.hostsUp} host(s) up, ${s.hostsDown} down.` : ""}
        </div>
      </div>
    );
  }

  return (
    <div className="results">
      <div className="results__summary">
        <strong>{openCount}</strong> open · {rows.length} total port(s)
        {s ? (
          <>
            {" · "}
            <strong>{s.hostsUp}</strong> host(s) up
            {s.hostsDown > 0 ? `, ${s.hostsDown} down` : ""}
            {s.elapsedSecs != null ? ` · ${s.elapsedSecs.toFixed(2)}s` : ""}
          </>
        ) : null}
      </div>

      <table className="results__table">
        <thead>
          <tr>
            {COLUMNS.map((c) => (
              <th
                key={c.key}
                onClick={() => toggleSort(c.key)}
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
                {c.label}
                <span className="th-sort__caret">
                  {c.key === sortKey ? (dir === "asc" ? " ▲" : " ▼") : ""}
                </span>
              </th>
            ))}
          </tr>
        </thead>
        <tbody>
          {sorted.map((r, i) => (
            <tr key={`${r.host}-${r.protocol}-${r.portid}-${i}`}>
              <td className="mono">{r.host}</td>
              <td className="muted">{r.hostname ?? "—"}</td>
              <td className="mono">{r.portid}</td>
              <td className="muted">{r.protocol}</td>
              <td>
                <span className={`state state--${r.state}`}>{r.state}</span>
              </td>
              <td>{r.service || <span className="muted">—</span>}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}
