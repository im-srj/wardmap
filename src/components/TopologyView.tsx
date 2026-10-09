import { useMemo, useRef, useState } from "react";
import type { Host, ScanResult } from "../types";

// SVG coordinate space; the <svg> scales responsively to its container.
const W = 860;
const H = 600;

/** Short node label: the last octet for IPv4 (hosts in one /24 share the
 *  rest), else the full address. Full address is shown in the tooltip. */
function shortLabel(addr: string): string {
  const m = addr.match(/^\d+\.\d+\.\d+\.(\d+)$/);
  return m ? m[1] : addr;
}

interface HostInfo {
  id: string;
  addr: string;
  hostname: string | null;
  subnet: string;
  openPorts: number;
  services: string[];
}

interface Pos {
  x: number;
  y: number;
}

/** Primary display address (IPv4 preferred). */
function hostAddr(h: Host): string {
  const v4 = h.addresses.find((a) => a.addrType === "ipv4");
  return (v4 ?? h.addresses[0])?.addr ?? "(unknown)";
}

/** /24 subnet for an IPv4 address, else a catch-all bucket. */
function subnetOf(addr: string): string {
  const m = addr.match(/^(\d+)\.(\d+)\.(\d+)\.\d+$/);
  return m ? `${m[1]}.${m[2]}.${m[3]}.0/24` : "non-IPv4";
}

function hostServices(h: Host): string[] {
  const names = h.ports
    .filter((p) => p.state === "open")
    .map((p) => p.service?.name)
    .filter((n): n is string => !!n);
  return [...new Set(names)];
}

/** A simple force-directed layout, run to a settled state synchronously.
 *  Node 0 is the scanner root (pinned at center); the rest are hosts. */
function computeLayout(count: number, iterations = 420): Pos[] {
  const cx = W / 2;
  const cy = H / 2;
  const hosts = Math.max(1, count - 1);
  // Ring radius scales with host count so nodes (and their labels) don't crowd.
  const restLen = Math.min(250, 120 + hosts * 6);
  // Deterministic initial ring so the layout is stable across renders.
  const pos: Pos[] = [];
  for (let i = 0; i < count; i++) {
    if (i === 0) {
      pos.push({ x: cx, y: cy });
    } else {
      const a = (2 * Math.PI * (i - 1)) / hosts - Math.PI / 2;
      pos.push({
        x: cx + Math.cos(a) * restLen,
        y: cy + Math.sin(a) * restLen,
      });
    }
  }
  const vel: Pos[] = pos.map(() => ({ x: 0, y: 0 }));

  const repulsion = 13000;
  const spring = 0.02;
  const gravity = 0.012;

  for (let it = 0; it < iterations; it++) {
    const cooling = 0.85 * (1 - it / iterations) + 0.1;

    // Pairwise repulsion.
    for (let i = 0; i < count; i++) {
      for (let j = i + 1; j < count; j++) {
        let dx = pos[i].x - pos[j].x;
        let dy = pos[i].y - pos[j].y;
        let d2 = dx * dx + dy * dy;
        if (d2 < 1) {
          dx = Math.random();
          dy = Math.random();
          d2 = 1;
        }
        const f = repulsion / d2;
        const d = Math.sqrt(d2);
        const fx = (dx / d) * f;
        const fy = (dy / d) * f;
        vel[i].x += fx;
        vel[i].y += fy;
        vel[j].x -= fx;
        vel[j].y -= fy;
      }
    }

    // Spring from root (0) to each host, plus center gravity.
    for (let i = 1; i < count; i++) {
      const dx = pos[i].x - pos[0].x;
      const dy = pos[i].y - pos[0].y;
      const d = Math.hypot(dx, dy) || 1;
      const f = spring * (d - restLen);
      vel[i].x -= (dx / d) * f * 60;
      vel[i].y -= (dy / d) * f * 60;
      vel[i].x += (cx - pos[i].x) * gravity;
      vel[i].y += (cy - pos[i].y) * gravity;
    }

    // Integrate (root stays pinned at center).
    for (let i = 1; i < count; i++) {
      pos[i].x += vel[i].x * cooling * 0.02;
      pos[i].y += vel[i].y * cooling * 0.02;
      vel[i].x *= 0.85;
      vel[i].y *= 0.85;
      pos[i].x = Math.max(28, Math.min(W - 28, pos[i].x));
      pos[i].y = Math.max(28, Math.min(H - 28, pos[i].y));
    }
  }
  return pos;
}

export function TopologyView({ result }: { result: ScanResult }) {
  const allHosts: HostInfo[] = useMemo(
    () =>
      result.hosts
        .filter((h) => h.state === "up")
        .map((h) => {
          const addr = hostAddr(h);
          return {
            id: addr,
            addr,
            hostname: h.hostnames[0] ?? null,
            subnet: subnetOf(addr),
            openPorts: h.ports.filter((p) => p.state === "open").length,
            services: hostServices(h),
          };
        }),
    [result],
  );

  const subnets = useMemo(
    () => [...new Set(allHosts.map((h) => h.subnet))].sort(),
    [allHosts],
  );
  const services = useMemo(
    () => [...new Set(allHosts.flatMap((h) => h.services))].sort(),
    [allHosts],
  );

  const [hiddenSubnets, setHiddenSubnets] = useState<Set<string>>(new Set());
  const [serviceFilter, setServiceFilter] = useState("");
  const [hovered, setHovered] = useState<HostInfo | null>(null);

  const visibleHosts = useMemo(
    () =>
      allHosts.filter(
        (h) =>
          !hiddenSubnets.has(h.subnet) &&
          (serviceFilter === "" || h.services.includes(serviceFilter)),
      ),
    [allHosts, hiddenSubnets, serviceFilter],
  );

  // Settled layout for the current visible set (root + hosts). Drag edits live.
  const baseLayout = useMemo(
    () => computeLayout(visibleHosts.length + 1),
    [visibleHosts.length],
  );
  const [positions, setPositions] = useState<Pos[]>(baseLayout);
  // Re-sync when the base layout changes (filter changed the node count).
  const lastKey = useRef("");
  const key = visibleHosts.map((h) => h.id).join(",");
  if (key !== lastKey.current) {
    lastKey.current = key;
    if (positions !== baseLayout) setPositions(baseLayout);
  }

  const dragRef = useRef<{ index: number } | null>(null);

  function toScreen(e: React.PointerEvent<SVGSVGElement>): Pos {
    const svg = e.currentTarget;
    const rect = svg.getBoundingClientRect();
    return {
      x: ((e.clientX - rect.left) / rect.width) * W,
      y: ((e.clientY - rect.top) / rect.height) * H,
    };
  }

  function onPointerMove(e: React.PointerEvent<SVGSVGElement>) {
    if (!dragRef.current) return;
    const p = toScreen(e);
    const i = dragRef.current.index;
    setPositions((prev) => {
      const next = prev.slice();
      next[i] = { x: p.x, y: p.y };
      return next;
    });
  }

  /** One of the theme's six categorical colors (--viz-1..6 in App.css). */
  function subnetColor(subnet: string): string {
    const idx = Math.max(0, subnets.indexOf(subnet));
    return `var(--viz-${(idx % 6) + 1})`;
  }

  function toggleSubnet(s: string) {
    setHiddenSubnets((prev) => {
      const next = new Set(prev);
      if (next.has(s)) next.delete(s);
      else next.add(s);
      return next;
    });
  }

  if (allHosts.length === 0) {
    return <p className="placeholder">No hosts were up in this scan.</p>;
  }

  const rootPos = positions[0] ?? { x: W / 2, y: H / 2 };

  return (
    <div className="topo">
      <div className="topo__controls">
        {subnets.length > 0 && (
          <div className="topo__filter">
            <span className="topo__filter-label">Subnets</span>
            {subnets.map((s) => (
              <button
                key={s}
                type="button"
                className={
                  "topo-chip" + (hiddenSubnets.has(s) ? " topo-chip--off" : "")
                }
                onClick={() => toggleSubnet(s)}
                style={{ borderColor: subnetColor(s) }}
              >
                <span
                  className="topo-chip__dot"
                  style={{ background: subnetColor(s) }}
                />
                {s}
              </button>
            ))}
          </div>
        )}
        {services.length > 0 && (
          <label className="topo__filter">
            <span className="topo__filter-label">Service</span>
            <select
              className="select topo__service"
              value={serviceFilter}
              onChange={(e) => setServiceFilter(e.target.value)}
            >
              <option value="">all</option>
              {services.map((s) => (
                <option key={s} value={s}>
                  {s}
                </option>
              ))}
            </select>
          </label>
        )}
      </div>

      <div className="topo__canvas">
        <svg
          viewBox={`0 0 ${W} ${H}`}
          className="topo__svg"
          onPointerMove={onPointerMove}
          onPointerUp={() => (dragRef.current = null)}
          onPointerLeave={() => (dragRef.current = null)}
        >
          {/* edges: root → each host */}
          {visibleHosts.map((h, i) => {
            const p = positions[i + 1];
            if (!p) return null;
            return (
              <line
                key={`e-${h.id}`}
                x1={rootPos.x}
                y1={rootPos.y}
                x2={p.x}
                y2={p.y}
                className="topo__edge"
              />
            );
          })}

          {/* root (scanner) node */}
          <g>
            <circle
              cx={rootPos.x}
              cy={rootPos.y}
              r={16}
              className="topo__root"
            />
            <text x={rootPos.x} y={rootPos.y + 30} className="topo__root-label">
              scan
            </text>
          </g>

          {/* host nodes */}
          {visibleHosts.map((h, i) => {
            const p = positions[i + 1];
            if (!p) return null;
            const r = 9 + Math.min(10, h.openPorts);
            // Place the label radially outward from the root so labels fan out
            // around the ring instead of stacking on top of each other.
            const ang = Math.atan2(p.y - rootPos.y, p.x - rootPos.x);
            const lx = p.x + Math.cos(ang) * (r + 11);
            const ly = p.y + Math.sin(ang) * (r + 11);
            const anchor =
              Math.cos(ang) > 0.25
                ? "start"
                : Math.cos(ang) < -0.25
                  ? "end"
                  : "middle";
            return (
              <g
                key={h.id}
                className="topo__node"
                onPointerDown={(e) => {
                  dragRef.current = { index: i + 1 };
                  e.currentTarget.setPointerCapture?.(e.pointerId);
                }}
                onPointerEnter={() => setHovered(h)}
                onPointerLeave={() =>
                  setHovered((cur) => (cur === h ? null : cur))
                }
              >
                <circle
                  cx={p.x}
                  cy={p.y}
                  r={r}
                  style={{ fill: subnetColor(h.subnet) }}
                  className="topo__host"
                />
                <text
                  x={lx}
                  y={ly}
                  textAnchor={anchor}
                  dominantBaseline="middle"
                  className="topo__host-label"
                >
                  {shortLabel(h.addr)}
                </text>
              </g>
            );
          })}
        </svg>

        {hovered && (
          <div className="topo__tooltip">
            <div className="topo__tooltip-addr mono">{hovered.addr}</div>
            {hovered.hostname && (
              <div className="topo__tooltip-host">{hovered.hostname}</div>
            )}
            <div className="topo__tooltip-meta">
              {hovered.subnet} · {hovered.openPorts} open
            </div>
            {hovered.services.length > 0 && (
              <div className="topo__tooltip-svc">
                {hovered.services.slice(0, 6).join(", ")}
                {hovered.services.length > 6 ? "…" : ""}
              </div>
            )}
          </div>
        )}
      </div>

      <p className="topo__hint">
        {visibleHosts.length} host(s) shown. Drag nodes to rearrange; hover for
        detail.
      </p>
    </div>
  );
}
