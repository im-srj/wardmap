// Hand-rolled stroke icons (24×24 grid, Lucide-style geometry) so the app
// carries no icon-library dependency. Add a path here when you need a new one.
const PATHS = {
  play: <path d="M7 4.5v15l12-7.5z" />,
  plus: <path d="M12 5v14M5 12h14" />,
  search: (
    <>
      <circle cx="11" cy="11" r="7" />
      <path d="m20 20-3.5-3.5" />
    </>
  ),
  target: (
    <>
      <circle cx="12" cy="12" r="9" />
      <circle cx="12" cy="12" r="5" />
      <circle cx="12" cy="12" r="1" />
    </>
  ),
  history: (
    <>
      <path d="M3 12a9 9 0 1 0 3-6.7L3 8" />
      <path d="M3 3v5h5M12 7v5l3 2" />
    </>
  ),
  palette: (
    <>
      <path d="M12 3a9 9 0 1 0 0 18c1.1 0 2-.9 2-2 0-.5-.2-1-.5-1.3-.3-.4-.5-.8-.5-1.2 0-1.1.9-2 2-2h2.3A4.7 4.7 0 0 0 21 9.8C21 6 17 3 12 3z" />
      <circle cx="7.5" cy="11" r="1" />
      <circle cx="10" cy="7" r="1" />
      <circle cx="15" cy="7" r="1" />
    </>
  ),
  table: (
    <>
      <rect x="3" y="4" width="18" height="16" rx="2" />
      <path d="M3 10h18M3 15h18M9 10v10" />
    </>
  ),
  graph: (
    <>
      <circle cx="12" cy="12" r="2.5" />
      <circle cx="5" cy="5" r="2" />
      <circle cx="19" cy="5" r="2" />
      <circle cx="5" cy="19" r="2" />
      <circle cx="19" cy="19" r="2" />
      <path d="m6.5 6.5 3.7 3.7M17.5 6.5l-3.7 3.7M6.5 17.5l3.7-3.7M17.5 17.5l-3.7-3.7" />
    </>
  ),
  compare: (
    <>
      <path d="M7 4v13M7 17l-3-3M7 17l3-3" />
      <path d="M17 20V7M17 7l-3 3M17 7l3 3" />
    </>
  ),
  copy: (
    <>
      <rect x="9" y="9" width="11" height="11" rx="2" />
      <path d="M5 15V6a2 2 0 0 1 2-2h8" />
    </>
  ),
  check: <path d="m5 12.5 4.5 4.5L19 7.5" />,
  x: <path d="M6 6l12 12M18 6 6 18" />,
  alert: (
    <>
      <path d="M12 3.5 2.5 20h19z" />
      <path d="M12 10v4.5M12 17.5v.01" />
    </>
  ),
  shield: (
    <>
      <path d="M12 3 4.5 6v6c0 4.5 3.2 7.8 7.5 9 4.3-1.2 7.5-4.5 7.5-9V6z" />
      <path d="m9 12 2 2 4-4" />
    </>
  ),
  zap: <path d="M13 2.5 4.5 13.5H12l-1 8 8.5-11H12z" />,
  layers: (
    <>
      <path d="m12 3 9 5-9 5-9-5z" />
      <path d="m3 13 9 5 9-5" />
    </>
  ),
  fingerprint: (
    <>
      <path d="M6.5 18.5c1-1.8 1.5-3.9 1.5-6.5a4 4 0 0 1 8 0c0 1 0 2-.2 3" />
      <path d="M12 12c0 3.5-.7 6.4-2.2 8.6" />
      <path d="M4 15c.3-1 .5-2 .5-3a7.5 7.5 0 0 1 13.4-4.6" />
      <path d="M19.8 11c.1.6.2 1.3.2 2 0 1.6-.2 3.1-.6 4.5" />
      <path d="M15.5 17.5c-.3 1.2-.8 2.3-1.4 3.3" />
    </>
  ),
  code: <path d="m8 7-5 5 5 5M16 7l5 5-5 5" />,
  chevronRight: <path d="m9 6 6 6-6 6" />,
  chevronDown: <path d="m6 9 6 6 6-6" />,
  server: (
    <>
      <rect x="3" y="4" width="18" height="7" rx="2" />
      <rect x="3" y="13" width="18" height="7" rx="2" />
      <path d="M7 7.5h.01M7 16.5h.01" />
    </>
  ),
  door: (
    <>
      <path d="M5 21V4a1 1 0 0 1 1-1h12a1 1 0 0 1 1 1v17" />
      <path d="M3 21h18M14.5 12h.01" />
    </>
  ),
  clock: (
    <>
      <circle cx="12" cy="12" r="9" />
      <path d="M12 7v5l3 2" />
    </>
  ),
  list: <path d="M8 6h13M8 12h13M8 18h13M3.5 6h.01M3.5 12h.01M3.5 18h.01" />,
  arrowRight: <path d="M5 12h14M13 6l6 6-6 6" />,
} as const;

export type IconName = keyof typeof PATHS;

interface Props {
  name: IconName;
  size?: number;
  className?: string;
}

export function Icon({ name, size = 16, className }: Props) {
  return (
    <svg
      className={"icon" + (className ? ` ${className}` : "")}
      width={size}
      height={size}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth={1.8}
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
    >
      {PATHS[name]}
    </svg>
  );
}

/** The app mark: the icon's hexagon of hosts around a central scanner node. */
export function BrandMark({ size = 28 }: { size?: number }) {
  const pts = [
    [16, 5],
    [25.5, 10.5],
    [25.5, 21.5],
    [16, 27],
    [6.5, 21.5],
    [6.5, 10.5],
  ];
  return (
    <svg
      className="brand-mark"
      width={size}
      height={size}
      viewBox="0 0 32 32"
      aria-hidden="true"
    >
      <rect width="32" height="32" rx="8" className="brand-mark__bg" />
      <g className="brand-mark__edges">
        {pts.map(([x, y], i) => {
          const [nx, ny] = pts[(i + 1) % pts.length];
          return (
            <g key={i}>
              <line x1={x} y1={y} x2={nx} y2={ny} />
              <line x1={16} y1={16} x2={x} y2={y} />
            </g>
          );
        })}
      </g>
      {pts.map(([x, y], i) => (
        <circle key={i} cx={x} cy={y} r={2.3} className="brand-mark__node" />
      ))}
      <circle cx={16} cy={16} r={3.6} className="brand-mark__core" />
    </svg>
  );
}
