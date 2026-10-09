import { useMemo, useState } from "react";
import type { ScanResult } from "../types";
import {
  CATEGORIES,
  CATEGORY_ORDER,
  addrSortKey,
  hostExposure,
  type Category,
  type HostExposure,
  type ServiceInfo,
} from "../exposure";
import type { DeviceKind } from "../device";
import { Icon, type IconName } from "./Icon";

const DEVICE_ICONS: Record<DeviceKind, IconName> = {
  self: "laptop",
  router: "router",
  printer: "printer",
  "domain-controller": "key",
  windows: "monitor",
  computer: "monitor",
  apple: "laptop",
  phone: "phone",
  tv: "tv",
  iot: "cpu",
  vm: "server",
  camera: "camera",
  database: "database",
  nas: "hardDrive",
  mail: "mail",
  web: "globe",
  server: "server",
  unknown: "help",
};

const MAX_PILLS = 6;

function pillClass(s: ServiceInfo): string {
  if (s.cleartext) return "svc-pill svc-pill--cleartext";
  if (s.review) return "svc-pill svc-pill--review";
  return "svc-pill";
}

/** "What does this network expose, and why does it matter?" — hosts grouped
 *  by subnet, services grouped by purpose, with plain-language notes. No edges
 *  are drawn: we can't see real routing paths without traceroute (root). */
export function ExposureMap({ result }: { result: ScanResult }) {
  const hosts = useMemo(
    () =>
      result.hosts
        .filter((h) => h.state === "up")
        .map(hostExposure)
        .sort((a, b) => addrSortKey(a.addr) - addrSortKey(b.addr)),
    [result],
  );

  const [attentionOnly, setAttentionOnly] = useState(false);
  const [category, setCategory] = useState<Category | null>(null);
  const [selectedAddr, setSelectedAddr] = useState<string | null>(null);

  const presentCategories = useMemo(() => {
    const set = new Set(
      hosts.flatMap((h) => h.services.map((s) => s.category)),
    );
    return CATEGORY_ORDER.filter((c) => set.has(c));
  }, [hosts]);

  const visible = hosts.filter(
    (h) =>
      (!attentionOnly || h.reviewCount + h.cleartextCount > 0) &&
      (category === null || h.services.some((s) => s.category === category)),
  );

  const groups = useMemo(() => {
    const m = new Map<string, HostExposure[]>();
    for (const h of visible) m.set(h.subnet, [...(m.get(h.subnet) ?? []), h]);
    return [...m.entries()];
  }, [visible]);

  // Default selection: the host with the most to review, else the first.
  const fallback =
    [...hosts].sort(
      (a, b) =>
        b.reviewCount + b.cleartextCount - (a.reviewCount + a.cleartextCount),
    )[0] ?? null;
  const selected = hosts.find((h) => h.addr === selectedAddr) ?? fallback;

  if (hosts.length === 0) {
    return (
      <div className="card empty empty--compact">
        <span className="empty__icon">
          <Icon name="server" size={22} />
        </span>
        <div className="empty__title">No hosts were up</div>
        <p className="empty__text">
          Nothing answered in this scan, so there's nothing to map.
        </p>
      </div>
    );
  }

  const all = hosts.flatMap((h) => h.services);
  const reviewTotal = all.filter((s) => s.review).length;
  const cleartextTotal = all.filter((s) => s.cleartext).length;
  const anyGuessed = all.some((s) => s.guessed);
  // With -sV/-A, "table" names mean nmap tried and failed to fingerprint —
  // so suggesting "run Service + version" would be wrong advice.
  const versionScan = /(^|\s)-(sV|A)(\s|$)/.test(result.args);

  return (
    <div className="xmap">
      <div className="card xmap__bar">
        <div className="xmap__totals">
          <span>
            <strong>{hosts.length}</strong> host{hosts.length === 1 ? "" : "s"}
          </span>
          <span>
            <strong>{all.length}</strong> open service
            {all.length === 1 ? "" : "s"}
          </span>
          <span className="xmap__total--review">
            <strong>{reviewTotal}</strong> worth reviewing
          </span>
          <span className="xmap__total--cleartext">
            <strong>{cleartextTotal}</strong> unencrypted
          </span>
        </div>
        <div className="xmap__filters">
          <button
            type="button"
            className={
              "chip-toggle" + (attentionOnly ? " chip-toggle--on" : "")
            }
            aria-pressed={attentionOnly}
            onClick={() => setAttentionOnly((v) => !v)}
          >
            <Icon name="alert" size={13} />
            Needs attention
          </button>
          {presentCategories.map((c) => (
            <button
              key={c}
              type="button"
              className={
                "chip-toggle" + (category === c ? " chip-toggle--on" : "")
              }
              aria-pressed={category === c}
              onClick={() => setCategory(category === c ? null : c)}
            >
              {CATEGORIES[c].label}
            </button>
          ))}
        </div>
      </div>

      {anyGuessed && (
        <div className="banner banner--muted">
          <Icon name="info" size={15} />
          <span>
            {versionScan ? (
              <>
                nmap couldn't fingerprint some services, so their names come
                from the port number alone — treat those as unconfirmed.
              </>
            ) : (
              <>
                Some service names were guessed from the port number alone. Run
                the <strong>Service + version</strong> profile to have nmap
                confirm what's actually listening.
              </>
            )}
          </span>
        </div>
      )}

      <div className="xmap__body">
        <div className="xmap__groups">
          {groups.length === 0 && (
            <div className="card empty empty--compact">
              <div className="empty__title">No hosts match these filters</div>
            </div>
          )}
          {groups.map(([subnet, members]) => (
            <section key={subnet} className="xgroup">
              <header className="xgroup__head">
                <span className="mono">{subnet}</span>
                <span className="count">{members.length}</span>
              </header>
              <div className="xgroup__grid">
                {members.map((h) => (
                  <HostCard
                    key={h.addr}
                    h={h}
                    selected={selected?.addr === h.addr}
                    onSelect={() => setSelectedAddr(h.addr)}
                  />
                ))}
              </div>
            </section>
          ))}
          <p className="xmap__note">
            <Icon name="info" size={14} />
            <span>
              Hosts are grouped by /24 subnet; no connecting lines are drawn
              because real routing paths need nmap's <code>--traceroute</code>,
              which requires root. Device types are guesses from names, MAC
              vendor and open services.
            </span>
          </p>
        </div>

        {selected && <HostDetail h={selected} versionScan={versionScan} />}
      </div>
    </div>
  );
}

function HostCard({
  h,
  selected,
  onSelect,
}: {
  h: HostExposure;
  selected: boolean;
  onSelect: () => void;
}) {
  const attention = h.reviewCount + h.cleartextCount;
  const shown = h.services.slice(0, MAX_PILLS);
  return (
    <button
      type="button"
      className={"xhost" + (selected ? " xhost--selected" : "")}
      onClick={onSelect}
      aria-pressed={selected}
    >
      <span className="xhost__head">
        <span className={`xhost__icon xhost__icon--${h.device.kind}`}>
          <Icon name={DEVICE_ICONS[h.device.kind]} size={18} />
        </span>
        <span className="xhost__titles">
          <span className="xhost__name">{h.name ?? h.addr}</span>
          {h.name && <span className="xhost__addr mono">{h.addr}</span>}
          <span className="xhost__sub">
            {h.device.label}
            {h.device.role && ` · ${h.device.role}`}
          </span>
        </span>
        {attention > 0 && (
          <span
            className="xhost__flag"
            title={`${attention} item(s) worth a look`}
          >
            <Icon name="alert" size={12} />
            {attention}
          </span>
        )}
      </span>
      <span className="xhost__svcs">
        {h.services.length === 0 && (
          <span className="muted xhost__none">No open ports</span>
        )}
        {shown.map((s) => (
          <span
            key={`${s.port.protocol}-${s.port.portid}`}
            className={pillClass(s)}
          >
            <span className="svc-pill__port">{s.port.portid}</span>
            {s.label}
          </span>
        ))}
        {h.services.length > MAX_PILLS && (
          <span className="svc-pill svc-pill--more">
            +{h.services.length - MAX_PILLS} more
          </span>
        )}
      </span>
    </button>
  );
}

function HostDetail({
  h,
  versionScan,
}: {
  h: HostExposure;
  versionScan: boolean;
}) {
  const byCategory = CATEGORY_ORDER.map(
    (c) => [c, h.services.filter((s) => s.category === c)] as const,
  ).filter(([, list]) => list.length > 0);

  return (
    <aside className="card xdetail" aria-label={`Details for ${h.addr}`}>
      <div className="xdetail__head">
        <span
          className={`xhost__icon xhost__icon--lg xhost__icon--${h.device.kind}`}
        >
          <Icon name={DEVICE_ICONS[h.device.kind]} size={22} />
        </span>
        <div className="xdetail__titles">
          <div className="xdetail__name">{h.name ?? h.addr}</div>
          {h.name && <div className="mono muted">{h.addr}</div>}
        </div>
      </div>

      <div className="xdetail__guess">
        <span className="xdetail__guess-label">
          {h.device.label}
          {h.device.role && (
            <span className="xdetail__role"> · {h.device.role}</span>
          )}
        </span>
        <span className="tag">guess</span>
        {h.device.because && (
          <span className="xdetail__because">based on {h.device.because}</span>
        )}
      </div>

      <dl className="xdetail__addrs">
        {h.host.addresses
          .filter((a) => a.addrType !== "mac")
          .map((a) => (
            <div key={a.addr}>
              <dt>{a.addrType.toUpperCase()}</dt>
              <dd className="mono">{a.addr}</dd>
            </div>
          ))}
        {h.host.hostnames.map((n) => (
          <div key={n}>
            <dt title="Reverse DNS (from nmap)">DNS</dt>
            <dd className="mono">{n}</dd>
          </div>
        ))}
        {h.mdnsName && (
          <div>
            <dt title="Multicast DNS / Bonjour / Avahi name">mDNS</dt>
            <dd className="mono">{h.mdnsName}</dd>
          </div>
        )}
        {h.mac && (
          <div>
            <dt>MAC</dt>
            <dd>
              <span className="mono">{h.mac}</span>
              {h.macSource === "arp" && (
                <span
                  className="tag"
                  title="Read from this computer's ARP cache — nmap only reports MACs when run as root"
                >
                  ARP cache
                </span>
              )}
              <div className="xdetail__vendor">
                {h.macRandomized
                  ? "Private (randomized) address — phones and laptops use these for Wi-Fi privacy, so the maker can't be looked up."
                  : (h.vendor ?? "Vendor not in nmap's database")}
              </div>
            </dd>
          </div>
        )}
      </dl>

      {byCategory.length === 0 && (
        <p className="muted xdetail__empty">
          No open ports found. The host answered, but nothing in the scanned
          port range accepted a connection.
        </p>
      )}

      {byCategory.map(([cat, list]) => (
        <section key={cat} className="xcat">
          <div className="xcat__head">
            <span className="xcat__title">{CATEGORIES[cat].label}</span>
            <span className="xcat__blurb">{CATEGORIES[cat].blurb}</span>
          </div>
          {list.map((s) => (
            <ServiceRow
              key={`${s.port.protocol}-${s.port.portid}`}
              s={s}
              versionScan={versionScan}
            />
          ))}
        </section>
      ))}

      {h.hiddenPorts > 0 && (
        <p className="xdetail__hidden">
          {h.hiddenPorts} closed or filtered port
          {h.hiddenPorts === 1 ? "" : "s"} not shown — see the Table view.
        </p>
      )}
    </aside>
  );
}

function ServiceRow({
  s,
  versionScan,
}: {
  s: ServiceInfo;
  versionScan: boolean;
}) {
  const svc = s.port.service;
  const product = [svc?.product, svc?.version].filter(Boolean).join(" ");
  const cert = s.port.cert;
  return (
    <div
      className={
        "xsvc" +
        (s.cleartext ? " xsvc--cleartext" : s.review ? " xsvc--review" : "")
      }
    >
      <div className="xsvc__top">
        <span className="mono xsvc__port">
          {s.port.portid}/{s.port.protocol}
        </span>
        <span className="xsvc__label">{s.label}</span>
        <span className="xsvc__tags">
          {s.cleartext && (
            <span className="tag tag--bad">
              <Icon name="unlock" size={11} />
              unencrypted
            </span>
          )}
          {s.tls && (
            <span className="tag tag--ok">
              <Icon name="lock" size={11} />
              TLS
            </span>
          )}
          {s.review && <span className="tag tag--warn">review</span>}
        </span>
      </div>
      {product && <div className="xsvc__product mono">{product}</div>}
      <p className="xsvc__note">{s.note}</p>
      {cert && (
        <p className="xsvc__cert">
          Certificate: {cert.subjectCn ?? "?"}
          {cert.issuerCn && cert.issuerCn !== cert.subjectCn
            ? `, issued by ${cert.issuerCn}`
            : cert.issuerCn
              ? " (likely self-signed)"
              : ""}
          {cert.notAfter ? `, valid until ${cert.notAfter.slice(0, 10)}` : ""}
        </p>
      )}
      {s.guessed && (
        <p className="xsvc__guessed">
          Named from the port number only{svc?.name ? ` ("${svc.name}")` : ""} —
          {versionScan
            ? "nmap couldn't fingerprint it, so it's unconfirmed."
            : "the Service + version profile would confirm it."}
        </p>
      )}
    </div>
  );
}
