import { useEffect, useRef, useState } from "react";
import type { ExportFormat, StoredScan } from "../types";
import { Icon } from "./Icon";

interface Props {
  scan: StoredScan;
  /** Load this scan's command into the builder (it runs only on Run). */
  onRerun: (scan: StoredScan) => void;
  onExport: (scan: StoredScan, format: ExportFormat) => void;
}

const FORMATS: { id: ExportFormat; label: string; hint: string }[] = [
  { id: "html", label: "HTML report", hint: "standalone page to share" },
  { id: "csv", label: "CSV", hint: "one row per port, for spreadsheets" },
  { id: "json", label: "JSON", hint: "Cartograph's parsed result" },
  { id: "xml", label: "nmap XML", hint: "the original -oX output" },
  { id: "normal", label: "Normal text", hint: "like nmap -oN" },
  { id: "grepable", label: "Grepable text", hint: "like nmap -oG" },
];

/** Actions on a saved scan: run it again, copy its command, export it. */
export function ScanActions({ scan, onRerun, onExport }: Props) {
  const [open, setOpen] = useState(false);
  const [copied, setCopied] = useState(false);
  const menu = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const close = (e: Event) => {
      if (
        e instanceof KeyboardEvent
          ? e.key === "Escape"
          : !menu.current?.contains(e.target as Node)
      )
        setOpen(false);
    };
    document.addEventListener("mousedown", close);
    document.addEventListener("keydown", close);
    return () => {
      document.removeEventListener("mousedown", close);
      document.removeEventListener("keydown", close);
    };
  }, [open]);

  async function copy() {
    try {
      await navigator.clipboard.writeText(scan.command);
      setCopied(true);
      setTimeout(() => setCopied(false), 1200);
    } catch {
      // Clipboard can be unavailable; failing silently is fine here.
    }
  }

  return (
    <div className="scan-actions">
      <button
        type="button"
        className="btn btn--ghost btn--sm"
        onClick={() => onRerun(scan)}
        title={`Load “${scan.command}” into the scan form`}
      >
        <Icon name="rerun" size={14} />
        Re-run
      </button>
      <button
        type="button"
        className="btn btn--ghost btn--sm"
        onClick={copy}
        title={scan.command}
      >
        <Icon name={copied ? "check" : "copy"} size={14} />
        {copied ? "Copied" : "Copy command"}
      </button>
      <div className="menu" ref={menu}>
        <button
          type="button"
          className="btn btn--ghost btn--sm"
          onClick={() => setOpen((o) => !o)}
          aria-haspopup="menu"
          aria-expanded={open}
        >
          <Icon name="download" size={14} />
          Export
          <Icon name="chevronDown" size={12} />
        </button>
        {open && (
          <div className="menu__list" role="menu">
            {FORMATS.map((f) => (
              <button
                key={f.id}
                type="button"
                role="menuitem"
                className="menu__item"
                onClick={() => {
                  setOpen(false);
                  onExport(scan, f.id);
                }}
              >
                <span className="menu__label">{f.label}</span>
                <span className="menu__hint">{f.hint}</span>
              </button>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
