import { useState, type FormEvent } from "react";
import { findOption, setOption } from "../options";
import { PRESETS, applyPreset, matchingPreset } from "../presets";
import type { CmdIssue, CmdItem } from "../types";
import { CommandPreview } from "./CommandPreview";
import { Icon, type IconName } from "./Icon";
import { OptionsBuilder } from "./OptionsBuilder";
import { ScriptBrowser } from "./ScriptBrowser";

interface Props {
  target: string;
  onTargetChange: (t: string) => void;
  /** The command's options (everything but the targets). */
  items: CmdItem[];
  onItemsChange: (items: CmdItem[]) => void;
  /** The full command line, as it will run. */
  command: string;
  issues: CmdIssue[];
  /** The command line was edited by hand. */
  onEditCommand: (text: string) => void;
  /** The backend has checked the current command and nothing blocks it. */
  canRun: boolean;
  onRun: () => void;
  scanning: boolean;
  /** Fold the profile/NSE options behind a summary row (used while results
   *  are on screen). The command preview always stays visible. */
  collapsible: boolean;
}

const PRESET_ICONS: Record<string, IconName> = {
  quick: "zap",
  regular: "layers",
  version: "fingerprint",
};

const SCRIPT_DEF = findOption("--script")!;

export function ScanForm({
  target,
  onTargetChange,
  items,
  onItemsChange,
  command,
  issues,
  onEditCommand,
  canRun,
  onRun,
  scanning,
  collapsible,
}: Props) {
  const [expanded, setExpanded] = useState(false);
  const showOptions = !collapsible || expanded;
  const preset = matchingPreset(items);

  // The script browser edits the --script option's comma list. Categories or
  // expressions typed into the command line ride along untouched.
  const scripts = (
    items.find((i) => i.name === "--script")?.value ?? ""
  )
    .split(",")
    .filter(Boolean);
  function onScriptsChange(ids: string[]) {
    onItemsChange(
      setOption(items, SCRIPT_DEF, ids.length ? ids.join(",") : undefined),
    );
  }

  function onSubmit(e: FormEvent) {
    e.preventDefault();
    if (!scanning && canRun) onRun();
  }

  return (
    <form className="card scan-form" onSubmit={onSubmit}>
      <div className="scan-form__row">
        <label className="target-field">
          <span className="sr-only">Target</span>
          <Icon name="target" size={18} className="target-field__icon" />
          <input
            className="target-field__input"
            type="text"
            placeholder="Target — e.g. scanme.nmap.org, 192.168.1.0/24, localhost"
            value={target}
            onChange={(e) => onTargetChange(e.target.value)}
            spellCheck={false}
            autoComplete="off"
            autoFocus
          />
        </label>
        <button
          type="submit"
          className="btn btn--primary btn--lg"
          disabled={scanning || !canRun}
        >
          {scanning ? (
            <>
              <span className="spinner" aria-hidden="true" />
              Scanning…
            </>
          ) : (
            <>
              <Icon name="play" size={15} />
              Run scan
            </>
          )}
        </button>
      </div>

      {collapsible && (
        <button
          type="button"
          className="options-toggle"
          onClick={() => setExpanded((e) => !e)}
          aria-expanded={expanded}
        >
          <Icon name={expanded ? "chevronDown" : "chevronRight"} size={14} />
          <span className="options-toggle__label">Scan options</span>
          {!expanded && (
            <span className="options-toggle__summary">
              {preset?.label ?? "Custom"}
              {items.length > 0 &&
                ` · ${items.length} option${items.length === 1 ? "" : "s"}`}
            </span>
          )}
        </button>
      )}

      {showOptions && (
        <fieldset className="presets">
          <legend className="section-label">Scan profile</legend>
          <div className="presets__options">
            {PRESETS.map((p) => (
              <label
                key={p.id}
                className={
                  "preset" + (p.id === preset?.id ? " preset--active" : "")
                }
              >
                <input
                  type="radio"
                  name="preset"
                  value={p.id}
                  checked={p.id === preset?.id}
                  onChange={() => onItemsChange(applyPreset(items, p))}
                />
                <span className="preset__icon">
                  <Icon name={PRESET_ICONS[p.id] ?? "layers"} size={16} />
                </span>
                <span className="preset__text">
                  <span className="preset__label">
                    {p.label}
                    <code className="preset__flags">
                      {p.items.length
                        ? p.items.flatMap((i) => i.tokens).join(" ")
                        : "default"}
                    </code>
                  </span>
                  <span className="preset__desc">{p.description}</span>
                </span>
              </label>
            ))}
          </div>
        </fieldset>
      )}

      <ScriptBrowser
        selected={scripts}
        onChange={onScriptsChange}
        collapsed={!showOptions}
      />

      <OptionsBuilder
        items={items}
        onChange={onItemsChange}
        collapsed={!showOptions}
      />

      <CommandPreview
        command={command}
        issues={issues}
        onEdit={onEditCommand}
      />
    </form>
  );
}
