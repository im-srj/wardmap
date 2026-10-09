import { useState, type FormEvent } from "react";
import { findOption, setOption } from "../options";
import { PRESETS, sameOptions } from "../presets";
import type { CmdIssue, CmdItem, Profile, StoredScan } from "../types";
import { CommandPreview } from "./CommandPreview";
import { relativeTime } from "./HistoryList";
import { Icon } from "./Icon";
import { OptionsBuilder } from "./OptionsBuilder";
import { ProfilePicker } from "./ProfilePicker";
import { ScriptBrowser } from "./ScriptBrowser";

interface Props {
  target: string;
  onTargetChange: (t: string) => void;
  /** The command's options (everything but the targets). */
  items: CmdItem[];
  onItemsChange: (items: CmdItem[]) => void;
  /** The full command line, as it will run. */
  command: string;
  /** Run nmap as root (pkexec asks for the password each scan). */
  elevate: boolean;
  onElevateChange: (on: boolean) => void;
  issues: CmdIssue[];
  /** The command line was edited by hand. */
  onEditCommand: (text: string) => void;
  /** The backend has checked the current command and nothing blocks it. */
  canRun: boolean;
  onRun: () => void;
  /** As many scans are running as may run at once: Run queues instead. */
  queueFull: boolean;
  /** Re-running this saved scan: its result will be compared with it. */
  rerunOf: StoredScan | null;
  onClearRerun: () => void;
  profiles: Profile[];
  onSaveProfile: (
    id: number | null,
    name: string,
    description: string,
  ) => Promise<Profile>;
  onDeleteProfile: (id: number) => Promise<void>;
  onImportZenmap: () => void;
  /** Fold the profile/NSE options behind a summary row (used while results
   *  are on screen). The command preview always stays visible. */
  collapsible: boolean;
}

const SCRIPT_DEF = findOption("--script")!;

export function ScanForm({
  target,
  onTargetChange,
  items,
  onItemsChange,
  command,
  elevate,
  onElevateChange,
  issues,
  onEditCommand,
  canRun,
  onRun,
  queueFull,
  rerunOf,
  onClearRerun,
  profiles,
  onSaveProfile,
  onDeleteProfile,
  onImportZenmap,
  collapsible,
}: Props) {
  const [expanded, setExpanded] = useState(false);
  const showOptions = !collapsible || expanded;
  const profileName =
    PRESETS.find((p) => sameOptions(items, p.items))?.label ??
    profiles.find((p) => sameOptions(items, p.items))?.name;

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
    if (canRun) onRun();
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
          disabled={!canRun}
          title={
            queueFull
              ? "Other scans are running; this one starts when one finishes"
              : undefined
          }
        >
          <Icon name={queueFull ? "list" : "play"} size={15} />
          {queueFull ? "Queue scan" : "Run scan"}
        </button>
      </div>

      {rerunOf && (
        <div className="rerun-note">
          <Icon name="rerun" size={14} />
          <span>
            Re-running the scan from {relativeTime(rerunOf.createdAt)} — the
            result will be compared with it.
          </span>
          <button
            type="button"
            className="icon-btn icon-btn--sm"
            onClick={onClearRerun}
            aria-label="Don't compare with the earlier scan"
            title="Don't compare"
          >
            <Icon name="x" size={13} />
          </button>
        </div>
      )}

      <label className="elevate">
        <input
          type="checkbox"
          checked={elevate}
          onChange={(e) => onElevateChange(e.target.checked)}
        />
        <Icon name={elevate ? "unlock" : "lock"} size={14} />
        <span className="elevate__label">Run as root</span>
        <span className="elevate__hint">
          {elevate
            ? "you'll be asked for your password when the scan starts"
            : "needed for SYN, UDP, OS detection and other raw-packet options"}
        </span>
      </label>

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
              {profileName ?? "Custom"}
              {items.length > 0 &&
                ` · ${items.length} option${items.length === 1 ? "" : "s"}`}
            </span>
          )}
        </button>
      )}

      {showOptions && (
        <ProfilePicker
          items={items}
          onApply={onItemsChange}
          profiles={profiles}
          onSave={onSaveProfile}
          onDelete={onDeleteProfile}
          onImportZenmap={onImportZenmap}
        />
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
