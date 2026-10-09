import type { FormEvent } from "react";
import { PRESETS, buildCommand, type Preset } from "../presets";
import { CommandPreview } from "./CommandPreview";

interface Props {
  target: string;
  onTargetChange: (t: string) => void;
  preset: Preset;
  onPresetChange: (p: Preset) => void;
  onRun: () => void;
  scanning: boolean;
}

export function ScanForm({
  target,
  onTargetChange,
  preset,
  onPresetChange,
  onRun,
  scanning,
}: Props) {
  const command = buildCommand(preset.flags, target);

  function onSubmit(e: FormEvent) {
    e.preventDefault();
    if (!scanning && target.trim()) onRun();
  }

  return (
    <form className="scan-form" onSubmit={onSubmit}>
      <div className="scan-form__row">
        <label className="field">
          <span className="field__label">Target</span>
          <input
            className="field__input"
            type="text"
            placeholder="e.g. scanme.nmap.org, 192.168.1.0/24, localhost"
            value={target}
            onChange={(e) => onTargetChange(e.target.value)}
            spellCheck={false}
            autoFocus
          />
        </label>
        <button
          type="submit"
          className="btn btn--primary"
          disabled={scanning || !target.trim()}
        >
          {scanning ? "Scanning…" : "Run scan"}
        </button>
      </div>

      <fieldset className="presets">
        <legend className="presets__legend">Scan intensity</legend>
        <div className="presets__options">
          {PRESETS.map((p) => (
            <label
              key={p.id}
              className={
                "preset" + (p.id === preset.id ? " preset--active" : "")
              }
            >
              <input
                type="radio"
                name="preset"
                value={p.id}
                checked={p.id === preset.id}
                onChange={() => onPresetChange(p)}
              />
              <span className="preset__label">{p.label}</span>
              <span className="preset__desc">{p.description}</span>
            </label>
          ))}
        </div>
      </fieldset>

      <CommandPreview command={command} />
    </form>
  );
}
