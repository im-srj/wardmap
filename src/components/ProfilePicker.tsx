import { useState, type ReactNode, type SyntheticEvent } from "react";
import { PRESETS, sameOptions } from "../presets";
import type { CmdItem, Profile } from "../types";
import { Icon, type IconName } from "./Icon";

interface Props {
  /** The current options. */
  items: CmdItem[];
  /** Replace the options with a profile's. */
  onApply: (items: CmdItem[]) => void;
  /** Saved profiles. */
  profiles: Profile[];
  /** Save the current options as a profile (`id` null = new). Rejects with
   *  a readable message. */
  onSave: (
    id: number | null,
    name: string,
    description: string,
  ) => Promise<Profile>;
  onDelete: (id: number) => Promise<void>;
  onImportZenmap: () => void;
}

/** Built-in profiles plus the user's own: pick one to load its options,
 *  save the current options as a profile, update or delete saved ones. */
export function ProfilePicker({
  items,
  onApply,
  profiles,
  onSave,
  onDelete,
  onImportZenmap,
}: Props) {
  // The saved profile the current options came from, so it can be updated.
  const [basedOnId, setBasedOnId] = useState<number | null>(null);
  const [form, setForm] = useState<{
    name: string;
    description: string;
  } | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [confirmDelete, setConfirmDelete] = useState<number | null>(null);
  const [busy, setBusy] = useState(false);

  const basedOn = profiles.find((p) => p.id === basedOnId) ?? null;
  const edited = basedOn !== null && !sameOptions(items, basedOn.items);

  async function save(id: number | null, name: string, description: string) {
    setBusy(true);
    setError(null);
    try {
      const saved = await onSave(id, name, description);
      setBasedOnId(saved.id);
      setForm(null);
    } catch (e) {
      setError(String(e));
    } finally {
      setBusy(false);
    }
  }

  function submit(e: SyntheticEvent) {
    // Nested in the scan form: don't let Enter here start a scan.
    e.preventDefault();
    e.stopPropagation();
    if (form) save(null, form.name, form.description);
  }

  function card(
    key: string,
    group: string,
    active: boolean,
    icon: IconName,
    label: string,
    flags: string,
    description: string,
    onSelect: () => void,
    extra?: ReactNode,
  ) {
    return (
      <label key={key} className={"preset" + (active ? " preset--active" : "")}>
        <input type="radio" name={group} checked={active} onChange={onSelect} />
        <span className="preset__icon">
          <Icon name={icon} size={16} />
        </span>
        <span className="preset__text">
          <span className="preset__label">
            <span className="preset__name">{label}</span>
            <code className="preset__flags" title={flags}>
              {flags}
            </code>
          </span>
          {description && <span className="preset__desc">{description}</span>}
        </span>
        {extra}
      </label>
    );
  }

  return (
    <fieldset className="presets">
      <legend className="section-label">Scan profile</legend>
      <div className="presets__options">
        {PRESETS.map((p) =>
          card(
            p.id,
            "preset",
            sameOptions(items, p.items),
            p.icon,
            p.label,
            p.items.length
              ? p.items.flatMap((i) => i.tokens).join(" ")
              : "default",
            p.description,
            () => {
              setBasedOnId(null);
              onApply(p.items);
            },
          ),
        )}
      </div>

      <div className="profiles__head">
        <span className="section-label">Your profiles</span>
        <span className="profiles__actions">
          {edited && (
            <button
              type="button"
              className="btn btn--ghost btn--sm"
              disabled={busy}
              onClick={() =>
                save(basedOn.id, basedOn.name, basedOn.description)
              }
              title="Save the current options into this profile"
            >
              <Icon name="save" size={13} />
              Update “{basedOn.name}”
            </button>
          )}
          <button
            type="button"
            className="btn btn--ghost btn--sm"
            onClick={() => {
              setError(null);
              setForm(form ? null : { name: "", description: "" });
            }}
            aria-expanded={form !== null}
          >
            <Icon name="plus" size={13} />
            Save as profile
          </button>
          <button
            type="button"
            className="btn btn--ghost btn--sm"
            onClick={onImportZenmap}
            title="Import profiles from Zenmap's scan_profile.usp"
          >
            <Icon name="upload" size={13} />
            Import from Zenmap
          </button>
        </span>
      </div>

      {form && (
        <div className="profile-form" role="group" aria-label="New profile">
          <input
            className="profile-form__input"
            placeholder="Profile name"
            value={form.name}
            onChange={(e) => setForm({ ...form, name: e.target.value })}
            onKeyDown={(e) => {
              if (e.key === "Enter") submit(e);
              if (e.key === "Escape") setForm(null);
            }}
            maxLength={80}
            autoFocus
            aria-label="Profile name"
          />
          <input
            className="profile-form__input profile-form__input--wide"
            placeholder="Description (optional)"
            value={form.description}
            onChange={(e) => setForm({ ...form, description: e.target.value })}
            onKeyDown={(e) => {
              if (e.key === "Enter") submit(e);
              if (e.key === "Escape") setForm(null);
            }}
            aria-label="Profile description"
          />
          <button
            type="button"
            className="btn btn--primary btn--sm"
            disabled={busy || form.name.trim() === ""}
            onClick={submit}
          >
            Save
          </button>
          <button
            type="button"
            className="btn btn--ghost btn--sm"
            onClick={() => setForm(null)}
          >
            Cancel
          </button>
          <span className="profile-form__hint">
            Saves the current options — not the target.
          </span>
        </div>
      )}
      {error && <div className="profile-form__error">{error}</div>}

      {profiles.length === 0 ? (
        !form && (
          <p className="profiles__empty">
            Set up options you use often, then “Save as profile” to reuse them.
          </p>
        )
      ) : (
        <div className="presets__options">
          {profiles.map((p) =>
            card(
              `user-${p.id}`,
              "profile",
              sameOptions(items, p.items),
              "save",
              p.name,
              p.command || "default",
              p.description,
              () => {
                setBasedOnId(p.id);
                onApply(p.items);
              },
              confirmDelete === p.id ? (
                <button
                  type="button"
                  className="preset__delete preset__delete--confirm"
                  onClick={() => {
                    setConfirmDelete(null);
                    if (basedOnId === p.id) setBasedOnId(null);
                    onDelete(p.id).catch((e) => setError(String(e)));
                  }}
                  onBlur={() => setConfirmDelete(null)}
                  autoFocus
                >
                  Delete?
                </button>
              ) : (
                <button
                  type="button"
                  className="preset__delete"
                  onClick={() => setConfirmDelete(p.id)}
                  aria-label={`Delete profile ${p.name}`}
                  title="Delete profile"
                >
                  <Icon name="trash" size={13} />
                </button>
              ),
            ),
          )}
        </div>
      )}
    </fieldset>
  );
}
