import { useEffect, useRef } from "react";
import { THEMES } from "../themes";
import { Icon } from "./Icon";

interface Props {
  current: string;
  onChange: (id: string) => void;
  onClose: () => void;
}

/** Appearance panel. Each card is a miniature of the app rendered under that
 *  theme's own tokens (via its data-theme attribute), so the preview is exact. */
export function ThemePicker({ current, onChange, onClose }: Props) {
  const dialogRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    dialogRef.current
      ?.querySelector<HTMLElement>(".theme-card--active")
      ?.focus();
    function onKey(e: KeyboardEvent) {
      if (e.key === "Escape") onClose();
    }
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  return (
    <div className="modal-backdrop" onMouseDown={onClose}>
      <div
        ref={dialogRef}
        className="modal"
        role="dialog"
        aria-modal="true"
        aria-labelledby="appearance-title"
        onMouseDown={(e) => e.stopPropagation()}
      >
        <div className="modal__head">
          <div>
            <h2 id="appearance-title" className="modal__title">
              Appearance
            </h2>
            <p className="modal__subtitle">
              Pick a theme. It's saved on this machine only.
            </p>
          </div>
          <button
            type="button"
            className="icon-btn"
            onClick={onClose}
            aria-label="Close"
          >
            <Icon name="x" />
          </button>
        </div>

        <div className="theme-grid" role="radiogroup" aria-label="Theme">
          {THEMES.map((t) => {
            const active = t.id === current;
            return (
              <button
                key={t.id}
                type="button"
                role="radio"
                aria-checked={active}
                className={"theme-card" + (active ? " theme-card--active" : "")}
                onClick={() => onChange(t.id)}
              >
                <div
                  className="theme-preview"
                  data-theme={t.id}
                  aria-hidden="true"
                >
                  <div className="theme-preview__side">
                    <span className="theme-preview__dot" />
                    <span className="theme-preview__line" />
                    <span className="theme-preview__line theme-preview__line--short" />
                    <span className="theme-preview__line" />
                  </div>
                  <div className="theme-preview__main">
                    <div className="theme-preview__card">
                      <span className="theme-preview__input" />
                      <span className="theme-preview__btn" />
                    </div>
                    <div className="theme-preview__pills">
                      <span className="theme-preview__pill theme-preview__pill--ok" />
                      <span className="theme-preview__pill theme-preview__pill--warn" />
                      <span className="theme-preview__pill theme-preview__pill--bad" />
                    </div>
                  </div>
                </div>
                <div className="theme-card__meta">
                  <span className="theme-card__label">
                    {t.label}
                    {active && <Icon name="check" size={14} />}
                  </span>
                  <span className="theme-card__desc">{t.description}</span>
                </div>
              </button>
            );
          })}
        </div>
      </div>
    </div>
  );
}
