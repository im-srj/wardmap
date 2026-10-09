import { useCallback, useState } from "react";

export interface Theme {
  id: string;
  label: string;
  description: string;
}

// The colors themselves live in App.css as `[data-theme="<id>"]` token blocks.
// Because the selector is an attribute (not just :root), any element can opt
// into a theme — the Appearance panel uses that to render live previews.
export const THEMES: Theme[] = [
  {
    id: "midnight",
    label: "Midnight",
    description: "Deep blue-black, cyan accent",
  },
  {
    id: "graphite",
    label: "Graphite",
    description: "Neutral charcoal, violet accent",
  },
  { id: "terminal", label: "Terminal", description: "Phosphor green on black" },
  { id: "arctic", label: "Arctic", description: "Cool slate, frost blue" },
  { id: "ember", label: "Ember", description: "Warm dark, amber accent" },
  { id: "daylight", label: "Daylight", description: "Light, for bright rooms" },
];

export const DEFAULT_THEME = "midnight";
const STORAGE_KEY = "cartograph.theme";

/** Saved theme id, falling back to the default if storage is unavailable or
 *  holds an id we no longer ship. */
export function loadTheme(): string {
  try {
    const saved = localStorage.getItem(STORAGE_KEY);
    if (saved && THEMES.some((t) => t.id === saved)) return saved;
  } catch {
    // Storage blocked — use the default.
  }
  return DEFAULT_THEME;
}

export function applyTheme(id: string) {
  document.documentElement.dataset.theme = id;
}

export function useTheme(): [string, (id: string) => void] {
  const [theme, setThemeState] = useState(loadTheme);
  const setTheme = useCallback((id: string) => {
    applyTheme(id);
    setThemeState(id);
    try {
      localStorage.setItem(STORAGE_KEY, id);
    } catch {
      // Not persisted this session; the switch still applies.
    }
  }, []);
  return [theme, setTheme];
}
