import { createContext, useContext, useEffect, useMemo, useState, type ReactNode } from "react";

/**
 * Assessment defaults, persisted per-browser.
 *
 * These are deliberately client-side: they pre-fill the run form, they are not
 * server configuration. Anything that changes how the *server* behaves stays
 * read-only over HTTP (see GET /settings).
 */
export type EnvProfile = "" | "production" | "internal" | "dev";

export interface Preferences {
  envProfile: EnvProfile;
  /** Empty string means "no CI gate", matching the form's optional field. */
  threshold: string;
  /**
   * Path to the suppression file, as the *server* sees it.
   *
   * The API refuses to guess this: the CLI's `.caspar-suppress.json` default is
   * relative to the process working directory, which for a long-running server
   * means "wherever it was launched" — not something a browser user can reason
   * about. So the path is asked for once and remembered here.
   */
  suppressFile: string;
}

const STORAGE_KEY = "cvm.preferences";

const DEFAULTS: Preferences = { envProfile: "", threshold: "", suppressFile: "" };

interface PreferencesContextValue {
  preferences: Preferences;
  setPreferences: (next: Partial<Preferences>) => void;
  resetPreferences: () => void;
}

const PreferencesContext = createContext<PreferencesContextValue | null>(null);

function readInitialPreferences(): Preferences {
  try {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (!stored) return DEFAULTS;
    // Merge over defaults so a preference added in a later version doesn't
    // come back undefined for someone with an older stored object.
    return { ...DEFAULTS, ...(JSON.parse(stored) as Partial<Preferences>) };
  } catch {
    return DEFAULTS;
  }
}

export function PreferencesProvider({ children }: { children: ReactNode }) {
  const [preferences, setState] = useState<Preferences>(readInitialPreferences);

  useEffect(() => {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(preferences));
  }, [preferences]);

  const value = useMemo<PreferencesContextValue>(
    () => ({
      preferences,
      setPreferences: (next) => setState((p) => ({ ...p, ...next })),
      resetPreferences: () => setState(DEFAULTS),
    }),
    [preferences],
  );

  return <PreferencesContext.Provider value={value}>{children}</PreferencesContext.Provider>;
}

export function usePreferences(): PreferencesContextValue {
  const ctx = useContext(PreferencesContext);
  if (!ctx) throw new Error("usePreferences must be used within PreferencesProvider");
  return ctx;
}
