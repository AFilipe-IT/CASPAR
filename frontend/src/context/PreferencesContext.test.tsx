import { beforeEach, describe, expect, it } from "vitest";
import { act, render, screen } from "@testing-library/react";
import { PreferencesProvider, usePreferences } from "./PreferencesContext";

const KEY = "cvm.preferences";

function Probe() {
  const { preferences, setPreferences, resetPreferences } = usePreferences();
  return (
    <div>
      <span data-testid="profile">{preferences.envProfile || "(none)"}</span>
      <span data-testid="threshold">{preferences.threshold || "(none)"}</span>
      <button onClick={() => setPreferences({ threshold: "7.5" })}>set</button>
      <button onClick={resetPreferences}>reset</button>
    </div>
  );
}

function renderProbe() {
  return render(
    <PreferencesProvider>
      <Probe />
    </PreferencesProvider>,
  );
}

describe("PreferencesContext", () => {
  beforeEach(() => localStorage.clear());

  it("starts with no defaults set", () => {
    renderProbe();
    expect(screen.getByTestId("profile")).toHaveTextContent("(none)");
    expect(screen.getByTestId("threshold")).toHaveTextContent("(none)");
  });

  it("persists a change to localStorage", () => {
    renderProbe();
    act(() => screen.getByText("set").click());

    expect(screen.getByTestId("threshold")).toHaveTextContent("7.5");
    expect(JSON.parse(localStorage.getItem(KEY)!).threshold).toBe("7.5");
  });

  it("restores what a previous session stored", () => {
    localStorage.setItem(KEY, JSON.stringify({ envProfile: "production", threshold: "4" }));
    renderProbe();
    expect(screen.getByTestId("profile")).toHaveTextContent("production");
    expect(screen.getByTestId("threshold")).toHaveTextContent("4");
  });

  it("fills in a preference the stored object predates", () => {
    // Someone who saved preferences before `threshold` existed must not get
    // `undefined` back — React would then flip its input to uncontrolled.
    localStorage.setItem(KEY, JSON.stringify({ envProfile: "dev" }));
    renderProbe();
    expect(screen.getByTestId("profile")).toHaveTextContent("dev");
    expect(screen.getByTestId("threshold")).toHaveTextContent("(none)");
  });

  it("falls back to defaults when the stored value is corrupt", () => {
    localStorage.setItem(KEY, "{not json");
    renderProbe();          // must not throw
    expect(screen.getByTestId("profile")).toHaveTextContent("(none)");
  });

  it("clears everything on reset", () => {
    localStorage.setItem(KEY, JSON.stringify({ envProfile: "internal", threshold: "9" }));
    renderProbe();
    act(() => screen.getByText("reset").click());

    expect(screen.getByTestId("profile")).toHaveTextContent("(none)");
    expect(screen.getByTestId("threshold")).toHaveTextContent("(none)");
  });
});
