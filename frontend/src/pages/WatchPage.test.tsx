import { describe, expect, it } from "vitest";
import { stateOf } from "./WatchPage";

/**
 * The console reads a session's state from two *independent* signals:
 *
 *   live         — heartbeat-derived, true for any running session including
 *                  one started by `caspar watch` in a terminal;
 *   runner_state — set only for sessions this server process owns, null for
 *                  CLI-started sessions and for anything predating a restart.
 *
 * The pairing matters: a paused session deliberately keeps beating (so it
 * stays live), which is exactly why runner_state has to win over live. That
 * was a real bug once — a paused session read as "stopped".
 */
describe("stateOf", () => {
  it("reports a paused session as paused, not live", () => {
    // The case the heartbeat bug produced: still beating (live), but
    // deliberately idle. runner_state must win.
    expect(stateOf({ live: true, runner_state: "paused" }).label).toBe("Paused");
  });

  it("reports a running server-owned session as live", () => {
    expect(stateOf({ live: true, runner_state: "running" }).label).toBe("Live");
  });

  it("reports a CLI-started session as live from its heartbeat alone", () => {
    // No runner_state, because this process doesn't own it — but it is
    // demonstrably alive, so the console must not call it stopped.
    expect(stateOf({ live: true, runner_state: null }).label).toBe("Live");
  });

  it("reports a stale CLI session as stopped", () => {
    expect(stateOf({ live: false, runner_state: null }).label).toBe("Stopped");
  });

  it("trusts an explicit stopped runner over a not-yet-stale heartbeat", () => {
    // Between `stop` and the heartbeat aging out (up to 2x interval) the two
    // signals disagree. The explicit signal is the truthful one.
    expect(stateOf({ live: true, runner_state: "stopped" }).label).toBe("Stopped");
  });
});
