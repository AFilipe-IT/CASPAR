import { useEffect, useState } from "react";
import {
  CartesianGrid,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { Eye, Info, Pause, Play, PlayCircle, Square } from "lucide-react";
import { PageHeader } from "@/components/layout/PageHeader";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Badge, severityTone } from "@/components/ui/Badge";
import { EmptyState } from "@/components/ui/EmptyState";
import { SkeletonBlock } from "@/components/ui/Skeleton";
import {
  useStartWatch,
  useWatchControl,
  useWatchSession,
  useWatchSessions,
} from "@/api/watch";
import type { WatchSession } from "@/api/types";
import { scoreToHex, scoreToRiskLabel } from "@/lib/severity";
import shared from "./JobsShared.module.css";
import styles from "./WatchPage.module.css";

/** A session's state in words, from the two independent signals the API
 *  gives us: heartbeat liveness, and (only for sessions this server owns)
 *  the runner's own state. */
export function stateOf(s: Pick<WatchSession, "live" | "runner_state">) {
  if (s.runner_state === "paused") return { label: "Paused", dot: styles.dotPaused };
  if (s.runner_state === "stopped") return { label: "Stopped", dot: styles.dot };
  if (s.live) return { label: "Live", dot: styles.dotLive };
  return { label: "Stopped", dot: styles.dot };
}

function StatePill({ session }: { session: Pick<WatchSession, "live" | "runner_state"> }) {
  const { label, dot } = stateOf(session);
  return (
    <span className={styles.state}>
      <span className={[styles.dot, dot].join(" ")} />
      {label}
    </span>
  );
}

function fmtTime(ts: string | null): string {
  if (!ts) return "—";
  const d = new Date(ts.endsWith("Z") ? ts : `${ts}Z`);
  return isNaN(d.getTime()) ? "—" : d.toLocaleTimeString();
}

export function WatchPage() {
  const [path, setPath] = useState("");
  const [interval, setIntervalValue] = useState(2);
  const [selected, setSelected] = useState<string | undefined>();

  const { data: sessions, isLoading } = useWatchSessions();
  const { data: detail } = useWatchSession(selected);
  const startWatch = useStartWatch();
  const control = useWatchControl();

  // Default to the first session so the page is never empty when one exists.
  useEffect(() => {
    if (!selected && sessions && sessions.length > 0) {
      setSelected(sessions[0].watch_session);
    }
  }, [sessions, selected]);

  const latest = detail?.latest;
  const owned = latest?.runner_state != null && latest.runner_state !== "stopped";
  const paused = latest?.runner_state === "paused";

  // Oldest-first for the chart; the API returns events newest-first.
  const chartData = (detail?.events ?? [])
    .slice()
    .reverse()
    .map((e, i) => ({
      i,
      time: fmtTime(e.timestamp),
      score: e.global_temporal_score,
    }));

  function act(action: "pause" | "resume" | "stop") {
    if (!selected) return;
    control.mutate({ sessionId: selected, action });
  }

  return (
    <>
      <PageHeader
        title="Watch"
        description="Continuously audit a config and see the score move as it changes — the same loop as `caspar watch`, with pause and stop from the browser."
      />

      <Card
        title="Start a session"
        subtitle="Re-scans on every change to the file or directory, server-side."
      >
        <div className={shared.form}>
          <div className={shared.row2}>
            <div className={shared.field}>
              <label className={shared.label} htmlFor="wpath">
                Config path
              </label>
              <input
                id="wpath"
                className={shared.input}
                placeholder="/etc/nginx/nginx.conf"
                value={path}
                onChange={(e) => setPath(e.target.value)}
              />
              <span className={shared.hint}>A file or directory on the server.</span>
            </div>

            <div className={shared.field}>
              <label className={shared.label} htmlFor="winterval">
                Interval (seconds)
              </label>
              <input
                id="winterval"
                className={shared.input}
                type="number"
                min={0.5}
                step={0.5}
                value={interval}
                onChange={(e) => setIntervalValue(Number(e.target.value))}
              />
            </div>
          </div>

          {startWatch.isError && (
            <div className={shared.error}>{(startWatch.error as Error).message}</div>
          )}

          <div className={shared.actions}>
            <Button
              variant="primary"
              icon={<PlayCircle size={16} />}
              disabled={!path || startWatch.isPending}
              onClick={() =>
                startWatch.mutate(
                  { path, interval },
                  { onSuccess: (r) => setSelected(r.watch_session) },
                )
              }
            >
              {startWatch.isPending ? "Starting…" : "Start watching"}
            </Button>
          </div>
        </div>
      </Card>

      <div className={styles.layout}>
        <Card title="Sessions" subtitle="Started here or by the CLI.">
          {isLoading ? (
            <SkeletonBlock rows={4} />
          ) : sessions && sessions.length > 0 ? (
            <div className={styles.sessionList}>
              {sessions.map((s) => (
                <div
                  key={s.watch_session}
                  className={[
                    styles.sessionRow,
                    s.watch_session === selected ? styles.sessionRowActive : "",
                  ].join(" ")}
                  onClick={() => setSelected(s.watch_session)}
                >
                  <div className={styles.sessionTop}>
                    <span className={styles.sessionName}>
                      {s.target_name ?? "unknown"}
                    </span>
                    <StatePill session={s} />
                  </div>
                  <span className={styles.sessionMeta}>{s.input_path}</span>
                  <div className={styles.sessionTop}>
                    <span className={styles.sessionMeta}>
                      {s.watch_session.slice(0, 8)}
                    </span>
                    <Badge tone={severityTone(s.severity ?? "None")}>
                      {s.global_temporal_score.toFixed(1)}
                    </Badge>
                  </div>
                </div>
              ))}
            </div>
          ) : (
            <EmptyState
              icon={<Eye size={22} />}
              title="No watch sessions"
              description="Start one above, or run `caspar watch` — sessions from either show up here."
            />
          )}
        </Card>

        <div>
          {detail && latest ? (
            <>
              <Card title="Live status">
                <div className={styles.detailHead}>
                  <div className={styles.scoreRow}>
                    <div className={styles.stat}>
                      <span
                        className={styles.bigScore}
                        style={{ color: scoreToHex(latest.global_temporal_score) }}
                      >
                        {latest.global_temporal_score.toFixed(1)}
                      </span>
                      <span
                        className={styles.scoreCaption}
                        style={{ color: scoreToHex(latest.global_temporal_score) }}
                      >
                        {scoreToRiskLabel(latest.global_temporal_score)}
                      </span>
                    </div>
                    <div className={styles.stat}>
                      <span className={styles.statValue}>{latest.total_issues}</span>
                      <span className={styles.scoreCaption}>Issues</span>
                    </div>
                    <div className={styles.stat}>
                      <span className={styles.statValue}>{latest.total_chains}</span>
                      <span className={styles.scoreCaption}>Chains</span>
                    </div>
                    <div className={styles.stat}>
                      <span className={styles.statValue}>{detail.events.length}</span>
                      <span className={styles.scoreCaption}>Events</span>
                    </div>
                    <div className={styles.stat}>
                      <StatePill session={latest} />
                      <span className={styles.scoreCaption}>
                        last seen {fmtTime(latest.last_seen)}
                      </span>
                    </div>
                  </div>

                  <div className={styles.controls}>
                    <Button
                      icon={paused ? <Play size={15} /> : <Pause size={15} />}
                      disabled={!owned || control.isPending}
                      onClick={() => act(paused ? "resume" : "pause")}
                    >
                      {paused ? "Resume" : "Pause"}
                    </Button>
                    <Button
                      icon={<Square size={15} />}
                      disabled={!owned || control.isPending}
                      onClick={() => act("stop")}
                    >
                      Stop
                    </Button>
                  </div>
                </div>

                {control.isError && (
                  <div className={shared.error}>{(control.error as Error).message}</div>
                )}

                {!owned && (
                  <p className={styles.notice}>
                    <Info size={13} style={{ flexShrink: 0, marginTop: 2 }} />
                    <span>
                      This session isn't controlled by this server process — it was
                      started by <code>caspar watch</code> on the command line, or
                      before the server restarted. It's still shown live from its
                      heartbeat, but pause and stop are unavailable; stop it where it
                      runs (Ctrl-C).
                    </span>
                  </p>
                )}
              </Card>

              <Card
                title="Score over time"
                subtitle="Every re-scan this session has recorded, oldest first."
              >
                {chartData.length > 1 ? (
                  <div className={styles.chart}>
                    <ResponsiveContainer width="100%" height="100%">
                      <LineChart
                        data={chartData}
                        margin={{ top: 8, right: 12, bottom: 4, left: -18 }}
                      >
                        <CartesianGrid
                          stroke="var(--border)"
                          strokeDasharray="2 4"
                          vertical={false}
                        />
                        <XAxis
                          dataKey="time"
                          tick={{ fill: "var(--text-faint)", fontSize: 11 }}
                          stroke="var(--border)"
                          minTickGap={28}
                        />
                        <YAxis
                          domain={[0, 10]}
                          tick={{ fill: "var(--text-faint)", fontSize: 11 }}
                          stroke="var(--border)"
                        />
                        <Tooltip
                          contentStyle={{
                            background: "var(--panel)",
                            border: "1px solid var(--border)",
                            borderRadius: 8,
                            fontSize: 12,
                          }}
                          labelStyle={{ color: "var(--text-muted)" }}
                          formatter={(v: number) => [v.toFixed(1), "Score"]}
                        />
                        <Line
                          type="monotone"
                          dataKey="score"
                          stroke={scoreToHex(latest.global_temporal_score)}
                          strokeWidth={2}
                          dot={false}
                          activeDot={{ r: 4 }}
                          isAnimationActive={false}
                        />
                      </LineChart>
                    </ResponsiveContainer>
                  </div>
                ) : (
                  <EmptyState
                    icon={<Eye size={22} />}
                    title="Not enough history yet"
                    description="The trend appears once the config changes at least once."
                  />
                )}
              </Card>

              <Card title="Events" subtitle="Every re-scan, newest first.">
                {detail.events.map((e, i) => (
                  <div key={i} className={styles.eventRow}>
                    <span className={styles.eventTime}>{fmtTime(e.timestamp)}</span>
                    <Badge tone={severityTone(e.severity ?? "None")}>
                      {e.severity ?? "None"}
                    </Badge>
                    <span>
                      {e.total_issues} issues · {e.total_chains} chains
                    </span>
                    <span
                      className={styles.eventScore}
                      style={{ color: scoreToHex(e.global_temporal_score) }}
                    >
                      {e.global_temporal_score.toFixed(1)}
                    </span>
                  </div>
                ))}
              </Card>
            </>
          ) : (
            <Card title="Live status">
              <EmptyState
                icon={<Eye size={22} />}
                title="No session selected"
                description="Pick a session on the left, or start a new one above."
              />
            </Card>
          )}
        </div>
      </div>
    </>
  );
}
