import { useState } from "react";
import {
  CartesianGrid,
  Line,
  LineChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from "recharts";
import { Eye, Info, Pause, Play, PlayCircle, Square, Trash2 } from "lucide-react";
import { PageHeader } from "@/components/layout/PageHeader";
import { Card } from "@/components/ui/Card";
import { Button } from "@/components/ui/Button";
import { Badge, severityTone } from "@/components/ui/Badge";
import { EmptyState } from "@/components/ui/EmptyState";
import { SkeletonBlock } from "@/components/ui/Skeleton";
import { Modal } from "@/components/ui/Modal";
import { WatchEventDetail } from "@/components/watch/WatchEventDetail";
import {
  useClearWatchSessions,
  useDeleteWatchSession,
  useStartWatch,
  useWatchControl,
  useWatchSession,
  useWatchSessions,
} from "@/api/watch";
import { useLiveServices } from "@/api/targets";
import type { WatchEvent, WatchSession } from "@/api/types";
import { scoreToHex, scoreToRiskLabel } from "@/lib/severity";
import shared from "./JobsShared.module.css";
import styles from "./WatchPage.module.css";

/** A session's state in words, from the two independent signals the API
 *  gives us: heartbeat liveness, and (only for sessions this server owns)
 *  the runner's own state. */
export function stateOf(s: Pick<WatchSession, "live" | "runner_state">) {
  // 'failed' primeiro: uma sessão que rebentou também não está viva, e
  // mostrá-la como "Stopped" faz uma avaria passar por uma paragem normal.
  if (s.runner_state === "failed") return { label: "Failed", dot: styles.dotFailed };
  if (s.runner_state === "paused") return { label: "Paused", dot: styles.dotPaused };
  if (s.runner_state === "stopped") return { label: "Stopped", dot: styles.dot };
  if (s.live) return { label: "Live", dot: styles.dotLive };
  return { label: "Stopped", dot: styles.dot };
}

/** Viva = a scanear agora, ou em pausa (que também está viva, deliberadamente
 *  parada). Uma sessão que o servidor já não controla ainda pode estar viva
 *  pelo batimento — é o caso de um `caspar watch` no terminal. */
export function isAliveSession(s: Pick<WatchSession, "live" | "runner_state">) {
  const label = stateOf(s).label;
  return label === "Live" || label === "Paused";
}

/**
 * Qual a sessão que o painel mostra.
 *
 * Exportada e pura para ser testável directamente: é aqui que estava o bug de
 * o watch "não reagir". A escolha tem de ser *revista* sempre que a lista
 * muda — era feita uma só vez e nunca mais, portanto uma sessão que morresse
 * deixava a vista presa num score congelado enquanto a viva ao lado ia
 * actualizando.
 *
 * @param pinned o utilizador clicou numa linha. Uma escolha explícita
 *   respeita-se mesmo numa sessão parada (ver o histórico de uma antiga é
 *   legítimo); só a selecção automática salta para a viva.
 */
export function pickSession(
  sessions: WatchSession[] | undefined,
  selected: string | undefined,
  pinned: boolean,
): string | undefined {
  if (!sessions || sessions.length === 0) return undefined;
  const current = sessions.find((s) => s.watch_session === selected);
  if (current && (pinned || isAliveSession(current))) return selected;
  return (sessions.find(isAliveSession) ?? sessions[0]).watch_session;
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
  // Watching a service is the common case (it is what `caspar watch --live`
  // does), and a path had to be typed from memory before — hence the default.
  const [mode, setMode] = useState<"service" | "path">("service");
  const [service, setService] = useState("");
  const [path, setPath] = useState("");
  const [interval, setIntervalValue] = useState(2);
  const [selected, setSelected] = useState<string | undefined>();
  // Distingue "a página escolheu por mim" de "eu cliquei nesta". Só a
  // primeira é que a selecção automática pode substituir.
  const [pinned, setPinned] = useState(false);
  // O evento aberto no detalhe: as directivas que produziram aquele score.
  const [openEvent, setOpenEvent] = useState<WatchEvent | null>(null);

  const { data: liveServices } = useLiveServices();
  const selectedService = liveServices?.find((s) => s.service === service);
  // An undetected service is still startable: the picker says so, and the
  // resolver's own error is the authority — it looks in more places than the
  // single directory this check knows about.
  const canStart = mode === "service" ? !!service : !!path;

  const { data: sessions, isLoading } = useWatchSessions();

  // Qual a sessão que o painel mostra. Derivada no render, não guardada por um
  // efeito: um efeito só chamaria `setSelected` depois do primeiro render, e o
  // pedido do detalhe ficaria um ciclo atrás da lista — a página aparecia
  // vazia antes de se preencher.
  //
  // Mostrar a sessão VIVA, não a primeira da lista: num ambiente já usado as
  // primeiras são sessões antigas e paradas, e a página abria num cemitério.
  // E, sobretudo, a escolha é *revista* a cada actualização da lista. Antes
  // era feita uma vez ("se ainda não escolhi nenhuma") e nunca mais: bastava
  // a sessão escolhida morrer — parada, ou órfã de um reinício do servidor —
  // para a vista ficar presa num score congelado enquanto a viva ao lado ia
  // actualizando. Era esta a razão de "só vejo mudança quando clico em start
  // watching": esse clique era a única coisa que reescrevia a selecção.
  //
  // `pinned` = o utilizador clicou numa linha. Uma escolha explícita respeita-
  // se mesmo numa sessão parada (ver o histórico de uma antiga é legítimo);
  // só a selecção automática é que salta para a viva.
  const picked = pickSession(sessions, selected, pinned);

  const { data: detail } = useWatchSession(picked);
  const startWatch = useStartWatch();
  const control = useWatchControl();
  const deleteSession = useDeleteWatchSession();
  const clearSessions = useClearWatchSessions();

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
    // `picked`, não `selected`: os botões têm de agir sobre a sessão que o
    // painel está a mostrar. Enquanto a selecção é automática, `selected`
    // ainda é undefined e pausar/parar não faria nada.
    if (!picked) return;
    control.mutate({ sessionId: picked, action });
  }

  /** Apagar uma sessão. Deselecciona-a antes: sem isso a página ficava a
   *  pedir o detalhe de uma sessão que já não existe e mostrava um 404. */
  function removeSession(sessionId: string) {
    deleteSession.mutate(sessionId, {
      onSuccess: () => {
        if (sessionId === picked) {
          setSelected(undefined);
          setPinned(false);   // volta a seguir a sessão viva
        }
      },
    });
  }

  // Só sessões paradas se podem apagar; uma viva tem de ser parada primeiro,
  // e o botão de limpeza não faria nada se não houvesse nenhuma parada.
  const stoppedCount = (sessions ?? []).filter(
    (s) => stateOf(s).label !== "Live" && stateOf(s).label !== "Paused",
  ).length;

  return (
    <>
      <PageHeader
        title="Watch"
        description="Continuously audit a config and see the score move as it changes — the same loop as `caspar watch`, with pause and stop from the browser."
      />

      <Card
        title="Start a session"
        subtitle="Re-scans on every change, server-side. Watch an installed service or a path."
      >
        <div className={shared.form}>
          <div className={shared.modeRow}>
            <button
              type="button"
              className={[shared.modeBtn, mode === "service" ? shared.modeBtnActive : ""].join(" ")}
              onClick={() => setMode("service")}
            >
              Installed service
            </button>
            <button
              type="button"
              className={[shared.modeBtn, mode === "path" ? shared.modeBtnActive : ""].join(" ")}
              onClick={() => setMode("path")}
            >
              Config path
            </button>
          </div>

          <div className={shared.row2}>
            {mode === "service" ? (
              <div className={shared.field}>
                <label className={shared.label} htmlFor="wservice">
                  Service
                </label>
                <select
                  id="wservice"
                  className={shared.input}
                  value={service}
                  onChange={(e) => setService(e.target.value)}
                >
                  <option value="">Select a service…</option>
                  {(liveServices ?? []).map((s) => (
                    <option key={s.plugin} value={s.service} disabled={!s.plugin_installed}>
                      {s.service}
                      {s.detected ? "" : " — not found on server"}
                      {s.plugin_installed ? "" : " (plugin not installed)"}
                    </option>
                  ))}
                </select>
                <span className={shared.hint}>
                  {selectedService && !selectedService.detected
                    ? `${selectedService.config_dir} does not exist where the server runs — under Docker the container has its own filesystem.`
                    : "Resolved to the service's config directory, like `caspar watch --live`."}
                </span>
              </div>
            ) : (
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
            )}

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
              disabled={!canStart || startWatch.isPending}
              onClick={() =>
                startWatch.mutate(
                  mode === "service"
                    ? { path: service, live: true, interval }
                    : { path, interval },
                  {
                    onSuccess: (r) => {
                      // Acabou de a arrancar: é nela que quer estar, e é uma
                      // escolha tão explícita como clicar na linha.
                      setSelected(r.watch_session);
                      setPinned(true);
                    },
                  },
                )
              }
            >
              {startWatch.isPending ? "Starting…" : "Start watching"}
            </Button>
          </div>
        </div>
      </Card>

      <div className={styles.layout}>
        <Card
          title="Sessions"
          subtitle="Started here or by the CLI."
          action={
            stoppedCount > 0 ? (
              <Button
                icon={<Trash2 size={14} />}
                disabled={clearSessions.isPending}
                onClick={() => {
                  // Apagar histórico não se desfaz — confirmar é barato.
                  if (
                    window.confirm(
                      `Delete ${stoppedCount} stopped session(s) and their history? ` +
                        "Running sessions are kept.",
                    )
                  ) {
                    clearSessions.mutate();
                  }
                }}
              >
                {clearSessions.isPending ? "Clearing…" : `Clear ${stoppedCount} stopped`}
              </Button>
            ) : undefined
          }
        >
          {(deleteSession.isError || clearSessions.isError) && (
            <div className={shared.error}>
              {((deleteSession.error ?? clearSessions.error) as Error).message}
            </div>
          )}
          {isLoading ? (
            <SkeletonBlock rows={4} />
          ) : sessions && sessions.length > 0 ? (
            <div className={styles.sessionList}>
              {sessions.map((s) => (
                <div
                  key={s.watch_session}
                  className={[
                    styles.sessionRow,
                    s.watch_session === picked ? styles.sessionRowActive : "",
                  ].join(" ")}
                  onClick={() => {
                    setSelected(s.watch_session);
                    setPinned(true);
                  }}
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
                    <div className={styles.sessionActions}>
                      <Badge tone={severityTone(s.severity ?? "None")}>
                        {s.global_temporal_score.toFixed(1)}
                      </Badge>
                      {/* Só nas paradas: a API recusa apagar uma viva, e um
                          botão que só devolve 409 é ruído. `stopPropagation`
                          porque a linha inteira selecciona a sessão. */}
                      {stateOf(s).label !== "Live" && stateOf(s).label !== "Paused" && (
                        <button
                          type="button"
                          className={styles.deleteBtn}
                          title="Delete this session and its history"
                          aria-label={`Delete session ${s.watch_session.slice(0, 8)}`}
                          disabled={deleteSession.isPending}
                          onClick={(e) => {
                            e.stopPropagation();
                            removeSession(s.watch_session);
                          }}
                        >
                          <Trash2 size={13} />
                        </button>
                      )}
                    </div>
                  </div>
                  {s.error && <div className={styles.sessionError}>{s.error}</div>}
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

              <Card
                title="Events"
                subtitle="Every re-scan, newest first — open one to see the directives behind its score."
              >
                {detail.events.map((e, i) => (
                  // Um botão, não uma <div> com onClick: cada evento abre um
                  // detalhe, portanto é accionável por teclado e anuncia-se
                  // como tal. Eventos antigos, gravados antes de o `scan_id`
                  // ir na resposta, ficam sem detalhe — daí o disabled.
                  <button
                    key={e.scan_id ?? i}
                    type="button"
                    className={styles.eventRow}
                    disabled={!e.scan_id}
                    onClick={() => e.scan_id && setOpenEvent(e)}
                  >
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
                  </button>
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

      {openEvent?.scan_id && (
        <Modal
          title={`${openEvent.target_name ?? "Config"} · ${openEvent.global_temporal_score.toFixed(1)}`}
          subtitle={`${openEvent.input_path ?? ""} · ${fmtTime(openEvent.timestamp)}`}
          onClose={() => setOpenEvent(null)}
        >
          <WatchEventDetail scanId={openEvent.scan_id} />
        </Modal>
      )}
    </>
  );
}
