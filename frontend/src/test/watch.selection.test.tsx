import { describe, expect, it } from "vitest";
import { pickSession } from "@/pages/WatchPage";
import type { WatchSession } from "@/api/types";

/**
 * Porque é que o painel do watch parecia não reagir a alterações.
 *
 * A selecção da sessão era feita uma única vez ("se ainda não escolhi
 * nenhuma") e nunca mais revista. Bastava a página abrir numa sessão que
 * entretanto morresse — parada, ou órfã de um reinício do servidor — para a
 * vista ficar presa num score congelado, enquanto a sessão viva ao lado ia
 * actualizando. A única coisa que reescrevia a selecção era carregar em
 * "Start watching", que era exactamente o sintoma relatado.
 *
 * A regra que a correcção introduz, e que estes testes fixam: a selecção
 * automática segue a sessão viva; uma escolha explícita do utilizador (clicar
 * numa linha) é que se respeita mesmo que a sessão esteja parada.
 */

function session(p: Partial<WatchSession>): WatchSession {
  return {
    watch_session: "s",
    live: false,
    runner_state: null,
    global_temporal_score: 7.1,
    severity: "Medium",
    total_issues: 12,
    total_chains: 8,
    target_name: "apache-httpd",
    input_path: "/etc/apache2/apache2.conf",
    watch_interval: 2,
    timestamp: "2026-08-10T12:00:00Z",
    ...p,
  } as WatchSession;
}

// `pickSession` é importada da própria página, não recriada aqui: uma cópia
// da lógica no teste passaria à mesma com a página avariada — verificado.
const autoSelect = pickSession;

describe("qual a sessão que o painel mostra", () => {
  it("salta de uma sessão morta para a viva", () => {
    // O caso real: uma sessão antiga ficou seleccionada e parou; a que está a
    // scanear é outra. Antes, a vista ficava na morta indefinidamente.
    const sessions = [
      session({ watch_session: "morta", live: false, runner_state: "stopped" }),
      session({ watch_session: "viva", live: true, runner_state: "running" }),
    ];
    expect(autoSelect(sessions, "morta", false)).toBe("viva");
  });

  it("não tira a vista de uma sessão viva", () => {
    const sessions = [
      session({ watch_session: "a", live: true, runner_state: "running" }),
      session({ watch_session: "b", live: true, runner_state: "running" }),
    ];
    expect(autoSelect(sessions, "b", false)).toBe("b");
  });

  it("respeita uma sessão parada escolhida à mão", () => {
    // Ver o histórico de uma sessão antiga é legítimo — a página não deve
    // saltar de lá só porque existe outra a correr.
    const sessions = [
      session({ watch_session: "antiga", live: false, runner_state: "stopped" }),
      session({ watch_session: "viva", live: true, runner_state: "running" }),
    ];
    expect(autoSelect(sessions, "antiga", true)).toBe("antiga");
  });

  it("uma sessão em pausa conta como viva", () => {
    // Em pausa está deliberadamente parada, não avariada: continua a bater e
    // é retomável. Saltar dela para outra seria contrariar o utilizador.
    const sessions = [
      session({ watch_session: "pausada", live: true, runner_state: "paused" }),
      session({ watch_session: "outra", live: true, runner_state: "running" }),
    ];
    expect(autoSelect(sessions, "pausada", false)).toBe("pausada");
  });

  it("escolhe uma viva do CLI, que não tem runner_state", () => {
    const sessions = [
      session({ watch_session: "morta", live: false, runner_state: "stopped" }),
      session({ watch_session: "cli", live: true, runner_state: null }),
    ];
    expect(autoSelect(sessions, "morta", false)).toBe("cli");
  });
});
