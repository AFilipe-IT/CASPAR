import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { App } from "@/App";
import { ThemeProvider } from "@/context/ThemeContext";
import { PreferencesProvider } from "@/context/PreferencesContext";

/**
 * A página do Watch mostrava um score global e mais nada: não havia como
 * limpar sessões antigas, nem como saber que directivas produziram aquele
 * número. Estes testes cobrem as duas coisas.
 */

const RUNNING = {
  watch_session: "sess-running", scan_id: "scan-2",
  target_name: "apache-httpd", input_path: "/etc/apache2/apache2.conf",
  host_id: null, global_temporal_score: 8.7, severity: "High",
  total_issues: 12, total_chains: 3, watch_interval: 2,
  timestamp: "2026-08-10T10:00:00", last_seen: "2026-08-10T10:00:00",
  live: true, runner_state: "running", error: null,
};

const STOPPED = {
  ...RUNNING, watch_session: "sess-stopped", scan_id: "scan-1",
  live: false, runner_state: "stopped",
};

const DETAIL = {
  watch_session: "sess-running",
  latest: RUNNING,
  events: [
    { scan_id: "scan-2", timestamp: "2026-08-10T10:00:00",
      target_name: "apache-httpd", input_path: "/etc/apache2/apache2.conf",
      global_temporal_score: 8.7, severity: "High",
      total_issues: 12, total_chains: 3, watch_interval: 2 },
  ],
  sparkline: "▇", first_score: 8.7, last_score: 8.7,
};

const SCAN = {
  id: "scan-2", scan_id: "scan-2", target_name: "apache-httpd",
  input_path: "/etc/apache2/apache2.conf", global_temporal_score: 8.7,
  severity: "High", total_directives_scanned: 41, detected_version: "2.4.52",
  issues: [
    { id: "f-user", directive: "User", bad_value: "root",
      temporal_score: 8.7, base_score: 8.7, description: "Runs as root",
      impact: "Full host compromise", remediation: "User www-data",
      severity: "High", cves: [], vector: "" },
    { id: "f-tokens", directive: "ServerTokens", bad_value: "Full",
      temporal_score: 5.3, base_score: 5.3, description: "Leaks version",
      impact: "Recon", remediation: "ServerTokens Prod",
      severity: "Medium", cves: [], vector: "" },
  ],
  chains: [],
};

function jsonFor(url: string): unknown {
  const u = String(url);
  if (u.includes("/watch/sess-")) return DETAIL;
  if (u.includes("/watch")) return [STOPPED, RUNNING];
  if (u.includes("/scans/scan-2")) return SCAN;
  return [];
}

function renderWatch() {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return render(
    <ThemeProvider>
      <PreferencesProvider>
        <QueryClientProvider client={qc}>
          <MemoryRouter initialEntries={["/watch"]}>
            <App />
          </MemoryRouter>
        </QueryClientProvider>
      </PreferencesProvider>
    </ThemeProvider>,
  );
}

describe("WatchPage", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string) =>
        new Response(JSON.stringify(jsonFor(url)), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
      ),
    );
  });

  it("oferece limpar as sessões paradas, contando só essas", async () => {
    renderWatch();
    // Duas sessões, uma viva: a limpeza tem de anunciar 1, não 2. Apagar uma
    // sessão viva deixaria o loop a escrever para um histórico apagado.
    await waitFor(() => {
      expect(screen.getByText("Clear 1 stopped")).toBeInTheDocument();
    });
  });

  it("abre um evento e mostra as directivas por trás do score", async () => {
    renderWatch();
    // A linha do evento é o único sítio onde o score aparece com a severidade
    // ao lado; abri-la tem de trazer as directivas concretas.
    const row = await screen.findByRole("button", { name: /12 issues/ });
    await userEvent.click(row);

    await waitFor(() => {
      expect(screen.getByText("User")).toBeInTheDocument();
    });
    expect(screen.getByText("ServerTokens")).toBeInTheDocument();
    expect(screen.getByText("41 directives scanned")).toBeInTheDocument();
  });
});
