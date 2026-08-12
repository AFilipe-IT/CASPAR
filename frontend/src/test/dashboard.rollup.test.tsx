import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { App } from "@/App";
import { ThemeProvider } from "@/context/ThemeContext";
import { PreferencesProvider } from "@/context/PreferencesContext";

/**
 * Reprodução: `/app` abria em branco enquanto as outras páginas funcionavam.
 *
 * `GET /hosts` devolve `scans` como a LISTA de alvos, mas o tipo declarava
 * `number` e o painel passava-a directamente a um KpiTile. Renderizar um
 * objecto como filho de React é o erro #31, que rebenta a árvore toda.
 *
 * O teste de navegação existente não apanhava isto porque respondia `[]` a
 * tudo: um array vazio renderiza sem se queixar. É preciso o payload real,
 * com linhas lá dentro, para o erro aparecer.
 */

const ROLLUP = {
  scans: [
    { target: "apache-httpd", input: "/etc/apache2", score: 7.1,
      severity: "High", issues: 17, chains: 9 },
    { target: "nginx", input: "/etc/nginx", score: 6.0,
      severity: "Medium", issues: 7, chains: 2 },
  ],
  total_issues: 9999,   // histórico acumulado, deliberadamente absurdo
  total_chains: 11,
  worst_score: 7.1,
  worst_target: "apache-httpd",
  average_score: 6.6,
};

function renderApp() {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  return render(
    <ThemeProvider>
      <PreferencesProvider>
        <QueryClientProvider client={qc}>
          <MemoryRouter initialEntries={["/"]}>
            <App />
          </MemoryRouter>
        </QueryClientProvider>
      </PreferencesProvider>
    </ThemeProvider>,
  );
}

describe("Dashboard com o payload real de /hosts", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string) => {
        const body = String(url).includes("/hosts") ? ROLLUP : [];
        return new Response(JSON.stringify(body), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
      }),
    );
  });

  it("renderiza sem rebentar quando `scans` traz linhas", async () => {
    renderApp();
    await waitFor(() => {
      expect(screen.getByText("Home / Overview")).toBeInTheDocument();
    });
    // A ErrorBoundary mostra esta mensagem quando a página rebenta; se
    // aparecer, o KpiTile voltou a receber um objecto.
    expect(screen.queryByText(/Erro ao renderizar/i)).not.toBeInTheDocument();
  });

  it("conta problemas em aberto, não o histórico acumulado", async () => {
    // `total_issues` do rollup soma o histórico todo (aqui 9999); o KPI tem de
    // descrever o estado actual, vindo dos scans mais recentes.
    renderApp();
    // O KPI passou a chamar-se "Open findings" na passagem ao novo desenho —
    // é o mesmo número e a mesma regra, e "finding" é o termo que o resto da
    // consola usa. O que este teste guarda continua a ser o 9999.
    await waitFor(() => {
      expect(screen.getAllByText("Open findings").length).toBeGreaterThan(0);
    });
    expect(screen.queryByText("9999")).not.toBeInTheDocument();
  });
});
