import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { ReportsPage } from "@/pages/ReportsPage";

/**
 * Apagar avaliações da base de dados a partir da consola.
 *
 * As avaliações acumulam-se sem limite — cada scan fica guardado e não havia
 * como remover nenhum sem ir à base de dados à mão. O que se fixa aqui é que
 * o botão chega mesmo ao `DELETE`, e que a confirmação é uma barreira real:
 * uma versão que apague sem perguntar destrói dados irrecuperáveis a um
 * clique de distância, e isso não daria erro nenhum a assinalar a regressão.
 */

const SCAN = {
  id: "scan-1",
  target_name: "apache-httpd",
  input_path: "/etc/apache2/apache2.conf",
  global_base_score: 8.1,
  global_temporal_score: 7.1,
  severity: "High",
  total_issues: 12,
  total_chains: 3,
  timestamp: "2026-08-12T10:00:00Z",
};

function renderPage() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <ReportsPage />
    </QueryClientProvider>,
  );
}

describe("Reports — apagar uma avaliação", () => {
  let deleted: string[] = [];

  beforeEach(() => {
    deleted = [];
    vi.stubGlobal("fetch", vi.fn(async (url: string, init?: RequestInit) => {
      if (init?.method === "DELETE") {
        deleted.push(String(url));
        return new Response(null, { status: 204 });
      }
      return new Response(JSON.stringify([SCAN]), {
        status: 200, headers: { "Content-Type": "application/json" },
      });
    }));
  });

  afterEach(() => {
    vi.unstubAllGlobals();
    vi.restoreAllMocks();
  });

  it("apaga a avaliação depois de confirmada", async () => {
    vi.spyOn(window, "confirm").mockReturnValue(true);
    renderPage();

    const btn = await screen.findByRole("button", { name: /delete/i });
    await userEvent.click(btn);

    await waitFor(() => expect(deleted).toHaveLength(1));
    expect(deleted[0]).toContain("/api/v1/scans/scan-1");
  });

  it("não apaga nada se a confirmação for recusada", async () => {
    vi.spyOn(window, "confirm").mockReturnValue(false);
    renderPage();

    const btn = await screen.findByRole("button", { name: /delete/i });
    await userEvent.click(btn);

    // Uma espera real, e não um `expect` imediato: sem ela o teste passaria
    // mesmo que o pedido estivesse a caminho, apenas por chegar mais tarde.
    await new Promise((r) => setTimeout(r, 50));
    expect(deleted).toHaveLength(0);
  });

  it("avisa quando o servidor recusa apagar", async () => {
    vi.spyOn(window, "confirm").mockReturnValue(true);
    vi.stubGlobal("fetch", vi.fn(async (_url: string, init?: RequestInit) => {
      if (init?.method === "DELETE") {
        return new Response(JSON.stringify({ detail: "Scan not found" }), {
          status: 404, headers: { "Content-Type": "application/json" },
        });
      }
      return new Response(JSON.stringify([SCAN]), {
        status: 200, headers: { "Content-Type": "application/json" },
      });
    }));

    renderPage();
    await userEvent.click(await screen.findByRole("button", { name: /delete/i }));

    // Uma falha silenciosa era indistinguível de não ter carregado no botão.
    expect(await screen.findByText(/Scan not found/)).toBeInTheDocument();
  });
});
