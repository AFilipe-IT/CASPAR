import { describe, expect, it, vi, afterEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { WatchEventDetail } from "@/components/watch/WatchEventDetail";
import detail from "./fixtures-scan-detail.json";

/**
 * O detalhe de um evento do watch, com a resposta real da API.
 *
 * O utilizador via o cabeçalho dizer "12 issues" e a tabela por baixo vazia —
 * só o cabeçalho `Severity / Finding / Service`, sem linha nenhuma. A fixture
 * é a resposta verdadeira de `GET /scans/{id}` para um evento de uma sessão
 * real (12 achados, 8 cadeias, 10 ids distintos), para o teste falhar pelas
 * mesmas razões que a consola falharia.
 */

function renderDetail() {
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={qc}>
      <WatchEventDetail scanId={(detail as { scan_id: string }).scan_id} />
    </QueryClientProvider>,
  );
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("WatchEventDetail — achados de um evento", () => {
  it("mostra uma linha por achado, tantas quantas o cabeçalho anuncia", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify(detail), {
      status: 200, headers: { "Content-Type": "application/json" },
    })));

    renderDetail();

    // O contador do cabeçalho e a tabela têm de concordar: era exactamente aí
    // que a consola se contradizia.
    expect(await screen.findByText("12 issues")).toBeInTheDocument();
    await waitFor(() => {
      expect(document.querySelectorAll("tbody tr")).toHaveLength(12);
    });
  });

  it("põe o achado de maior score na primeira linha", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response(JSON.stringify(detail), {
      status: 200, headers: { "Content-Type": "application/json" },
    })));

    renderDetail();

    await waitFor(() => expect(document.querySelectorAll("tbody tr").length).toBeGreaterThan(0));

    // A primeira linha é a que fixa o score global — é a resposta a "porque é
    // que isto não desce?".
    const issues = (detail as { issues: { directive: string; temporal_score: number }[] }).issues;
    const worst = [...issues].sort((a, b) => b.temporal_score - a.temporal_score)[0];
    const firstRow = document.querySelector("tbody tr");
    expect(firstRow?.textContent).toContain(worst.directive);
  });
});
