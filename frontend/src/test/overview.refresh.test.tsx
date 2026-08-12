import { describe, expect, it, vi, beforeEach, afterEach } from "vitest";
import { renderHook, waitFor } from "@testing-library/react";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import type { ReactNode } from "react";
import { useScans } from "@/api/scans";
import { useHostsRollup } from "@/api/hosts";

/**
 * A Home tem de acompanhar o sistema sozinha.
 *
 * Sem `refetchInterval` estas hooks só iam à rede ao montar: bastava deixar o
 * separador aberto para os números envelhecerem em silêncio, com ar de dados
 * estáticos. Como isso não dá erro nenhum — a página continua a pintar,
 * apenas com números velhos — a regressão volta sem ninguém dar por ela se não
 * ficar presa aqui.
 *
 * O que se mede é o número de chamadas à rede ao longo do tempo, e não a
 * presença da opção: uma asserção sobre o objecto de configuração passaria à
 * mesma se o `useQuery` deixasse de o receber.
 */

const POLL_MS = 60_000;

function wrapper({ children }: { children: ReactNode }) {
  // `retry: false` para que uma falha não se disfarce de nova tentativa e
  // inflacione a contagem de chamadas.
  const qc = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return <QueryClientProvider client={qc}>{children}</QueryClientProvider>;
}

describe("Home / Overview auto-refresh", () => {
  let calls = 0;

  beforeEach(() => {
    calls = 0;
    vi.stubGlobal("fetch", vi.fn(async () => {
      calls += 1;
      return new Response("[]", {
        status: 200, headers: { "Content-Type": "application/json" },
      });
    }));
    // `shouldAdvanceTime` porque o `waitFor` da Testing Library faz polling com
    // temporizadores reais: com timers falsos totalmente parados, a primeira
    // espera fica bloqueada e o teste rebenta por timeout em vez de medir o que
    // interessa.
    vi.useFakeTimers({ shouldAdvanceTime: true });
  });

  afterEach(() => {
    vi.useRealTimers();
    vi.unstubAllGlobals();
  });

  it("volta a pedir os scans da Home a cada minuto", async () => {
    renderHook(() => useScans({ limit: 50 }, true), { wrapper });
    await waitFor(() => expect(calls).toBe(1));

    await vi.advanceTimersByTimeAsync(POLL_MS + 1_000);
    expect(calls).toBe(2);

    await vi.advanceTimersByTimeAsync(POLL_MS + 1_000);
    expect(calls).toBe(3);
  });

  it("volta a pedir o rollup de hosts a cada minuto", async () => {
    renderHook(() => useHostsRollup(), { wrapper });
    await waitFor(() => expect(calls).toBe(1));

    await vi.advanceTimersByTimeAsync(POLL_MS + 1_000);
    expect(calls).toBe(2);
  });

  it("não recarrega o histórico do Assessment por baixo dos pés", async () => {
    // A mesma hook sem `live`: ali o utilizador está a filtrar à mão e uma
    // recarga espontânea seria pior que útil.
    renderHook(() => useScans({ limit: 50 }), { wrapper });
    await waitFor(() => expect(calls).toBe(1));

    await vi.advanceTimersByTimeAsync(POLL_MS * 3);
    expect(calls).toBe(1);
  });
});
