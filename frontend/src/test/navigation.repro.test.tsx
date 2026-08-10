import { describe, expect, it, vi, beforeEach } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { MemoryRouter } from "react-router-dom";
import { App } from "@/App";
import { ThemeProvider } from "@/context/ThemeContext";
import { PreferencesProvider } from "@/context/PreferencesContext";

/**
 * Reprodução: navegar para outro menu e voltar ao principal deixa o ecrã
 * escuro, e a aplicação não recupera mesmo com a URL correcta.
 */

function renderApp(initial = "/") {
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  });
  // A mesma pilha de providers do main.tsx — sem ela o teste rebenta por
  // razões suas e não pelas da aplicação.
  return render(
    <ThemeProvider>
      <PreferencesProvider>
        <QueryClientProvider client={qc}>
          <MemoryRouter initialEntries={[initial]}>
            <App />
          </MemoryRouter>
        </QueryClientProvider>
      </PreferencesProvider>
    </ThemeProvider>,
  );
}

describe("navegação entre menus", () => {
  beforeEach(() => {
    vi.restoreAllMocks();
  });

  it("volta ao Dashboard depois de visitar outro menu", async () => {
    // A API responde sempre com lista vazia: o objectivo é a navegação, não os dados.
    vi.stubGlobal(
      "fetch",
      vi.fn(async () =>
        new Response(JSON.stringify([]), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
      ),
    );

    const user = userEvent.setup();
    renderApp("/");

    await waitFor(() => expect(screen.getByRole("navigation")).toBeInTheDocument());

    const nav = screen.getByRole("navigation");
    const links = [...nav.querySelectorAll("a")].map((a) => a.getAttribute("href"));

    // Visita cada menu e volta sempre ao principal. Se algum deixar a app
    // por render, o shell desaparece e este ciclo falha no menu seguinte.
    for (const href of links) {
      if (!href || href === "/") continue;
      const link = nav.querySelector(`a[href="${href}"]`);
      if (!link) continue;
      await user.click(link);
      const home = nav.querySelector('a[href="/"]');
      expect(home, `sidebar desapareceu depois de visitar ${href}`).toBeTruthy();
      await user.click(home!);
      await waitFor(() =>
        expect(
          screen.getByRole("navigation"),
          `shell perdido ao voltar de ${href}`,
        ).toBeInTheDocument(),
      );
    }
  });
});
