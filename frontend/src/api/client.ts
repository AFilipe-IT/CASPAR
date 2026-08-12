// Thin fetch wrapper. All CVM business logic lives server-side — this file
// only knows how to talk HTTP to /api/v1, never interprets scores or rules.
const BASE_URL = "/api/v1";

export class ApiError extends Error {
  status: number;
  constructor(status: number, message: string) {
    super(message);
    this.status = status;
    this.name = "ApiError";
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const res = await fetch(`${BASE_URL}${path}`, {
    ...init,
    headers: {
      "Content-Type": "application/json",
      ...init?.headers,
    },
  });

  if (!res.ok) {
    let detail = res.statusText;
    try {
      const body = await res.json();
      detail = body.detail ?? detail;
    } catch {
      // response had no JSON body — keep statusText
    }
    throw new ApiError(res.status, detail);
  }

  if (res.status === 204) return undefined as T;
  return res.json() as Promise<T>;
}

/**
 * Cadência das vistas que mostram o estado actual do sistema (a Home, sobre-
 * tudo). Não é uma vista live como o Watch, que segue uma sessão ao segundo;
 * é um retrato que não pode estar velho sem se dar por isso.
 *
 * Sem isto a Home só ia buscar dados ao montar: bastava deixar o separador
 * aberto para os números ficarem a envelhecer em silêncio, com ar de dados
 * estáticos — e é isso que parecem quando uma avaliação corre noutro sítio e
 * o painel continua a dizer o mesmo.
 *
 * `staleTime` acompanha o intervalo para que uma navegação de volta à Home
 * mostre o que está em cache em vez de piscar, mas nunca sirva algo mais
 * velho do que um ciclo.
 */
export const OVERVIEW_POLL_MS = 60_000;
export const overviewQueryOptions = {
  refetchInterval: OVERVIEW_POLL_MS,
  staleTime: OVERVIEW_POLL_MS,
  // Voltar ao separador é o momento em que um número velho mais engana:
  // esteve escondido e o utilizador presume que entretanto acompanhou.
  refetchOnWindowFocus: true,
} as const;

export const api = {
  get: <T>(path: string) => request<T>(path),
  post: <T>(path: string, body?: unknown) =>
    request<T>(path, { method: "POST", body: body ? JSON.stringify(body) : undefined }),
  delete: <T>(path: string) => request<T>(path, { method: "DELETE" }),
};
