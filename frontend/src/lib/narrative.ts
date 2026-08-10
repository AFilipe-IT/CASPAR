/**
 * O `narrative` chega como uma *string* JSON (é assim que fica guardado na
 * coluna `narrative` da base de dados, não como objecto). Vem do pipeline LLM
 * da fase de build e traz a descrição, o impacto, o cenário de exploração e —
 * o que mais falta na consola — a justificação métrica a métrica.
 *
 * Nem todas as regras têm narrativa: as curadas à mão e as anteriores ao
 * pipeline trazem `"{}"`. Daí devolver-se sempre um objecto com campos
 * opcionais, e nunca deixar um JSON inválido rebentar a página — uma regra
 * mal formada não deve impedir de ver as outras.
 */

export interface MetricJustifications {
  av?: string;
  au?: string;
  ac?: string;
  c?: string;
  i?: string;
  a?: string;
  gel?: string;
  grl?: string;
}

export interface ExploitationScenario {
  prerequisites?: string[];
  example?: string;
  result?: string;
}

export interface Narrative {
  description?: string;
  potential_impact?: string[];
  exploitation_scenario?: ExploitationScenario;
  metric_justifications?: MetricJustifications;
}

export function parseNarrative(raw: string | null | undefined): Narrative | null {
  if (!raw) return null;
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return null;
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return null;
  const n = parsed as Narrative;
  // `"{}"` faz parse com sucesso mas não tem nada para mostrar: quem chama
  // quer saber "há narrativa?", não "o JSON era válido?".
  const hasContent =
    !!n.description ||
    (n.potential_impact?.length ?? 0) > 0 ||
    !!n.exploitation_scenario ||
    Object.keys(n.metric_justifications ?? {}).length > 0;
  return hasContent ? n : null;
}

/** Nome legível de cada métrica CCSS, para as etiquetas do painel. */
export const METRIC_LABELS: Record<keyof MetricJustifications, string> = {
  av: "Access Vector",
  au: "Authentication",
  ac: "Access Complexity",
  c: "Confidentiality",
  i: "Integrity",
  a: "Availability",
  gel: "General Exploit Level",
  grl: "General Remediation Level",
};

export const METRIC_ORDER: (keyof MetricJustifications)[] = [
  "av",
  "au",
  "ac",
  "c",
  "i",
  "a",
  "gel",
  "grl",
];
