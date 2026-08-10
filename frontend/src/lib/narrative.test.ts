import { describe, expect, it } from "vitest";
import { parseNarrative } from "./narrative";

/**
 * O `narrative` é uma string JSON guardada na base de dados, e nem todas as
 * regras a têm. O painel usa o resultado para decidir entre mostrar a
 * justificação de cada métrica e dizer que a regra não tem narrativa — são
 * mensagens diferentes, e confundi-las foi o que fez parecer que a informação
 * se tinha perdido.
 */
describe("parseNarrative", () => {
  it("lê a justificação de cada métrica", () => {
    const raw = JSON.stringify({
      description: "ServerTokens Full expõe a versão do Apache.",
      potential_impact: ["Facilita ataques dirigidos"],
      metric_justifications: { ac: "AC=L: trivialmente explorável", c: "C=P" },
    });
    const n = parseNarrative(raw);
    expect(n?.metric_justifications?.ac).toContain("AC=L");
    expect(n?.potential_impact).toHaveLength(1);
  });

  it("trata uma narrativa vazia como inexistente", () => {
    // É o valor por omissão na coluna: faz parse, mas não tem nada para
    // mostrar. Devolver um objecto vazio faria o painel prometer detalhe
    // que não existe.
    expect(parseNarrative("{}")).toBeNull();
  });

  it("não rebenta com JSON inválido", () => {
    // Uma regra mal formada não pode impedir de ver as outras.
    expect(parseNarrative("{nao é json")).toBeNull();
  });

  it("aceita ausência de narrativa", () => {
    expect(parseNarrative("")).toBeNull();
    expect(parseNarrative(null)).toBeNull();
    expect(parseNarrative(undefined)).toBeNull();
  });

  it("ignora um JSON que não seja objecto", () => {
    expect(parseNarrative("[1,2]")).toBeNull();
    expect(parseNarrative('"texto"')).toBeNull();
  });
});
