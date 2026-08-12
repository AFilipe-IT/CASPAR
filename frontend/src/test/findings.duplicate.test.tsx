import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { FindingsTable } from "@/components/dashboard/FindingsTable";
import type { Misconfiguration } from "@/api/types";

/**
 * A mesma regra violada em sítios diferentes tem de dar linhas diferentes.
 *
 * O `id` de um achado é o da *regra*, não o da ocorrência: um `Options` mal
 * posto em dois `<Directory>` chega com o mesmo `id` duas vezes. Como a tabela
 * usava esse campo como chave de React, as ocorrências repetidas colidiam e
 * desapareciam da lista — o cabeçalho ficava lá e o corpo perdia linhas, com o
 * contador do evento a dizer "12 issues" por cima de uma tabela mais curta.
 *
 * Num scan real do /etc/apache2/apache2.conf são 10 ids distintos para 12
 * achados, e é essa a forma reproduzida aqui.
 */

function finding(id: string, directive: string, score: number): Misconfiguration {
  return {
    id,
    directive,
    temporal_score: score,
    base_score: score,
    cves: [],
    target_name: "apache-httpd",
    bad_value: "", good_value: "", ac: "L", c: "P", i: "P", a: "N",
    av: "L", au: "N", gel: "H", grl: "O", cce_id: "", cis_section: "",
    justification: "", recommendation: "", rule_type: "", required_when: "",
    expected_value_prefix: "", detected_in_scan: true, source_directive: null,
    version_amplification: 1, version_risk_note: "", narrative: "",
    confidence: 1,
  } as Misconfiguration;
}

describe("FindingsTable — ocorrências com o mesmo id de regra", () => {
  it("mostra as duas ocorrências da mesma regra", () => {
    const rows = [
      { finding: finding("rule-options", "Options", 5.4), service: "apache-httpd" },
      { finding: finding("rule-options", "Options", 5.4), service: "apache-httpd" },
    ];

    render(<FindingsTable rows={rows} />);

    // Duas ocorrências → duas linhas. Com o id da regra como chave ficava uma.
    expect(screen.getAllByText("Options")).toHaveLength(2);
  });

  it("mostra os 12 achados quando só há 10 ids distintos", () => {
    const rows = [
      ...Array.from({ length: 10 }, (_, n) =>
        ({ finding: finding(`rule-${n}`, `Directive${n}`, 9 - n * 0.5), service: "apache-httpd" })),
      { finding: finding("rule-0", "Directive0", 9), service: "apache-httpd" },
      { finding: finding("rule-1", "Directive1", 8.5), service: "apache-httpd" },
    ];

    render(<FindingsTable rows={rows} />);

    // O corpo tem de ter tantas linhas quantos os achados — é o número que o
    // cabeçalho do evento anuncia.
    const body = document.querySelectorAll("tbody tr");
    expect(body).toHaveLength(12);
  });
});
