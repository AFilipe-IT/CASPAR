import { describe, expect, it } from "vitest";
import { render, screen } from "@testing-library/react";
import { FindingDetail } from "@/components/knowledge/FindingDetail";
import type { Misconfiguration } from "@/api/types";

/**
 * "Set ServerTokens to Prod (currently OS)" diz o quê, não onde.
 *
 * O `--dashboard live` mostrava a linha da configuração; esta consola tinha os
 * dados (`source_directive.source_file` + `line_number` chegam na resposta da
 * API) e descartava-os. Num apache com a configuração espalhada por
 * `apache2.conf`, `conf-enabled/` e `mods-enabled/`, saber que directiva
 * corrigir sem saber em que ficheiro é meio trabalho.
 */

function finding(source: Partial<Misconfiguration["source_directive"]> | null): Misconfiguration {
  return {
    id: "r1",
    directive: "ServerTokens",
    bad_value: "OS",
    good_value: "Prod",
    recommendation: "Set 'ServerTokens Prod' to expose only the product name.",
    temporal_score: 7.1,
    base_score: 7.1,
    av: "L", au: "N", ac: "L", c: "P", i: "N", a: "N", gel: "M", grl: "H",
    version_amplification: 1,
    cves: [],
    source_directive: source,
    // Só os campos que o componente lê; o resto de `Misconfiguration` seria ruído.
  } as unknown as Misconfiguration;
}

describe("FindingDetail — onde está a misconfiguration", () => {
  it("mostra o ficheiro, a linha e o texto tal como está na configuração", () => {
    render(
      <FindingDetail
        rule={finding({
          name: "ServerTokens",
          value: "OS",
          context: "global",
          source_file: "/etc/apache2/conf-enabled/security.conf",
          line_number: 25,
        })}
      />,
    );

    expect(
      screen.getByText("/etc/apache2/conf-enabled/security.conf:25"),
    ).toBeInTheDocument();
    // A linha reconstruída, para se reconhecer no ficheiro ao abri-lo.
    expect(screen.getByText("ServerTokens OS")).toBeInTheDocument();
    expect(screen.getByText("25")).toBeInTheDocument();
  });

  it("mostra o contexto quando a directiva não é global", () => {
    // Num VirtualHost ou <Directory>, o caminho e a linha não chegam: a mesma
    // directiva aparece várias vezes no mesmo ficheiro com sentidos diferentes.
    render(
      <FindingDetail
        rule={finding({
          name: "Options",
          value: "Indexes FollowSymLinks",
          context: "Directory /var/www/html",
          source_file: "/etc/apache2/apache2.conf",
          line_number: 160,
        })}
      />,
    );

    expect(screen.getByText("Directory /var/www/html")).toBeInTheDocument();
  });

  it("omite a secção quando o achado não traz origem", () => {
    // Regras que não vêm de uma directiva presente no ficheiro (uma directiva
    // em falta, por exemplo) não têm linha nenhuma para apontar — uma secção
    // vazia seria pior do que nenhuma.
    render(<FindingDetail rule={finding(null)} />);

    expect(screen.queryByText("Where it is")).not.toBeInTheDocument();
    // O resto do detalhe continua lá.
    expect(screen.getByText("How to remediate")).toBeInTheDocument();
  });
});
