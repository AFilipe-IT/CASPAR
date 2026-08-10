import { describe, expect, it } from "vitest";
import { summarise } from "./dashboard";
import type { Misconfiguration, ScanResult } from "@/api/types";

/**
 * Os CVEs vinham na resposta da API e não apareciam em lado nenhum do painel.
 *
 * Mostrá-los no detalhe de um achado não chegava: na prática só as directivas
 * de TLS trazem CVE, e essas têm scores baixos — ficavam sempre fora do corte
 * por score das Top Findings, e não havia sinal nenhum de que existiam. Daí o
 * KPI a contar CVEs distintos.
 *
 * Os cenários abaixo são os da base de dados real: os achados graves
 * (`User=root` a 8.7) não têm CVE, os que têm estão a 4.7, e o mesmo alvo
 * aparece repetido porque `target_name` não é único.
 */

function issue(
  id: string, directive: string, score: number, cves: string[] = [],
): Misconfiguration {
  return {
    id, directive, bad_value: "x", temporal_score: score, base_score: score,
    description: "d", impact: "i", remediation: "r",
    severity: score >= 7 ? "High" : "Medium", cves,
    // Só os campos que a agregação lê; o resto de `Misconfiguration` é
    // irrelevante aqui e enchia o teste de ruído.
  } as unknown as Misconfiguration;
}

function scan(
  scanId: string, target: string, input: string, issues: Misconfiguration[],
): ScanResult {
  return {
    scan_id: scanId, target_name: target, input_path: input, issues,
    chains: [], global_temporal_score: issues[0]?.temporal_score ?? 0,
    total_directives_scanned: 34,
  } as unknown as ScanResult;
}

describe("summarise", () => {
  it("conta CVEs distintos, não achados com CVE", () => {
    // Três achados com CVE, dois CVEs distintos: o mesmo CVE-2011-3389
    // reaparece em cada configuração TLS avaliada, e contá-lo duas vezes
    // inflacionaria o KPI.
    const s = summarise([
      scan("s1", "apache-httpd", "/etc/apache2/apache2.conf", [
        issue("i1", "User", 8.7),
        issue("i6", "SSLProtocol", 4.7, ["CVE-2011-3389"]),
        issue("i7", "SSLCompression", 4.7, ["CVE-2012-4929"]),
      ]),
      scan("s2", "apache-httpd", "/tmp/copia/httpd.conf", [
        issue("i8", "SSLProtocol", 4.7, ["CVE-2011-3389"]),
      ]),
    ]);
    expect(s.cveCount).toBe(2);
  });

  it("junta os achados com CVE numa lista própria, apesar do score baixo", () => {
    // O caso real: os achados graves não têm CVE e os que têm ficam abaixo do
    // corte por score das Top Findings. Sem lista própria, o KPI dizia que
    // existiam CVEs e não havia como chegar a nenhum deles.
    const s = summarise([
      scan("s1", "apache-httpd", "/etc/apache2/apache2.conf", [
        issue("i1", "User", 8.7),
        issue("i2", "Group", 7.9),
        issue("i3", "ServerTokens", 7.1),
        issue("i4", "TraceEnable", 6.0),
        issue("i5", "ServerSignature", 5.5),
        issue("i6", "Header", 5.2),
        issue("i7", "SSLProtocol", 4.7, ["CVE-2011-3389"]),
      ]),
    ]);
    // Fora do top por score...
    expect(s.topFindings.map((r) => r.finding.directive)).not.toContain("SSLProtocol");
    // ...mas presente na lista que existe precisamente para isso.
    expect(s.cveFindings.map((r) => r.finding.directive)).toEqual(["SSLProtocol"]);
  });

  it("deixa a lista de CVEs vazia quando não há nenhum", () => {
    // O painel só aparece quando há alguma coisa para mostrar.
    const s = summarise([
      scan("s1", "apache-httpd", "/etc/apache2/apache2.conf", [issue("i1", "User", 8.7)]),
    ]);
    expect(s.cveFindings).toEqual([]);
  });

  it("não conta CVE nenhum quando os achados não os têm", () => {
    const s = summarise([
      scan("s1", "apache-httpd", "/etc/apache2/apache2.conf", [
        issue("i1", "User", 8.7),
        issue("i2", "Group", 7.9),
      ]),
    ]);
    expect(s.cveCount).toBe(0);
  });

  it("deduplica a mesma directiva repetida entre configurações do mesmo alvo", () => {
    // `target_name` não é único: o apache do sistema, uma fixture e uma cópia
    // de trabalho partilham-no. As linhas do topo gastavam-se a mostrar
    // "User" três vezes em vez de três problemas distintos.
    const s = summarise([
      scan("s1", "apache-httpd", "/etc/apache2/apache2.conf", [issue("a", "User", 8.7)]),
      scan("s2", "apache-httpd", "/tmp/x/httpd.conf", [issue("b", "User", 8.7)]),
      scan("s3", "apache-httpd", "/tmp/y/httpd.conf", [
        issue("c", "User", 8.7), issue("d", "Group", 7.9),
      ]),
    ]);
    const shown = s.topFindings.map((r) => r.finding.directive);
    expect(shown).toEqual(["User", "Group"]);
  });

  it("mantém a mesma directiva quando os serviços são diferentes", () => {
    // A deduplicação é por directiva E serviço: `ssl_protocols` no nginx e no
    // apache são dois problemas, não uma repetição.
    const s = summarise([
      scan("s1", "nginx", "/etc/nginx/nginx.conf", [issue("a", "ssl_protocols", 5.0)]),
      scan("s2", "apache-httpd", "/etc/apache2/apache2.conf", [issue("b", "ssl_protocols", 5.0)]),
    ]);
    expect(s.topFindings).toHaveLength(2);
  });

  it("conta problemas em aberto pelo estado actual, não pelo histórico", () => {
    const s = summarise([
      scan("s1", "nginx", "/etc/nginx/nginx.conf", [
        issue("a", "ssl_protocols", 5.0), issue("b", "server_tokens", 4.0),
      ]),
    ]);
    expect(s.openIssues).toBe(2);
  });

  it("conta como críticos os achados a partir de 9.0", () => {
    // Contava dentro das Top Findings, que já estão cortadas — o máximo
    // possível era o tamanho do corte, e dava 0 mesmo com um 10.0 na base.
    const s = summarise([
      scan("s1", "nginx", "/etc/nginx/nginx.conf", [
        issue("a", "d1", 9.8), issue("b", "d2", 8.9), issue("c", "d3", 9.0),
      ]),
    ]);
    expect(s.criticalFindings).toBe(2);
  });
});
