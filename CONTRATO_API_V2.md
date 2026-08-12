# CVM v2 — Contrato de API

Documento de referência para o desenvolvimento da UI e do backend em paralelo.

**Regra que este documento existe para garantir:** a UI é construída sobre estas
formas de dados exactas. Não sobre estruturas inventadas que depois seja preciso
traduzir. Campos, tipos e valores de enum abaixo são normativos.

Base: `/api/v1`. Versão do contrato: `2.0`.
Estado: proposto — a Fase A (§3 do PLANO_V2) implementa a maior parte.

---

## 0. Conceitos e vocabulário

Três termos com significado preciso, usados em todo o contrato:

| Termo | Significado |
|---|---|
| **Dimensão** (*dimension*) | Um eixo de avaliação: configuração, permissões, exposição… Cada uma produz o seu indicador. |
| **Achado** (*finding*) | Um problema concreto detetado, com score CCSS e recomendação. Antes chamado `misconfiguration`. |
| **Cadeia** (*chain*) | Combinação de achados que, juntos, representam risco superior à soma das partes. |

### Escala de scores

`0.0` a `10.0`, uma casa decimal. **Mais alto = pior** (é uma medida de risco,
não de saúde). Faixas de severidade, alinhadas com o CCSS:

| Faixa | Rótulo | Token de cor |
|---|---|---|
| `0.0` | `None` | cinzento |
| `0.1 – 3.9` | `Low` | verde |
| `4.0 – 6.9` | `Medium` | amarelo |
| `7.0 – 8.9` | `High` | laranja |
| `9.0 – 10.0` | `Critical` | vermelho |

> **Aviso para a UI:** um score baixo é bom. Não pintar `2.0` de verde-vivo como
> se fosse uma meta atingida nem `9.5` como "95%". Não é uma percentagem.

### Estado de uma dimensão — o campo mais importante do contrato

Toda a dimensão traz um `status` com **três** valores possíveis, e a distinção
entre eles é obrigatória na UI:

| `status` | Significado | Como a UI o mostra |
|---|---|---|
| `assessed` | Foi avaliada e produziu resultados | Score e achados normalmente |
| `clean` | Foi avaliada e nada foi encontrado | Score `0.0`, marcada como limpa |
| `not_assessed` | **Não foi avaliada** | Estado neutro explícito. NUNCA `0.0`, NUNCA verde |

Confundir `not_assessed` com `clean` faz o produto mentir ao utilizador: um
sistema onde a análise de segredos nunca correu apareceria como um sistema sem
segredos expostos. Isto é um requisito, não uma preferência estética.

---

## 1. `GET /api/v1/posture` — a resposta principal

A visão global. Alimenta o ecrã inicial.

```json
{
  "overall": {
    "score": 8.5,
    "severity": "High",
    "delta": -0.4,
    "driver": {
      "kind": "finding",
      "dimension": "configuration",
      "label": "ServerTokens = Full",
      "finding_id": "3f2b1c9a-…"
    }
  },
  "coverage": {
    "dimensions_total": 6,
    "dimensions_assessed": 3,
    "percent": 50
  },
  "dimensions": [
    {
      "id": "configuration",
      "label": "Configuration",
      "status": "assessed",
      "score": 8.5,
      "severity": "High",
      "weight": 0.35,
      "findings_count": 23,
      "critical_count": 2,
      "delta": -0.4,
      "assessed_at": "2026-08-12T14:32:00Z"
    },
    {
      "id": "permissions",
      "label": "Identity & Permissions",
      "status": "assessed",
      "score": 6.2,
      "severity": "Medium",
      "weight": 0.30,
      "findings_count": 8,
      "critical_count": 0,
      "delta": 0.0,
      "assessed_at": "2026-08-12T14:32:00Z"
    },
    {
      "id": "exposure",
      "label": "Network Exposure",
      "status": "assessed",
      "score": 7.4,
      "severity": "High",
      "weight": 0.35,
      "findings_count": 11,
      "critical_count": 1,
      "delta": 1.2,
      "assessed_at": "2026-08-12T14:32:00Z"
    },
    { "id": "secrets",  "label": "Secrets",          "status": "not_assessed", "score": null, "severity": null, "weight": null, "findings_count": null, "critical_count": null, "delta": null, "assessed_at": null },
    { "id": "patch",    "label": "Patch Intelligence","status": "not_assessed", "score": null, "severity": null, "weight": null, "findings_count": null, "critical_count": null, "delta": null, "assessed_at": null },
    { "id": "hardening","label": "OS Hardening",      "status": "not_assessed", "score": null, "severity": null, "weight": null, "findings_count": null, "critical_count": null, "delta": null, "assessed_at": null }
  ],
  "chains": {
    "active_count": 6,
    "highest_score": 9.1,
    "exceeds_overall": true
  },
  "totals": {
    "targets_assessed": 12,
    "rules_evaluated": 514,
    "findings_open": 42,
    "critical_findings": 3,
    "related_cves": 6
  },
  "scoring_model": {
    "version": "2.0",
    "aggregation": "weighted",
    "missing_dimension_policy": "excluded",
    "weights_source": "declared"
  },
  "manifest": {
    "cvm_version": "2.0.0",
    "python": "3.12.3",
    "db_sha256": "f595efe56da0…",
    "scoring_model_version": "2.0"
  },
  "assessed_at": "2026-08-12T14:32:00Z"
}
```

**Notas normativas**

- `dimensions` traz **sempre as seis**, mesmo as não avaliadas. É a UI que
  decide como as apresenta, mas não pode fingir que não existem.
- Quando `status` é `not_assessed`, todos os campos numéricos vêm `null` — nunca
  `0`. A UI tem de tratar `null` como "não avaliado", não como zero.
- `delta` é a variação desde a avaliação anterior. `null` quando não há termo de
  comparação (primeira avaliação, ou mudança de versão do modelo de scoring).
  **`0.0` significa "estável"; `null` significa "não comparável".** São coisas
  diferentes e a UI não as pode confundir.
- `overall.driver` identifica o que produziu o número. `kind` é `"finding"` ou
  `"chain"`.
- `chains.exceeds_overall` é `true` quando uma cadeia pontua acima do indicador
  global. É um sinal de destaque: a UI deve chamar a atenção para ele.
- `missing_dimension_policy`: `"excluded"` (pesos renormalizados sobre as
  avaliadas) ou `"unknown"` (o global é declarado incompleto).

---

## 2. `GET /api/v1/dimensions/{id}` — detalhe de uma dimensão

`id` ∈ `configuration` | `permissions` | `exposure` | `secrets` | `patch` | `hardening`

```json
{
  "id": "permissions",
  "label": "Permissions",
  "status": "assessed",
  "score": 6.2,
  "severity": "Medium",
  "description": "File ownership, modes, SUID/SGID binaries and sudo policy.",
  "assessed_at": "2026-08-12T14:32:00Z",
  "severity_breakdown": {
    "Critical": 0, "High": 2, "Medium": 4, "Low": 2, "None": 0
  },
  "findings": [ /* ver §3 */ ],
  "trend": [
    { "at": "2026-08-10T09:00:00Z", "score": 7.1 },
    { "at": "2026-08-11T09:00:00Z", "score": 6.8 },
    { "at": "2026-08-12T14:32:00Z", "score": 6.2 }
  ]
}
```

Para `status: "not_assessed"`, a resposta traz `findings: []`, `trend: []`,
`score: null` e um campo adicional `not_assessed_reason` (string legível, ex.:
`"No permissions module has run against this system."`).

---

## 3. Achado (*finding*) — a forma partilhada

Usada em `/posture`, `/dimensions/{id}`, `/findings` e no detalhe de cadeias.

```json
{
  "id": "3f2b1c9a-…",
  "dimension": "configuration",
  "target": "apache-httpd",
  "target_label": "Apache HTTPD",
  "identifier": "ServerTokens",
  "observed_value": "Full",
  "expected_value": "Prod",
  "score": 8.5,
  "severity": "High",
  "title": "Server version disclosed in HTTP responses",
  "impact": "Reveals the exact Apache version to any client, letting an attacker match known exploits without probing.",
  "recommendation": "Set ServerTokens to Prod in the main configuration.",
  "evidence": {
    "kind": "config_file",
    "location": "/etc/apache2/apache2.conf",
    "line": 142,
    "snippet": "ServerTokens Full"
  },
  "cves": ["CVE-2023-25690"],
  "references": [
    { "label": "CIS Apache HTTP Server 2.4 §2.5", "url": "https://…" }
  ],
  "in_chains": ["chain-info-disclosure-01"],
  "first_seen": "2026-08-10T09:00:00Z",
  "status": "open"
}
```

**`evidence.kind`** é o que difere por dimensão — e é o que permite à UI mostrar
a proveniência certa em cada caso:

| `kind` | `location` | Campos extra |
|---|---|---|
| `config_file` | caminho do ficheiro | `line`, `snippet` |
| `file_metadata` | caminho do ficheiro | `mode`, `owner`, `group` |
| `listening_socket` | `tcp/0.0.0.0:6379` | `process`, `pid` |
| `package` | nome do pacote | `installed_version`, `fixed_version` |

`status` ∈ `open` | `resolved` | `suppressed`.

---

## 4. `GET /api/v1/chains` — cadeias de ataque

A contribuição mais distintiva do produto. **Não é uma lista de achados** — é a
composição que interessa.

```json
{
  "chains": [
    {
      "id": "chain-rce-escalation-03",
      "title": "Version disclosure enables targeted exploitation",
      "score": 9.1,
      "severity": "Critical",
      "active": true,
      "amplification": 1.4,
      "exceeds_overall": true,
      "cross_dimension": true,
      "narrative": "Apache discloses its exact version, and the running version has a public RCE. An attacker does not need to fingerprint the service — the banner names the exploit to use.",
      "steps": [
        {
          "order": 1,
          "finding_id": "3f2b1c9a-…",
          "dimension": "configuration",
          "identifier": "ServerTokens",
          "score": 8.5,
          "role": "Reveals the exact version"
        },
        {
          "order": 2,
          "finding_id": "7c4e2a1b-…",
          "dimension": "exposure",
          "identifier": "tcp/0.0.0.0:80",
          "score": 5.2,
          "role": "Service reachable from any network"
        }
      ]
    }
  ]
}
```

**Notas normativas**

- `amplification` é o factor pelo qual o pior elo é multiplicado. A UI pode
  mostrá-lo, mas o número que importa é `score`.
- `cross_dimension: true` quando os elos vêm de dimensões diferentes — é o caso
  mais valioso e merece destaque visual.
- `steps[].role` é a frase que explica **porque é que este elo importa nesta
  cadeia**. É o texto que torna a cadeia compreensível; não o omitir na UI.
- `exceeds_overall`: a cadeia pontua acima do indicador global. Ver §1.

---

## 5. `GET /api/v1/targets` — tecnologias avaliadas

```json
{
  "targets": [
    {
      "name": "apache-httpd",
      "label": "Apache HTTPD",
      "icon_key": "apache",
      "status": "assessed",
      "score": 8.5,
      "severity": "High",
      "findings_count": 23,
      "rules_total": 35,
      "chains_total": 11,
      "benchmark": "CIS Apache HTTP Server 2.4",
      "provenance": "LLM (CIS) — MAE-validated",
      "last_assessed": "2026-08-12T14:32:00Z"
    }
  ]
}
```

`icon_key` é a chave para o glifo e a cor de marca — ver a tabela no prompt da
UI. Nunca deduzir o ícone do `name` na UI: usar sempre `icon_key`.

Os doze alvos actuais: `apache-httpd`, `nginx`, `ssh`, `mysql`, `postgresql`,
`redis`, `tomcat`, `docker`, `dockerfile`, `kubernetes`, `azure-iac`, `ubuntu`.

---

## 6. `GET /api/v1/trends` — evolução temporal

```json
{
  "series": [
    {
      "dimension": "overall",
      "scoring_model_version": "2.0",
      "points": [
        { "at": "2026-08-10T09:00:00Z", "score": 9.1 },
        { "at": "2026-08-12T14:32:00Z", "score": 8.5 }
      ]
    }
  ],
  "model_changes": [
    {
      "at": "2026-08-11T00:00:00Z",
      "from_version": "1.0",
      "to_version": "2.0",
      "note": "Multidimensional aggregation introduced. Scores before and after are not directly comparable."
    }
  ]
}
```

**Requisito para a UI:** quando existe uma entrada em `model_changes` dentro do
intervalo visível, o gráfico **tem de marcar essa fronteira** (linha vertical +
legenda). Ligar dois pontos calculados por modelos diferentes com uma linha
contínua apresenta uma mudança de fórmula como se fosse uma variação de risco.

---

## 7. `GET /api/v1/findings` — lista filtrável

Parâmetros: `dimension`, `target`, `severity`, `status`, `has_cve`, `in_chain`,
`q` (texto livre), `limit`, `offset`.

```json
{
  "total": 31,
  "limit": 50,
  "offset": 0,
  "findings": [ /* §3 */ ]
}
```

---

## 8. Endpoints que já existem e se mantêm

Sem alteração de forma. A UI v2 pode consumi-los tal como estão:

| Endpoint | Função |
|---|---|
| `GET /api/v1/health` | estado do serviço |
| `GET /api/v1/scans` | lista de avaliações |
| `GET /api/v1/scans/{id}` | avaliação completa |
| `POST /api/v1/scans` | executar avaliação |
| `GET /api/v1/knowledge/*` | base de conhecimento (regras, cadeias) |
| `GET /api/v1/plugins` | plugins instalados |
| `GET /api/v1/watch` | sessões de monitorização contínua |
| `POST /api/v1/scans/{id}/report` | gerar relatório |

---

## 9. Erros

```json
{ "error": { "code": "dimension_not_available", "message": "The exposure dimension is not implemented in this build.", "detail": null } }
```

Códigos previstos: `dimension_not_available`, `not_found`, `invalid_parameter`,
`assessment_failed`, `unauthorized`.

---

## 10. Notas de implementação (backend)

- `/posture`, `/dimensions/{id}` e `/findings` são **novos** e dependem da Fase A
  (scoring multidimensional).
- **Âmbito da v2 (decidido):** três dimensões avaliadas — `configuration` (já
  existe), `permissions` (Fase B) e `exposure` (Fase C). As restantes três
  (`secrets`, `patch`, `hardening`) respondem `not_assessed`.
- A UI é construída desde já para as três, com dados fictícios. Enquanto uma
  dimensão não estiver implementada, responde `not_assessed` — **o contrato não
  muda, só o conteúdo**, e a UI já prevê esse estado.
- `exposure` depende do inventário de hosts, que não existe hoje (a unidade de
  avaliação é um caminho de configuração). É o item de maior custo do plano e o
  candidato a corte se o prazo apertar: nesse caso responde `not_assessed` e a
  UI degrada sem alteração.
- `manifest` já existe e é persistido (`scan_results.manifest_json`); acrescenta
  `scoring_model_version` na Fase A.
- Os 12 alvos, 514 regras e 32 cadeias são números reais do estado actual.
