# CVM v2 — Plano de execução

**Objectivo declarado:** consola acabada ao nível de produto, três dimensões
avaliadas (configuração, permissões, exposição de rede), instância única por
organização, self-hosted. UI gerada no Lovable e ligada ao backend real.

Levantado contra o repositório em `c58f2c7`, com verificações feitas em
2026-08-13. Os custos são estimativas de esforço, não datas.

Esta é a segunda versão do plano. A primeira assumia que o inventário de hosts
era o item mais caro e possivelmente cortável, e propunha "o host local como
alvo implícito" como atalho. **Ambas as premissas estavam erradas** e a §7
regista porquê — a correcção reordenou as fases.

---

## 1. O achado que decide a arquitectura

A preocupação inicial era que dimensões novas (permissões, exposição) não
coubessem no modelo de dados actual, obrigando a reescrever o núcleo. **Não é o
caso**, e isso reduz o custo da v2 de forma decisiva.

O modelo `Misconfiguration` — o achado que o scoring consome, a base grava e a UI
mostra — **não depende de a origem ser um ficheiro de configuração**. Os campos
que descrevem o problema (`directive`, `bad_value`, `good_value`, métricas CCSS,
`justification`, `recommendation`) são agnósticos quanto à proveniência, e o
único campo que liga a um ficheiro, `source_directive`, é **opcional**.

O que assume ficheiros é apenas a etapa de **recolha**: o contrato `Target`
define `parse_config(path) -> list[Directive]`, e `Directive` traz `source_file`
e `line_number`. Mas `Directive` só é referido em **cinco ficheiros do núcleo**
(`target.py`, `models.py`, `engines/assessment.py`, `unknown_directives.py`,
`watch_loop.py`).

**Consequência:** a generalização necessária é localizada na recolha. O scoring,
a persistência, a API, os relatórios, as cadeias e a consola funcionam sem
alteração com achados de qualquer dimensão. É a diferença entre uma reescrita e
uma extensão.

## 2. Como se generaliza a recolha

`Directive` passa a ser um caso particular de **evidência**: um facto observado
sobre o sistema, com um identificador, um valor observado e uma proveniência.

| Dimensão | Identificador | Valor observado | Proveniência |
|---|---|---|---|
| Configuração *(hoje)* | `ServerTokens` | `Full` | ficheiro + linha |
| Permissões | `/etc/shadow:mode` | `0644` | inode (`stat`) |
| Exposição | `tcp/0.0.0.0:6379` | `redis-server` | socket + processo |

As regras continuam a ser pares (identificador, valor inseguro) com métricas
CCSS — o motor de correspondência que já existe (`match_value_rules`,
`detect_absences`) opera igual. O que muda é quem produz as evidências.

Recomendação concreta: acrescentar ao contrato `Target` um método opcional
`collect_evidence(path) -> list[Evidence]`, com `parse_config` a manter-se como
o caso ficheiro (implementado por omissão em termos do novo método). Os doze
plugins existentes não são tocados.

**Risco assumido:** `core/target.py` diz hoje "zero modificações a este
ficheiro". Esta alteração contradiz essa regra. É uma alteração aditiva e
retrocompatível, mas é uma decisão de arquitectura consciente e deve ficar
registada como tal no PRD (§9).

### 2.1 A recolha não precisa de agente nem de SSH

Numa instância única por organização, o CASPAR **já corre onde estão os
ficheiros** — é assim que o `watch` funciona hoje, com `/etc` montado no
contentor. Ler modos de ficheiros (`stat`) e sockets à escuta (`/proc/net/tcp`,
`/proc/<pid>/fd`) é a mesma posição de execução e o mesmo privilégio que ler
`/etc/nginx/nginx.conf`.

Não há agente a construir, não há credenciais de terceiros a guardar, não há
alcance de rede a garantir. A dimensão de exposição custa o recolector e as
regras — não custa infraestrutura distribuída.

## 3. A base de conhecimento: obtenção automatizada

A pergunta que motivou esta revisão foi se as regras das dimensões novas podem
ser obtidas automaticamente, em vez de curadas à mão como as 18 actuais do
plugin `ubuntu`. **Podem**, e a fonte é melhor do que a curadoria.

### 3.1 Regressão descoberta: `plugin fetch` está partido

O `BenchmarkFetcher` depende inteiramente do `stigviewer.com`, que passou a
exigir autenticação. Verificado em 2026-08-13:

```
canonical_ubuntu_2204_lts: HTTP 401
f5_nginx:                  HTTP 401
kubernetes:                HTTP 401
```

Não é específico do Ubuntu: **as 45 entradas do `fetch/catalog.json` estão
inacessíveis**. É uma regressão pré-existente, independente da v2, e que hoje
falha com uma `FetchError` genérica que não distingue "fonte fechada" de "alvo
inexistente".

### 3.2 Fonte de substituição: ComplianceAsCode / SCAP Security Guide

O `ComplianceAsCode/content` publica o `scap-security-guide` em release pública,
sem autenticação (8,6 MB no tarball `.tar.bz2`; a versão corrente é a v0.1.81).
Contém dois artefactos que juntos dão tudo o que a extracção precisa:

**`controls/cis_ubuntu2204.yml`** — o CIS Ubuntu 22.04 LTS Benchmark **v2.0.0**
(lançado 2024-03-28) inteiro e estruturado: ID de secção, título, nível
(`l1_server`/`l2_server`/…) e estado (`automated`/`manual`) por controlo.

**`linux_os/guide/**/rule.yml`** (2509 ficheiros) — a substância de cada regra:
`rationale` em prosa, `severity`, identificadores `CCE`, referências normativas
(NIST, ISO 27001, PCI-DSS, SRG) e, decisivamente, **o valor esperado por
produto**. Exemplo real de `file_permissions_etc_shadow/rule.yml`:

```yaml
template:
    name: file_permissions
    vars:
        filepath: /etc/shadow
        filemode: '0000'
        filemode@ubuntu2204: '0640'
```

Isto é (identificador, valor esperado) explícito e legível por máquina — o par
que o motor de regras consome, sem inferência.

### 3.3 O que a fonte cobre, por dimensão

Contagem real sobre o perfil **Level 1 Server** (`l1_server`, `status:
automated`): **225 controlos**, dos 300 totais do benchmark. Classificados pelas
três dimensões da v2:

| Dimensão | Controlos | Secções CIS predominantes |
|---|---|---|
| Configuração | 123 | §1 módulos e partições, §4 autenticação, §5 SSH e PAM |
| Exposição | 53 | §2 serviços em uso, §3 rede e firewall |
| Permissões | 49 | §7 ficheiros do sistema, §6.2 auditoria, `nosuid`/`nodev` |

Compare-se com as **18 regras** curadas hoje. Duas propriedades que a curadoria
manual não tinha e que contam para a tese:

1. **Versionada e citável** — v2.0.0, data de lançamento, URL de origem.
2. **É a mesma fonte que o OpenSCAP consome.** A comparação com o OpenSCAP passa
   de "mesmos controlos aproximados, output diferente" para o mesmo corpo de
   regras, com a diferença a residir exclusivamente no que cada ferramenta faz
   com elas — pass/fail contra score CCSS reproduzível com narrativa.

### 3.4 O que ainda exige trabalho, e não deve ser subestimado

O SSG dá identificador, valor esperado, justificação e severidade qualitativa.
**Não dá métricas CCSS** (AV, AC, Au, C, I, A) — que é precisamente o que o CVM
produz e o SSG não. Essas continuam a sair do pipeline `plugin add` (LLM+RAG
sobre o `rationale` e a descrição), como nos 35 do `apache-httpd`.

Consequência directa: estas regras entram no **mesmo regime de validação** dos
alvos derivados por LLM, e **não herdam** a validação dos alvos curados. Precisam
de MAE próprio contra os CCE que o SSG já traz nos `identifiers` — o que, note-se,
é uma vantagem: o ground truth vem anotado na própria fonte, alvo a alvo, em vez
de ser reunido à parte.

### 3.5 Não substituir o plugin `ubuntu` actual

As 18 regras curadas do `ubuntu` são o alvo que sustenta a comparação com o
OpenSCAP já escrita. Trocá-las por 225 extraídas altera um resultado publicado.

**Decisão:** o alvo novo é `ubuntu2204` (ou `ubuntu-cis`), a par do `ubuntu`
existente, que fica intacto. Permite ainda um resultado que o plano anterior não
previa: comparar *curadoria manual* com *extracção automatizada* sobre o mesmo
benchmark e o mesmo sistema — as 18 regras curadas são um subconjunto exacto das
225, portanto a concordância é medível directamente.

## 4. Inventário de hosts — o sujeito do modelo

Existe hoje mais do que a versão anterior deste plano afirmava: há tabela
`hosts` (colunas `id`, `label`, `created_at`, `updated_at`), há registo em
`/api/v1/hosts/registry`, e **`scan_results.host_id` já liga cada avaliação a um
host**. A tabela está vazia (0 linhas) e é fina, mas o conceito e a ligação
existem.

O que falta não é a noção de host: é a **identidade persistente** e os atributos.

**Decisão tomada:** UUID gerado no primeiro registo e guardado no host; hostname
e IP passam a atributos mutáveis. As séries temporais sobrevivem a mudanças de
nome, de IP e a re-imaging — que é o que distingue um inventário de uma lista de
caminhos.

Porque é que isto passou a ser a primeira fase e não a última: um score precisa
de um sujeito. "O host `web-01` tem risco 8.5 em três dimensões" é uma
afirmação de produto; "um caminho de configuração tem risco 8.5" não é. A UI
gerada assume-o — `Posture.totals.targets_assessed`, achados com `target`,
cadeias que cruzam dimensões *dentro do mesmo host*. Sem inventário, `posture`
não tem a que se referir.

## 5. Sequência

A ordem decorre de dependências verificadas, não de preferência.

### Fase 0 — `plugin fetch` com fonte SSG *(desbloqueia tudo)*

Acrescentar ao `BenchmarkFetcher` um tipo de fonte `ssg`: descarrega o release do
ComplianceAsCode, extrai o `controls/cis_<produto>.yml` e os `rule.yml`
referenciados, e produz um ficheiro que o `plugin add` consome. Marcar as fontes
`stigviewer` como indisponíveis, com erro que o diga em vez de falhar
genericamente.

**Custo:** baixo. **Valor:** repara uma regressão que existe hoje, é útil
independentemente da v2, e é pré-requisito de qualquer regra nova.

### Fase A — Inventário de hosts

Estender `hosts` com UUID persistente, hostname, sistema operativo, primeira e
última observação. Registo no primeiro contacto. `scan_results.host_id` passa a
ser preenchido sempre (hoje existe mas não é usado).

**Custo:** moderado, quase todo em schema e API. **Valor:** dá sujeito ao score.

### Fase B — Scoring multidimensional

Sem isto, uma dimensão nova não tem onde aparecer: o indicador global é hoje o
pior achado individual (`engines/aggregation.py::aggregate_scan`), sem noção de
dimensão.

- Cada achado passa a declarar a dimensão a que pertence.
- Agregação produz um indicador por dimensão + um global parametrizável.
- Manifesto passa a gravar versão do modelo de scoring e pesos aplicados.
- Cobertura explícita: dimensões não avaliadas ≠ dimensões limpas.
- Séries temporais segmentam na fronteira de versão do modelo.

**Custo:** moderado. Toca em `aggregation.py`, `manifest.py`, `models.py`,
schema (aditivo) e testes de agregação.
**Valor de tese:** é a §6 do PRD tornada executável, e o que permite a análise de
sensibilidade.

### Fase C — Alvo `ubuntu2204` e as três dimensões

Construir o alvo novo a partir da Fase 0, com recolectores para as três
dimensões: ficheiros (já existe), `stat` (permissões), sockets (exposição).

Faseável por dimensão dentro da própria fase — configuração primeiro (valida o
pipeline de extracção contra as 18 regras conhecidas), depois permissões, depois
exposição.

**Custo:** o mais alto, sobretudo em validação. **Valor:** fecha a limitação
declarada em `plugins/ubuntu/__init__.py` e é o que torna a comparação com o
OpenSCAP directa.

### Fase D — Ligação da UI

Substituir `src/lib/cvm/data.ts` por chamadas reais. Ver §6.

### Fase E — Validação

MAE dos scores CCSS contra os CCE que o SSG anota; recall de detecção sobre
configurações deliberadamente vulneráveis; concordância entre as 18 regras
curadas e as suas equivalentes extraídas; análise de sensibilidade dos pesos
(±10%, estabilidade de ordenação).

## 6. A UI do Lovable — estado verificado

Repositório: `AFilipe-IT/cvm-security-posture`. Clonado e inspeccionado em
2026-08-13.

**A iteração de densidade foi aplicada** (commit `0468b06`, "Dense overview
layout built") e as inconsistências de dados foram corrigidas: 24 achados
abertos, 4 críticos, cadeia máxima 9.5, `rules_evaluated: 514`, "Configuration"
como designação única, e o benchmark do Dockerfile deixou de ser inventado.

**O contrato foi respeitado.** `src/lib/cvm/types.ts` segue o
`CONTRATO_API_V2.md` quase à letra: `DimensionStatus` com os três estados,
`score: number | null`, `delta: number | null`, e `Evidence` como união
discriminada pelas quatro `kind`. Ligar é substituir mocks por chamadas, não
traduzir estruturas — que era a condição posta antes de abrir o Lovable.

Os doze alvos estão presentes, com o Ubuntu já a declarar
`benchmark: "CIS Ubuntu Linux 22.04 v2.0"` — o mesmo que a Fase 0 passa a
descarregar.

**Divergência de stack a resolver:** o Lovable usou TanStack Start + TanStack
Router + Tailwind 4 + shadcn/Radix; o `frontend/` actual é Vite + React Router +
CSS Modules. Não é conflito (o novo fica em `frontend-v2/`), mas `src/server.ts`
e `src/start.ts` indicam SSR, que não serve para o `caspar serve` montar como
estático. Resolve-se com build SPA ou pré-render — trabalho pequeno, mas real.

**A portar do `frontend/` actual**, em vez de reinventar: os tokens de cor e
tipografia, o `ServiceIcon` (resolve 37 alvos por família) e os 55 testes.

## 7. Correcções à versão anterior deste plano

Registadas porque a versão anterior está no histórico do repositório e as suas
conclusões não devem ser reutilizadas.

- **"Não existe inventário de hosts."** Errado. Existe tabela `hosts`, endpoint
  de registo e `scan_results.host_id`. Está vazio e é fino, mas o conceito
  existe — o custo é de extensão, não de construção.
- **Exposição como "a fase mais cara, a cortar se o prazo apertar".** O custo que
  lhe atribuí vinha de inventário distribuído e recolha remota. Numa instância
  única self-hosted não há nem uma coisa nem outra (§2.1).
- **"O host local como alvo implícito, adiando o inventário."** Atalho de
  protótipo, incompatível com o nível de acabamento pretendido. O inventário
  passou a Fase A precisamente por isto.
- **Ordem anterior (scoring → permissões → exposição).** O scoring vinha antes do
  inventário, ou seja, o indicador vinha antes do sujeito a que se refere.

## 8. Riscos a manter à vista

- **A dissertação está por escrever e a parte prática estava fechada e
  validada.** Reabri-la continua a ser a decisão de maior risco. As fases estão
  ordenadas para que parar depois de B+C(configuração) deixe um resultado
  coerente, em vez de um sistema meio-migrado.
- **Regressão na base validada.** As 846 passagens de teste e os números de
  avaliação (20/20 CCE, 96/96 detecção) são o activo mais valioso do projecto.
  Re-executar ao fim de cada fase; qualquer alteração ao scoring mantém a
  comparabilidade documentada ou versiona-a explicitamente.
- **225 regras extraídas por LLM não herdam validação.** Entram no regime do
  `apache-httpd`, não no dos alvos curados. A Fase E não é opcional.
- **Dependência de uma fonte externa nova.** O SSG substitui o stigviewer, mas é
  igualmente externo. O release descarregado deve ser fixado por versão e o seu
  SHA registado no manifesto, para que a reprodutibilidade não dependa de a
  fonte continuar disponível.
- **Seis dimensões anunciadas, três entregues.** O PRD deve declarar o estado de
  cada dimensão, para que a UI e o documento não prometam mais do que o sistema
  entrega. A UI já o faz correctamente (`not_assessed` com justificação).
