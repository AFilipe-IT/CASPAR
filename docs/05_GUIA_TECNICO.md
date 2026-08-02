# CASPAR — Guia Técnico do Projeto

> Documento para perceberes o projeto de ponta a ponta: como está organizado,
> como os dados fluem, onde mexer para cada tipo de alteração, e o que cada
> ficheiro faz. Lê de cima a baixo uma vez; depois usa como referência.

---

## 1. A ideia em três frases

O CASPAR lê a configuração de um serviço (13 plugins hoje — Apache, Nginx, MySQL, PostgreSQL, Redis, SSH, Tomcat, Docker, Dockerfile, Kubernetes, Ubuntu OS, Azure IaC, mais um plugin `dummy` de teste), compara cada directiva/regra contra o CIS Benchmark ou DISA STIG de origem, e atribui um score de segurança 0–10 baseado no standard NISTIR 7502 (CCSS). O trabalho pesado — perceber o que cada má configuração significa, atribuir métricas, escrever narrativas, procurar CVEs — acontece **uma vez** no *build time*, usando um LLM local (Ollama), e fica gravado numa base SQLite. Cada *scan* depois é **100% determinístico**: lê a config, procura na base, faz aritmética, produz o relatório — sem LLM, sem internet, mesmo resultado sempre.

Esta separação build/runtime é a decisão de arquitetura mais importante do projeto e o que o torna defensável academicamente: os scores são reprodutíveis e auditáveis (manifesto com hash SHA-256 do conteúdo da base de conhecimento, ver §7 do [03_GUIA_VM_UBUNTU22.md](03_GUIA_VM_UBUNTU22.md)).

---

## 2. Os dois tempos do sistema

### Build time (corre raramente — quando adicionas ou actualizas um plugin)

```
CIS Benchmark PDF (ou DISA STIG XCCDF XML) + CCE XLS + NISTIR 7502
        │
        ├─ RAG (TF-IDF, build/rag.py) extrai a secção relevante do benchmark
        │           por directiva/regra
        │
        ├─ STAGE 1 (llm_pipeline.py, genérico): LLM lê cada recomendação e
        │           atribui as métricas base AC, C, I, A + justificação curta.
        │           Auto-consistência opcional (consensus_samples>1): amostra
        │           N vezes, faz majority-vote por métrica, e persiste a taxa
        │           de acordo como `confidence` (1.0 = unânime, 0.0 = fallback
        │           conservador de forma determinística)
        │
        ├─ STAGE 2 (chain_pipeline.py, genérico): LLM olha para todas as
        │           misconfigs já pontuadas e identifica combinações
        │           perigosas (attack chains)
        │
        ├─ STAGE 3 (narrative_pipeline.py, genérico): LLM escreve, por
        │           misconfig, a narrativa rica — descrição, impacto,
        │           cenário de exploração, justificação detalhada
        │
        └─ Enrichment (enrichment/): cve_enricher.py procura CVEs reais na
                    NVD + CISA KEV e ajusta as métricas temporais GEL/GRL;
                    ttp_enricher.py mapeia CVEs para técnicas MITRE ATT&CK
                    conhecidas e refina o GEL com esse contexto
        │
        ▼
   ┌──────────────┐
   │  ccss.db     │   514 misconfigs + métricas + narrativas + 32 attack
   └──────────────┘   chains, em 11 plugins com regras (+ 1 dummy de teste)
```

Os plugins puramente **curados** (kubernetes, dockerfile, ubuntu) não passam pelos Stages 1-3 por LLM — as regras vêm diretamente de um CIS Benchmark curado à mão em `build_<plugin>.py`/`chains.json`, mantendo esse caminho 100% determinístico mesmo no build. O `azure-iac` é o oposto: é o plugin mais dependente de LLM+RAG, porque faz *extração com mapeamento de vocabulário* a partir do benchmark CIS Azure (ver `build_azure.py`/`canon.py`) para lidar com a variação de nomes entre Terraform/Bicep/ARM.

### Runtime (corre em cada scan — rápido, determinístico)

```
input (ficheiro / pasta / serviço live / imagem docker / IaC)
   │
   ├─ input_resolver.py  → resolve o input para um caminho concreto de config
   ├─ parser.py          → lê a config e produz uma lista de Directives (por plugin)
   ├─ rules.py            → decide AV e Au com base na config concreta (worst-case,
   │                        incl. avaliação estática de blocos `Match` no SSH)
   ├─ lookup na ccss.db  → para cada directiva má, vai buscar a entrada pré-calculada
   ├─ ccss.py            → recalcula os scores com o AV/Au reais deste sistema
   ├─ deteção de chains  → vê quais combinações estão todas presentes
   ├─ agregação          → score global = pior caso
   │
   ▼
ScanResult → terminal / HTML / JSON / SARIF + rodapé de reprodutibilidade
             (versão · hash SHA-256 do conteúdo da KB · nº de regras do plugin)
```

**Porque é que AV e Au são runtime e não build time?** Porque dependem do sistema concreto. A mesma directiva `AllowOverride All` é mais perigosa se o servidor estiver exposto à rede (AV=Network) do que se só escutar em localhost (AV=Local). O LLM não pode saber isto no build — só o scan do sistema real sabe. Por isso o build calcula AC/C/I/A (intrínsecos à directiva) e o runtime calcula AV/Au (dependem do ambiente) e combina os dois.

---

## 3. Mapa de ficheiros — o que mexer para cada coisa

### Núcleo genérico (`config_assessment/core/`) — não depende de nenhum plugin

| Ficheiro | Responsabilidade | Mexes aqui quando… |
|---|---|---|
| `target.py` | Interface abstrata `Target` que todo plugin implementa + constantes de `detection_confidence` | Adicionas um conceito novo a todos os plugins |
| `models.py` | Dataclasses: `Directive`, `Misconfiguration`, `SystemProfile`, `ScanResult` | Adicionas um campo novo aos dados (ex: `confidence`, `narrative`) |
| `ccss.py` | As fórmulas NISTIR 7502 e os pesos das métricas | Mudas como os scores são calculados |
| `runtime.py` | O motor de scan — orquestra parse→lookup→score→agregação | Mudas a lógica do que acontece durante um scan |
| `input_resolver.py` | Resolve os modos de input (ficheiro/pasta/live/docker) para um caminho | Adicionas um modo de scan novo |
| `manifest.py` | Constrói o manifesto de reprodutibilidade (hash SHA-256 do conteúdo da KB) | Mudas o que entra no hash de reprodutibilidade |
| `unknown_directives.py` | Deteção de directivas ausentes da base de conhecimento (3 camadas) | Mudas a heurística de "directiva desconhecida" |
| `watch.py` | Modo `caspar watch` (daemon de vigilância contínua) | Mudas o ciclo de acompanhamento |
| `db/schema.sql` | Definição das tabelas (`misconfigurations`, `attack_chains`, `version_exploits`, metadados) | Adicionas/alteras colunas (lembra: também tens de migrar) |
| `db/database.py` | Todas as queries e o `_row_to_misconfiguration` | Adicionas um campo (tens de o ler aqui também!) |
| `db/doctor.py` | Verificação de integridade da DB (`caspar doctor`) | Adicionas uma checagem de saúde nova |
| `db/reseed.py` | Restauro/actualização da DB canónica | Mudas o processo de reseed |

### Build genérico (`config_assessment/build/`) — reutilizado por todos os plugins baseados em LLM

| Ficheiro | Responsabilidade |
|---|---|
| `llm_client.py` | Wrapper do Ollama (+ stub para testes) |
| `rag.py` | TF-IDF sobre o benchmark, `BenchmarkIndex` |
| `benchmark_extractor.py` | Extração de secções PDF/XCCDF |
| `curated_build.py` | Caminho de build para plugins curados (sem LLM) |
| `generic_build.py` | Orquestração de build partilhada |
| `chain_pipeline.py` | Stage 2 — attack chains via LLM (genérico) |
| `plugin_detector.py` / `plugin_scaffolder.py` | Auto-deteção do formato da fonte + scaffolding de um plugin novo (`caspar plugin add`) |

### Enrichment (`config_assessment/enrichment/`)

| Ficheiro | Responsabilidade |
|---|---|
| `cve_enricher.py` | NVD API v2 + CISA KEV → GEL/GRL |
| `ttp_enricher.py` | Mapeia CVEs para técnicas MITRE ATT&CK conhecidas, refina o GEL |
| `exploit_enricher.py` | Enriquecimento de exploits conhecidos |
| `version_prefetch.py` | Pré-cálculo de `version_exploits` por versão de serviço |

### Plugins (`config_assessment/plugins/<nome>/`)

Cada plugin implementa `Target` e tipicamente tem `parser.py` (lê a config, produz `Directive`s) e `rules.py` (decide AV/Au a partir da config concreta). Os plugins baseados em LLM (`apache_httpd`, `nginx`, `mysql`, `redis`, `ssh`, `tomcat`, `docker`) reutilizam o `llm_pipeline.py`/`chain_pipeline.py`/`narrative_pipeline.py` genéricos que hoje vivem em `plugins/apache_httpd/` (ver nota de arquitectura abaixo). Os plugins curados (`kubernetes`, `dockerfile`, `ubuntu`) têm as regras escritas directamente em `build_<plugin>.py`/`chains.json`, sem chamada a LLM no build. O `azure_iac` é o único plugin de IaC "genérico" (Terraform/Bicep/ARM), com extração LLM+RAG e mapeamento de vocabulário próprio (`canon.py`).

| Plugin | Fonte | Build |
|---|---|---|
| `apache_httpd` | CIS Apache HTTP Server 2.4 Benchmark | LLM (Stages 1-3) — target de referência, tem ground truth CCE |
| `nginx` | CIS NGINX Benchmark v3.0.0 | LLM (Stages 1-3) |
| `mysql` | CIS Oracle MySQL 5.6 Benchmark (STIG) | LLM (Stages 1-3) |
| `redis` | DISA Redis Enterprise 6.x STIG | LLM (Stages 1-3) |
| `ssh` | CIS Ubuntu 24.04 Benchmark §5.1 | LLM (Stages 1-3) + avaliação estática worst-case de blocos `Match` |
| `tomcat` | DISA Apache Tomcat 9 STIG | LLM (Stages 1-3) |
| `docker` | CIS Docker Benchmark v1.8.0 | LLM (Stages 1-3) |
| `dockerfile` | CIS Docker Benchmark (curado) | curado |
| `kubernetes` | CIS Kubernetes Benchmark v1.9 §5 (curado) | curado |
| `ubuntu` | CIS Ubuntu 22.04 LTS Benchmark L1 Server (subconjunto config-based, curado) | curado |
| `azure-iac` | CIS Microsoft Azure Benchmarks | LLM + RAG, mapeamento de vocabulário (Terraform/Bicep/ARM) |
| `dummy` | fixture de teste (Phase 1) | — |

> **Nota de arquitectura (dívida técnica conhecida):** `llm_pipeline.py`, `chain_pipeline.py`/`narrative_pipeline.py` e os entry points `build_llm.py`/`build_narratives.py` são **genéricos** — servem qualquer plugin baseado em LLM — mas continuam fisicamente na pasta `plugins/apache_httpd/` por serem esse o primeiro plugin implementado. Todos os outros plugins LLM (nginx, mysql, redis, ssh, tomcat) importam-nos de lá. Migrar para `core/` ou `build/` é um refactor futuro de baixo risco, ainda por fazer.

### CLI (`cli/`)

`cli/main.py` é só o ponto de entrada: define o grupo `cli` e regista os comandos (e re-exporta os
nomes históricos, por isso `from cli.main import X` continua a funcionar). A implementação vive em:

| Módulo | Contém |
|--------|--------|
| `cli/_output.py` | Impressão no terminal + export SARIF |
| `cli/_discovery.py` | Auto-descoberta de plugins (`_plugin_dirs`, `_discover_plugins`) |
| `cli/_knowledge.py` | Base de conhecimento RAG build-time (Camada 3 — descoberta + ingestão de manuais para `--assess-unknown`) |
| `cli/commands/scan_cmds.py` | `scan`, `watch` |
| `cli/commands/plugin_cmds.py` | `plugin add` / `fetch` / `manual` |
| `cli/commands/build_cmds.py` | `build`, `fetch-exploits`, `refresh` |
| `cli/commands/report_cmds.py` | `targets`, `diff`, `badge`, `explain`, `history`, `trend`, `report` |
| `cli/commands/manage_cmds.py` | `suppress`, `doctor`, `fix`, `promote` |

A função `scan` orquestra: resolve input → corre runtime → imprime terminal → gera relatórios → limpa temporários.

---

## 4. O fluxo de dados de uma misconfiguration (exemplo concreto)

Segue `AllowOverride All` do build ao relatório (plugin `apache_httpd`):

1. **Build, Stage 1**: o LLM lê a secção 4.4 do CIS Benchmark, percebe que `AllowOverride All` permite `.htaccess` sobreporem a config, e atribui `AC=M, C=P, I=P, A=N`. Calcula `base_score = 5.8`. Se `consensus_samples>1`, este valor é o resultado de majority-vote entre N amostras independentes; a taxa de acordo fica gravada em `confidence`. Grava na `ccss.db`.

2. **Build, Stage 3**: o LLM escreve a narrativa — descrição, impactos, cenário com exemplo de `.htaccess` malicioso, e justificação de cada métrica. Grava no campo `narrative` (JSON).

3. **Build, enrichment**: não há CVE associado a esta directiva, fica `GEL=L, GRL=H` (sem refinamento TTP, por ausência de CVE). `temporal_score = 5.8 × 0.93 × 1.0 = 5.4`.

4. **Runtime, scan**: o parser encontra `AllowOverride All` em duas `<Directory>` no ficheiro. As `rules.py` veem que há um `Listen 80` (rede) e nenhum `AuthType`, por isso `AV=N, Au=N`. O runtime vai à base buscar a entrada de `AllowOverride All`, aplica o AV/Au reais, confirma `temporal_score = 5.4`.

5. **Relatório**: o HTML mostra o score 5.4, as métricas com justificação, os impactos, o cenário, o `confidence` da entrada, e — graças ao snippet — o bloco real das duas `<Directory>` com a linha destacada. O rodapé mostra o manifesto de reprodutibilidade.

---

## 5. As métricas CCSS explicadas

Cada misconfiguration tem 8 métricas que se combinam em dois scores.

**Exploitability (quão fácil é explorar):**
- **AV** (Access Vector): de onde se ataca. Local / Adjacent / Network. *Runtime.*
- **Au** (Authentication): quantas credenciais são precisas. Multiple / Single / None. *Runtime.*
- **AC** (Access Complexity): quão difícil é. High / Medium / Low. *Build time.*

**Impact (o que acontece se explorado):**
- **C / I / A** (Confidentiality / Integrity / Availability): None / Partial / Complete. *Build time.*

**Temporal (ajustam o score base ao longo do tempo):**
- **GEL** (Exploit Level): existe exploit ativo? None→High. *CVE + TTP enrichment.*
- **GRL** (Remediation Level): há correção oficial? Unavailable→Official. *CVE enrichment.*

**Build-time, meta-informação (não entra na fórmula CCSS, mas viaja com a entrada):**
- **confidence**: taxa de acordo do self-consistency voting (1.0 = unânime/sem LLM, 0.0 = fallback conservador determinístico após esgotar retries).

**As fórmulas** (em `ccss.py`):
```
f_impact  = 10.41 × (1 − (1−C)(1−I)(1−A))
f_exploit = 20 × AV × Au × AC
BaseScore = ((0.6 × f_impact) + (0.4 × f_exploit) − 1.5) × 1.176
TemporalScore = BaseScore × GEL × GRL
```

Regras especiais que vale a pena saber:
- **Worst-case AV/Au**: se o serviço está exposto à rede, todas as misconfigs ganham AV=Network. No SSH, isto é avaliado estaticamente por bloco `Match` (`_match_applies_worst_case`), sem sondar sessões reais.
- **KEV força GEL=High**: se um CVE está na CISA Known Exploited Vulnerabilities, o GEL sobe para High independentemente do CVSS.
- **TTP enrichment**: quando há CVE associado, `ttp_enricher.py` procura técnicas MITRE ATT&CK conhecidas para refinar o GEL para além do que o CVSS/KEV por si só indicariam.

---

## 6. Attack chains — e o ponto delicado

Uma chain é uma combinação de misconfigs que juntas são mais perigosas que a soma. Ex: `User=root` + `Group=root` = escalada total de privilégios.

O Stage 2 pede ao LLM para identificar estas combinações e atribuir um **factor de amplificação** (×1.2 a ×1.8) conforme a severidade das partes. O score da chain é `pior_parte × factor`, com teto em 10. Nos plugins curados, as chains vêm directamente de `chains.json` (revistas à mão), sem passar pelo Stage 2.

**O que precisas de saber para a tese:** este factor de amplificação é uma **heurística proposta por ti**, não vem do NISTIR 7502. O standard define como pontuar misconfigs isoladas mas é silencioso sobre como compô-las em cadeias. Isto é uma contribuição original — boa para o artigo, mas precisa de ser justificada (porquê estas bandas? idealmente alguma validação). Nos relatórios o multiplicador não é mostrado como número solto; só aparece o score final.

---

## 7. Como operar o projeto (comandos)

```bash
# Ativar ambiente (sempre primeiro)
cd ~/caspar && source .venv/bin/activate

# ── Adicionar/atualizar um plugin (build time) ──
caspar plugin fetch mongodb --then-install   # descobre STIG/benchmark, gera plugin, faz build
caspar refresh                               # CVE + TTP enrichment de todos os plugins

# ── Fazer scans (runtime) ──
caspar scan /tmp/httpd.conf                 # ficheiro
caspar scan /etc/apache2/                   # pasta
caspar scan --live apache2                  # serviço instalado
caspar scan docker://httpd:2.4              # imagem docker
caspar scan test_target/pod_vulnerable.yaml # IaC (kubernetes/dockerfile/azure-iac)

# ── Com relatório ──
caspar scan /etc/apache2/ --report --format json
caspar scan /etc/apache2/ --threshold 7.0   # exit 1 se score > 7 (CI/CD)

# ── Utilitários ──
caspar targets                              # lista os 13 plugins
caspar doctor                               # integridade da DB
pytest tests/ -q                            # corre os 647 testes
```

---

## 8. Receitas de modificação comuns

**"Quero adicionar uma misconfiguration nova a um plugin LLM"**
→ Não edites código. Corre `caspar build`/`plugin fetch --then-install` de novo (o LLM extrai do benchmark). Depois `refresh` para CVEs/TTP.

**"Quero mudar como o HTML aparece"**
→ Só `core/report_html.py` (ou o módulo de output equivalente em `cli/_output.py`). A função `generate_html` constrói tudo; `render_issue` faz cada card; `mrow` faz cada linha de métrica.

**"Quero mudar o que o LLM escreve nas narrativas"**
→ `narrative_pipeline.py` (em `plugins/apache_httpd/`, reutilizado por todos), função `_build_prompt` (o que é pedido) e `_SYSTEM_PROMPT` (as regras). Depois re-corre o build.

**"Quero adicionar um campo novo aos dados"**
→ Três sítios, sempre: (1) `models.py` na dataclass, (2) `schema.sql` + migração em `database.py`, (3) `_row_to_misconfiguration` em `database.py` para o ler. Esquecer o (3) causou o bug do `confidence` que apanhámos nesta sessão (testes já referenciavam o campo antes de existir no modelo).

**"Quero adicionar um serviço novo"**
→ `caspar plugin add`/`plugin fetch` faz scaffold automático (`plugin_detector.py` + `plugin_scaffolder.py`), detectando se a fonte é CIS Benchmark PDF ou DISA STIG XCCDF. Cria `plugins/<nome>/` com parser + rules + entry point de build. Zero mudanças no `core/` para o caso comum (plugin baseado em LLM); plugins curados exigem escrever `build_<nome>.py`/`chains.json` à mão.

**"O meu novo plugin está a competir com outro pelo mesmo ficheiro"**
→ Sobrepõe `detection_confidence(path)` na tua classe plugin, usando as constantes
partilhadas de `core/target.py` (a escala é definida lá, uma vez, para todos):

| Constante | Valor | Quando usar |
|---|---|---|
| `CONFIDENCE_EXACT_FILENAME` | 90 | Nome de ficheiro inequívoco (`nginx.conf`, `httpd.conf`) |
| `CONFIDENCE_SYNTAX_MARKER`  | 70 | Sintaxe só desta tecnologia (`server {`, `<VirtualHost`) |
| `CONFIDENCE_DIRECTORY`      | 60 | Nome de directório associado (`conf.d/`, `nginx/`) |
| `CONFIDENCE_WEAK`           | 20 | Palavra genérica no conteúdo (pode estar num comentário) |

O runtime chama `detection_confidence(path)` em todos os candidatos que passaram em `detect()` e escolhe o de maior confiança. Sem override, o plugin herda `metadata().priority` (retro-compatível mas sem granularidade por tipo de evidência). O contrato garante que a comparação é entre tipos de evidência — não entre números arbitrários escolhidos por cada plugin.

**"Quero mudar as fórmulas de score"**
→ Só `core/ccss.py`. Mas cuidado: muda a validação contra o ground truth CCE (`scripts/evaluate.py`).

**"Quero adicionar auto-consistência a um plugin LLM"**
→ Passa `consensus_samples>1` ao construtor do pipeline (`llm_pipeline.py`); o majority-vote e o cálculo de `confidence` já são genéricos (`_vote`), não precisas de reimplementar por plugin.

---

## 9. Estado atual

**Núcleo e runtime — fechados e validados:**
- 4+ modos de scan (ficheiro, pasta, live, docker, IaC), testados em máquina real (Ubuntu 22.04)
- Os 3 stages do LLM pipeline (métricas, chains, narrativas), genéricos e partilhados por todos os plugins LLM
- Self-consistency opcional (majority-vote, `confidence` persistido)
- CVE enrichment (NVD + KEV) e TTP enrichment (MITRE ATT&CK)
- Relatórios terminal / HTML / JSON / SARIF, com manifesto de reprodutibilidade (hash SHA-256 do conteúdo da KB)
- 0% mismatch (MAE) contra o ground truth CCE no Apache; 100% de recall nas fixtures vulneráveis (96/96)
- 647 testes automatizados, todos offline-safe, incl. réplica dos 18 exemplos oficiais do NISTIR 7502 §4

**13 plugins registados** (12 com regras próprias + `dummy` de teste): apache-httpd, nginx, mysql, postgresql, redis, ssh, tomcat, docker, dockerfile, kubernetes, ubuntu, azure-iac. 514 misconfigurations catalogadas, 32 attack chains, distribuídas de forma muito desigual (azure-iac 220, docker 57, tomcat 49… dockerfile 5) — reflexo direto da riqueza do benchmark-fonte de cada um, não de esforço desigual.

**Dívida técnica conhecida, honesta:**
- `llm_pipeline.py`/`chain_pipeline.py`/`narrative_pipeline.py` continuam em `plugins/apache_httpd/` embora sejam genéricos — candidatos a mover para `core/` ou `build/`.
- Nem todos os plugins têm ground truth CCE (só o Apache) — os outros validam-se por revisão manual + testes de cobertura/recall nas fixtures dedicadas.
- Attack chains só existem onde o benchmark-fonte ou o Stage 2 as sustentam; nem todos os plugins têm a mesma densidade de chains.
- O factor de amplificação das chains é uma heurística proposta neste trabalho, sem fundamentação directa no NISTIR 7502 — está identificado e justificado em `docs/tese-docs/DISSERTACAO_REFERENCIA.md`, mas continua sem validação externa.

---

## 10. Glossário rápido

- **CCSS**: Common Configuration Scoring System (NISTIR 7502) — o standard que dá o score.
- **CIS Benchmark / DISA STIG**: os documentos-fonte que dizem o que é uma boa/má configuração.
- **CCE**: Common Configuration Enumeration — IDs de configurações, usados como ground truth (só Apache).
- **CVE / NVD / KEV**: vulnerabilidades conhecidas / base de dados nacional / lista de exploradas ativamente.
- **TTP**: Tactics, Techniques and Procedures (MITRE ATT&CK) — usadas para refinar o GEL a partir de CVEs conhecidos.
- **RAG**: Retrieval-Augmented Generation — extrair a secção certa da base de conhecimento (benchmark, manual do serviço ingerido no build-time, NISTIR/CCSS) para dar ao LLM. Vive no build-time e na Camada 3 (`--assess-unknown`), nunca no scoring.
- **Self-consistency**: amostrar o LLM N vezes e fazer majority-vote por métrica; a taxa de acordo fica persistida como `confidence`.
- **Build time vs runtime**: a separação central — trabalho pesado uma vez, scans determinísticos sempre.
- **Attack chain**: combinação de misconfigs mais perigosa que a soma das partes.
- **Profile (AV/Au)**: as métricas que dependem do sistema concreto, decididas no scan.
- **Manifesto de reprodutibilidade**: hash SHA-256 do conteúdo da base de conhecimento (regras/chains/enrichment), impresso no rodapé de cada scan — mesmo hash ⇒ mesmos scores, por construção.
