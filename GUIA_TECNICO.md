# CCSS-Scan — Guia Técnico do Projeto

> Documento para perceberes o projeto de ponta a ponta: como está organizado,
> como os dados fluem, onde mexer para cada tipo de alteração, e o que cada
> ficheiro faz. Lê de cima a baixo uma vez; depois usa como referência.

---

## 1. A ideia em três frases

O CCSS-Scan lê a configuração de um serviço (Apache, por agora), compara cada directiva contra o CIS Benchmark, e atribui um score de segurança 0–10 baseado no standard NISTIR 7502 (CCSS). O trabalho pesado — perceber o que cada má configuração significa, atribuir métricas, escrever narrativas, procurar CVEs — acontece **uma vez** no *build time*, usando um LLM local, e fica gravado numa base SQLite. Cada *scan* depois é **100% determinístico**: lê a config, procura na base, faz aritmética, produz o relatório — sem LLM, sem internet, mesmo resultado sempre.

Esta separação build/runtime é a decisão de arquitetura mais importante do projeto e o que o torna defensável academicamente: os scores são reprodutíveis e auditáveis.

---

## 2. Os dois tempos do sistema

### Build time (corre raramente — quando montas ou actualizas a base)

```
CIS Benchmark PDF + CCE XLS + NISTIR 7502
        │
        ├─ RAG (TF-IDF) extrai a secção relevante do benchmark por directiva
        │
        ├─ STAGE 1 (llm_pipeline.py): LLM lê cada recomendação CIS e atribui
        │           as métricas base AC, C, I, A + escreve justificação curta
        │
        ├─ STAGE 2 (chain_pipeline.py): LLM olha para todas as misconfigs já
        │           pontuadas e identifica combinações perigosas (attack chains)
        │
        ├─ STAGE 3 (narrative_pipeline.py): LLM escreve, por misconfig, a
        │           narrativa rica — descrição, impacto, cenário de exploração,
        │           justificação detalhada de cada métrica
        │
        └─ CVE enrichment (cve_enricher.py): procura CVEs reais na NVD + CISA
                    KEV e ajusta as métricas temporais GEL/GRL
        │
        ▼
   ┌──────────────┐
   │  ccss.db     │   30 misconfigs + métricas + narrativas + attack chains
   └──────────────┘
```

### Runtime (corre em cada scan — rápido, determinístico)

```
input (ficheiro / pasta / serviço live / imagem docker)
   │
   ├─ input_resolver.py  → resolve o input para um caminho concreto de config
   ├─ parser.py          → lê a config e produz uma lista de Directives
   ├─ rules.py           → decide AV e Au com base na config concreta (worst-case)
   ├─ lookup na ccss.db  → para cada directiva má, vai buscar a entrada pré-calculada
   ├─ ccss.py            → recalcula os scores com o AV/Au reais deste sistema
   ├─ deteção de chains  → vê quais combinações estão todas presentes
   ├─ agregação          → score global = pior caso
   │
   ▼
ScanResult → terminal / HTML / JSON / SARIF
```

**Porque é que AV e Au são runtime e não build time?** Porque dependem do sistema concreto. A mesma directiva `AllowOverride All` é mais perigosa se o servidor estiver exposto à rede (AV=Network) do que se só escutar em localhost (AV=Local). O LLM não pode saber isto no build — só o scan do sistema real sabe. Por isso o build calcula AC/C/I/A (intrínsecos à directiva) e o runtime calcula AV/Au (dependem do ambiente) e combina os dois.

---

## 3. Mapa de ficheiros — o que mexer para cada coisa

### Núcleo genérico (`core/`) — não depende de Apache

| Ficheiro | Responsabilidade | Mexes aqui quando… |
|---|---|---|
| `target.py` | Interface abstrata que todo plugin implementa | Adicionas um conceito novo a todos os plugins |
| `models.py` | Dataclasses: `Directive`, `Misconfiguration`, `SystemProfile`, `ScanResult` | Adicionas um campo novo aos dados (ex: foi aqui que adicionámos `narrative`) |
| `ccss.py` | As fórmulas NISTIR 7502 e os pesos das métricas | Mudas como os scores são calculados |
| `runtime.py` | O motor de scan — orquestra parse→lookup→score→agregação | Mudas a lógica do que acontece durante um scan |
| `input_resolver.py` | Resolve os 4 modos de input para um caminho | Adicionas um modo de scan novo |
| `report_html.py` | Gera o relatório HTML | Mudas o aspeto ou conteúdo do HTML |
| `cve_enricher.py` | NVD API + CISA KEV → GEL/GRL | Mudas como os CVEs são procurados/pontuados |
| `llm_client.py` | Wrapper do Ollama (+ stub para testes) | Mudas de modelo LLM ou backend |
| `rag.py` | TF-IDF sobre o benchmark | Mudas como o contexto é extraído para o LLM |
| `db/schema.sql` | Definição das 4 tabelas | Adicionas/alteras colunas (lembra: também tens de migrar) |
| `db/database.py` | Todas as queries e o `_row_to_misconfiguration` | Adicionas um campo (tens de o ler aqui também!) |

### Plugin Apache (`plugins/apache_httpd/`) — específico do Apache

| Ficheiro | Responsabilidade |
|---|---|
| `parser.py` | Lê `httpd.conf`, segue `Include`, produz `Directive`s |
| `rules.py` | Regras AV/Au específicas do Apache (lê `Listen`, `AuthType`) |
| `llm_pipeline.py` | Stage 1 — métricas via LLM |
| `chain_pipeline.py` | Stage 2 — attack chains via LLM |
| `narrative_pipeline.py` | Stage 3 — narrativas via LLM |
| `build_llm.py` | Entry point que corre Stage 1 + 2 |
| `build_narratives.py` | Entry point que corre Stage 3 |
| `refresh_cve.py` | Entry point do CVE enrichment |
| `chains.json` | Fallback de chains se o LLM falhar |
| `build_apache.py` | Fallback de 30 misconfigs hard-coded |
| `validate_mae.py` | Valida scores contra o ground truth CCE |

> **Nota de arquitectura (Fase 3):** apesar de viverem na pasta `apache_httpd/`,
> os ficheiros `llm_pipeline.py`, `chain_pipeline.py`, `narrative_pipeline.py`,
> `build_llm.py` e `build_narratives.py` são **genéricos** — servem qualquer
> plugin. O plugin Nginx reutiliza-os tal como estão. Idealmente migrariam para
> `core/` (refactor futuro); por agora o Apache é a "casa" do código de build
> partilhado.

### Plugin Nginx (`plugins/nginx/`) — específico do Nginx

| Ficheiro | Responsabilidade |
|---|---|
| `parser.py` | Parser de raiz para a sintaxe Nginx (blocos `{}`, directivas `;`, `include`, contexto hierárquico `http>server>location`) |
| `rules.py` | Regras AV/Au específicas do Nginx (lê `listen`, `auth_basic`, `auth_request`) |
| `__init__.py` | Classe `NginxPlugin(Target)` + detecção (distingue de Apache) + auto-registo |
| `build_nginx.py` | Entry point do build — lista `ENTRIES` (8 misconfigs ancoradas no CIS NGINX v3.0.0); reutiliza o pipeline genérico do Apache |
| `CIS_NGINX_Benchmark_v3.0.0.pdf` | O benchmark-fonte para o RAG |


### CLI (`cli/main.py`)

Define os comandos: `scan`, `build`, `targets`, `refresh`. É o ponto de entrada de tudo. A função `scan` orquestra: resolve input → corre runtime → imprime terminal → gera relatórios → limpa temporários.

---

## 4. O fluxo de dados de uma misconfiguration (exemplo concreto)

Segue `AllowOverride All` do build ao relatório:

1. **Build, Stage 1**: o LLM lê a secção 4.4 do CIS Benchmark, percebe que `AllowOverride All` permite `.htaccess` sobreporem a config, e atribui `AC=M, C=P, I=P, A=N`. Calcula `base_score = 5.8`. Grava na `ccss.db`.

2. **Build, Stage 3**: o LLM escreve a narrativa — descrição, 3 impactos, cenário com exemplo de `.htaccess` malicioso, e justificação de cada métrica. Grava no campo `narrative` (JSON).

3. **Build, CVE**: não há CVE associado a esta directiva, fica `GEL=L, GRL=H`. `temporal_score = 5.8 × 0.93 × 1.0 = 5.4`.

4. **Runtime, scan**: o parser encontra `AllowOverride All` em duas `<Directory>` no ficheiro. As `rules.py` veem que há um `Listen 80` (rede) e nenhum `AuthType`, por isso `AV=N, Au=N`. O runtime vai à base buscar a entrada de `AllowOverride All`, aplica o AV/Au reais, confirma `temporal_score = 5.4`.

5. **Relatório**: o HTML mostra o score 5.4, as métricas com justificação, os impactos, o cenário, e — graças ao snippet — o bloco real das duas `<Directory>` com a linha destacada.

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
- **GEL** (Exploit Level): existe exploit ativo? None→High. *CVE enrichment.*
- **GRL** (Remediation Level): há correção oficial? Unavailable→Official. *CVE enrichment.*

**As fórmulas** (em `ccss.py`):
```
f_impact  = 10.41 × (1 − (1−C)(1−I)(1−A))
f_exploit = 20 × AV × Au × AC
BaseScore = ((0.6 × f_impact) + (0.4 × f_exploit) − 1.5) × 1.176
TemporalScore = BaseScore × GEL × GRL
```

Regras especiais que vale a pena saber:
- **Worst-case AV/Au**: se o serviço está exposto à rede, todas as misconfigs ganham AV=Network.
- **KEV força GEL=High**: se um CVE está na CISA Known Exploited Vulnerabilities, o GEL sobe para High independentemente do CVSS.

---

## 6. Attack chains — e o ponto delicado

Uma chain é uma combinação de misconfigs que juntas são mais perigosas que a soma. Ex: `User=root` + `Group=root` = escalada total de privilégios.

O Stage 2 pede ao LLM para identificar estas combinações e atribuir um **factor de amplificação** (×1.2 a ×1.8) conforme a severidade das partes. O score da chain é `pior_parte × factor`, com teto em 10.

**O que precisas de saber para a tese:** este factor de amplificação é uma **heurística proposta por ti**, não vem do NISTIR 7502. O standard define como pontuar misconfigs isoladas mas é silencioso sobre como compô-las em cadeias. Isto é uma contribuição original — boa para o artigo, mas precisa de ser justificada (porquê estas bandas? idealmente alguma validação). Nos relatórios o multiplicador não é mostrado como número solto; só aparece o score final.

---

## 7. Como operar o projeto (comandos)

```bash
# Ativar ambiente (sempre primeiro)
cd ~/ccss_scan && source .venv/bin/activate

# ── Construir a base (build time) ──
ccss build --benchmark plugins/apache_httpd/Benchmark.pdf --model qwen2.5:14b
python3 -m plugins.apache_httpd.build_narratives --db ccss.db --model qwen2.5:14b
ccss refresh                              # CVE enrichment

# ── Fazer scans (runtime) ──
ccss scan /tmp/httpd.conf                 # ficheiro
ccss scan /etc/apache2/                   # pasta
ccss scan --live apache2                  # serviço instalado
ccss scan docker://httpd:2.4              # imagem docker

# ── Com relatório ──
ccss scan docker://ccss-test-apache:vulnerable --report --output ~/relatorios/
ccss scan /etc/apache2/ --report --format json
ccss scan /etc/apache2/ --threshold 7.0   # exit 1 se score > 7 (CI/CD)

# ── Utilitários ──
ccss targets                              # lista plugins
pytest tests/ -v                          # corre os testes
python3 fix_ac_consistency.py --db ccss.db --dry-run   # verifica narrativas
```

---

## 8. Receitas de modificação comuns

**"Quero adicionar uma misconfiguration nova ao Apache"**
→ Não edites código. Corre `ccss build` de novo (o LLM extrai do benchmark) ou adiciona ao `build_apache.py` (fallback). Depois `build_narratives` para gerar a narrativa, e `refresh` para CVEs.

**"Quero mudar como o HTML aparece"**
→ Só `core/report_html.py`. A função `generate_html` constrói tudo; `render_issue` faz cada card; `mrow` faz cada linha de métrica. O CSS está na variável `CSS` no topo.

**"Quero mudar o que o LLM escreve nas narrativas"**
→ `narrative_pipeline.py`, função `_build_prompt` (o que é pedido) e `_SYSTEM_PROMPT` (as regras). Depois re-corre `build_narratives`.

**"Quero adicionar um campo novo aos dados"**
→ Três sítios, sempre: (1) `models.py` na dataclass, (2) `schema.sql` + migração em `database.py`, (3) `_row_to_misconfiguration` em `database.py` para o ler. Esquecer o (3) foi o bug do `narrative` que tivemos.

**"Quero adicionar um serviço novo (Nginx, SSH…)"**
→ Cria `plugins/<nome>/` com os 4 ficheiros base (parser, rules, e os pipelines). Zero mudanças no `core/`. É exatamente isto a Fase 3.

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
→ Só `core/ccss.py`. Mas cuidado: muda a validação contra o ground truth CCE.

---

## 9. Estado atual (Fase 3 em curso — plugin Nginx funcional)

**Fase 2 (Apache) — fechada e validada:**
- 4 modos de scan, todos testados em máquina real
- Os 3 stages do LLM pipeline (métricas, chains, narrativas)
- CVE enrichment com NVD + KEV, key ativa
- Relatórios terminal / HTML / dashboard / JSON / SARIF
- 0% mismatch contra o ground truth CCE
- 30 misconfigurations, teste de cobertura automatizado que garante deteção completa

**Fase 3 (Nginx) — plugin funcional, paridade de relatório:**
- Parser de raiz para a sintaxe Nginx (blocos `{}` / `;`), distinta do Apache
- Detecção que distingue Nginx de Apache pelo conteúdo
- 8 misconfigurations, todas ancoradas em secções CIS NGINX v3.0.0 reais
- Build (Stage 1) + narrativas (Stage 3), agora **target-agnostic**
- Dashboard completo com drawer rico e terminologia 100% Nginx

**O que a Fase 3 expôs e corrigiu (acoplamentos implícitos ao Apache):**
Adicionar o 2.º plugin revelou três sítios onde o "core" assumia o formato Apache.
Corrigi-los tornou o sistema genuinamente extensível — é a evidência concreta de
extensibilidade para a tese:
1. **Parser RAG** (`core/rag.py`): o regex de secções só aceitava IDs de 2 níveis
   (`8.1`, estilo Apache); o CIS NGINX usa 3 (`2.5.1`). Generalizado para 2+ níveis.
2. **Prompt de build** (`llm_pipeline.py`): dizia "Apache HTTP Server" fixo.
3. **Prompt de narrativas** (`narrative_pipeline.py`): idem + "httpd.conf".
   Ambos passaram a receber o nome do serviço dinamicamente (`service_name`).

**Decisões de design da Fase 3 (limitações honestas):**
- **Sem CCE/MAE para Nginx**: o NGINX não tem ground truth CCE publicado como o
  Apache. O Nginx é validado por **revisão manual**; o Apache continua o caso de
  validação quantitativa. São contribuições complementares, não equivalentes.
- **Sem attack chains Nginx ainda**: 0 vs 9 do Apache (trabalho futuro).
- **Só directivas com secção CIS dedicada**: directivas sem âncora no benchmark
  (ex.: `autoindex`, `ssl_prefer_server_ciphers`) foram deliberadamente excluídas
  para manter cada misconfiguration rastreável à fonte.

**Pontos a ter em mente (transversais):**
- O factor de amplificação das chains precisa de fundamentação teórica para a tese
- As narrativas LLM são revisão-humana-recomendada (mitigadas, não garantidas)
- O build é agora **idempotente** (refazer com lista menor remove órfãs)
- O tempo de build LLM na máquina de referência é ~3 min/narrativa (CPU/GPU modesta)

**Por fazer (Fases 3-6):**
- Attack chains do Nginx; teste de cobertura Nginx
- Migrar o código de build genérico para `core/`
- Plugins SSH, Ubuntu, Docker
- Scheduler de refresh automático de CVE; report PDF; validação inter-analista (MAE)

---

## 10. Glossário rápido

- **CCSS**: Common Configuration Scoring System (NISTIR 7502) — o standard que dá o score.
- **CIS Benchmark**: o documento que diz o que é uma boa/má configuração.
- **CCE**: Common Configuration Enumeration — IDs de configurações, usados como ground truth.
- **CVE / NVD / KEV**: vulnerabilidades conhecidas / base de dados nacional / lista de exploradas ativamente.
- **RAG**: Retrieval-Augmented Generation — extrair a secção certa do benchmark para dar ao LLM.
- **Build time vs runtime**: a separação central — trabalho pesado uma vez, scans determinísticos sempre.
- **Attack chain**: combinação de misconfigs mais perigosa que a soma das partes.
- **Profile (AV/Au)**: as métricas que dependem do sistema concreto, decididas no scan.
