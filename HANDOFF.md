# CASPAR — Briefing de Continuação (handoff)

> **Propósito:** dá este ficheiro a uma IA (ou a ti, noutra sessão/máquina) no
> início. Resume, com FACTOS VERIFICADOS, o que o projeto é, onde está, as
> decisões e invariantes que não se podem violar, e o que falta. Para detalhe:
> [README.md](README.md) (vitrine + comandos), [GUIA_CASPAR.md](GUIA_CASPAR.md)
> (utilizador/demo), [GUIA_TECNICO.md](GUIA_TECNICO.md) (arquitectura interna),
> [GUIA_TESTE_MAQUINA.md](GUIA_TESTE_MAQUINA.md) (setup + build Docker).
>
> **Última actualização:** 2026-07-06. Se números abaixo divergirem do repo,
> o repo manda — corre os comandos da secção "Verificação" e actualiza este
> ficheiro.

---

## 1. O que é o CASPAR

Framework Python que lê a configuração de um serviço (ficheiro, directório,
serviço instalado, imagem Docker, **ou ficheiro IaC**), a compara contra um
benchmark de segurança (CIS / DISA STIG) e atribui a cada problema um score
**CCSS 0–10** (Common Configuration Scoring System, **NISTIR 7502**) — com
narrativa, CVEs reais (NVD + CISA KEV), e detecção de *attack chains*.

**A decisão de arquitectura central (o argumento académico):** separação
estrita **build-time / runtime**.

- **Build-time** (corre UMA vez, por serviço): LLM local (Ollama), RAG sobre a
  base de conhecimento, lookups de rede. Produz regras + scores gravados em
  SQLite. Não-determinístico, pesado, offline-após-corrido.
- **Runtime** (cada scan): parse → lookup exacto → aritmética CCSS → relatório.
  **100% determinístico, zero LLM, zero rede.** Mesmo input ⇒ mesmo score,
  sempre — e isto é **auditável** pelo *manifesto de reprodutibilidade* (ver §5).

Estado: submissão **INForum 2026 já submetida** (pasta `caspar_inforum2026/`).
Foco actual: dissertação (avaliação empírica) + extensão IaC.

---

## 1b. Inventário de funcionalidades (o que o projeto FAZ)

Visão de capacidades — o *quê*, antes do *onde* (§4) e do *como-não-partir* (§6).

**Análise / scoring (núcleo):**
- Score **CCSS 0–10** por misconfiguration (NISTIR 7502), determinístico e
  reprodutível; base + temporal (GEL/GRL de CVEs).
- **4 modos de input:** ficheiro · directório (segue `include`s) · serviço
  instalado (`--live`) · imagem Docker (`docker://`).
- **Detecção de attack chains** — combinações de misconfigs que se amplificam
  (score amplificado, não somado); 27 chains na DB.
- **Enriquecimento por CVE real** — NVD + CISA KEV, cross-reference por versão
  detectada; exploits (Exploit-DB) quando há versão.
- **Detecção de directivas desconhecidas (3 camadas):** L1-2 determinísticas
  (surfacing + triagem heurística, sempre); L3 opt-in (`--assess-unknown`) usa
  LLM+RAG e produz candidatos de baixa confiança **nunca somados ao score**.
- **Perfis de ambiente** (`--profile production|internal|dev`) ajustam a
  exposição (AV) usada no scoring.

**Alvos suportados (11):** apache-httpd, nginx, ssh, mysql, redis, tomcat,
docker (daemon), ubuntu (OS hardening — sysctl/login.defs) · **IaC:**
kubernetes, dockerfile, azure-iac (Terraform/Bicep/ARM). Fontes: CIS Benchmark
(PDF), DISA STIG (XCCDF), curada. Formatos parseados: key-value, YAML,
Dockerfile, HCL, Bicep, ARM JSON.

**Avaliação / baselines** (`scripts/`): `evaluate.py` (composição da KB, MAE vs
CCE, recall nas fixtures); `baseline_compare.py` (CASPAR vs **Trivy** em IaC/
Docker; CASPAR vs **OpenSCAP** `--oscap` em Ubuntu OS). Ver §7.

**Gestão de plugins (build-time):**
- `plugin add` (extrai regras de um PDF CIS ou XCCDF STIG via LLM+RAG),
  `plugin fetch` (descarrega STIGs públicos — catálogo de **44 serviços** —,
  `--then-install`), `plugin manual` (ingere manual do serviço na base RAG).
- `build_azure` — extração + **mapeamento de vocabulário** (portal→IaC, §6.7).
- `curated_build` — build determinístico para rulesets curados (k8s/dockerfile).

**Relatórios e saída:**
- Terminal colorido; **HTML** rico; **dashboard** (offline/online); **JSON**;
  **SARIF** (integra com GitHub Code Scanning / anotações de PR).
- **Gates de CI:** `--threshold`, `--exit-code` (Critical→2, >threshold→1).
- `report --merge` (sumário executivo multi-scan); `badge` (shields.io).

**Ciclo de vida / operação:**
- `watch` — auditoria contínua (ficheiro/dir/`--live`), alerta em 1 linha ao
  mudar, `--log`, `--notify`; `history` (grava cada scan); **`trend`** (deriva
  do score no tempo, sparkline).
- `fix` — remediação assistida (reescreve valores inseguros; passos manuais).
- `promote` — candidata (L3) → regra permanente determinística; **`--stats`**
  mede o ciclo de aprendizagem.
- `suppress` — aceitar risco conhecido (excluído de scans/exit-code futuros).
- `explain` — origem completa de uma regra (secção CIS, CCSS, CVEs, narrativa),
  sem scan; `diff` (delta entre dois scans JSON); `doctor` (integridade da DB).

**Garantias transversais:**
- **Manifesto de reprodutibilidade** em cada scan (§5) — score auditável.
- **RAG build-time** — conhecimento ingerido uma vez, consultado sempre (§5).
- **Persistência Docker** — plugins/DB sobrevivem `--rm` via volume `caspar_data`.
- **602 testes** + CI; runtime **offline e determinístico** por construção.

---

## 2. Estado actual (verificado 2026-07-09)

- **Branch:** `master`, working tree limpo (tudo committed).
- **Testes:** **602** recolhidos, todos verdes offline. CI em GitHub Actions
  (`.github/workflows/ci.yml`) corre a suite completa a cada push (é offline-safe).
- **DB canónica** (`data/ccss_canonical.sql`, restaura para `ccss.db`): **488
  regras / 27 chains** em **11 targets**:

| Target | Regras | Proveniência das regras |
|---|---|---|
| apache-httpd | 35 | LLM (validado por MAE vs CCE) |
| nginx | 18 | LLM (revisão manual) |
| ssh | 17 | LLM |
| mysql | 23 | LLM |
| redis | 36 | STIG |
| tomcat | 49 | STIG |
| docker | 57 | LLM (config runtime do daemon) |
| **ubuntu** | 18 | **curada** (CIS Ubuntu 22.04 L1, subconjunto config) |
| **kubernetes** | 10 | **curada** (CIS K8s §5) |
| **dockerfile** | 5 | **curada** (CIS Docker) |
| **azure-iac** | 220 | **LLM + mapeamento de vocabulário** (CIS Azure) |

- **3 proveniências de conhecimento**, todas a alimentar o MESMO scoring
  determinístico: **LLM-extraída** · **curada** · **promovida** (ciclo `promote`).

---

## 3. Ambiente

- **Directório:** `~/caspar/` (WSL2 Ubuntu). Venv em `.venv/`.
- **Comando:** `caspar` (via `pip install -e .`) ou `python -m cli.main …`.
  ⚠️ Não existe `python` global com deps — usa **sempre** o venv:
  `source .venv/bin/activate` (ou `.venv/bin/python -m …`).
- **Deps runtime:** pydantic, click, **pyyaml** (parser K8s). Build: openpyxl,
  requests, pypdf. Sistema: `poppler-utils` (pdftotext), `sqlite3`.
- **LLM:** Ollama local. `qwen2.5:14b` (melhor) ou `7b` (~3-4× mais rápido).
  ~1-2 min/secção no 14b nesta máquina (CPU/GPU modesta) — os builds LLM são
  demorados e comem RAM (14b ≈ 9GB). **Correr testes SEMPRE um processo de cada
  vez** (5 pytests paralelos já esgotaram a RAM e derrubaram o WSL).
- **DB:** `ccss.db` (SQLite) na raiz; nunca committed (`*.db` gitignored),
  restaura-se do dump.

---

## 4. Arquitectura — o que mexer onde

**`config_assessment/core/`** — genérico, NÃO depende de nenhum serviço:
- `target.py` — interface `Target` (4 métodos: `detect`, `parse_config`,
  `get_profile`, `metadata`). **Adicionar um target = criar um plugin, zero
  alterações ao core.**
- `models.py` — dataclasses (Directive, Misconfiguration, SystemProfile,
  ScanResult[tem `manifest`], AttackChain, TargetMetadata).
- `ccss.py` — fórmulas NISTIR 7502 (base_score, temporal_score). **Aritmética
  pura — é o coração determinístico.**
- `runtime.py` — motor: `scan()`, `register_plugin()`, `_select_plugin()`,
  detecção de chains, unknown-directives (Camadas 1-2).
- `manifest.py` — manifesto de reprodutibilidade (§5).
- `db/database.py`, `db/schema.sql` — SQLite; `db/doctor.py` (integridade);
  `db/reseed.py` (semear DB do dump num volume, idempotente).
- `input_resolver.py` (file/dir/live/docker), `watch.py`, `unknown_directives.py`.
- `enrichment/cve_enricher.py`, `version_prefetch.py` (NVD + KEV).
- `reports/` (html, dashboard, sarif via `_to_sarif`, scan_features, remediation).
- `build/` — `rag.py` (BenchmarkIndex/TF-IDF), `llm_client.py` (Ollama+stub),
  `benchmark_extractor.py` (PDF CIS + XCCDF STIG), `plugin_scaffolder.py`,
  `curated_build.py` (build determinístico p/ regras curadas), `generic_build.py`.
- `fetch/benchmark_fetcher.py` + `catalog.json` (fetch de STIGs públicos).

**`config_assessment/parsers/`** — parsers genéricos, um por formato:
- `key_value.py` (apache/nginx/ssh/…), `yaml_flat.py` (K8s),
  `dockerfile.py`, `hcl_flat.py` (Terraform), `bicep_flat.py`, `arm_json.py`.

**`config_assessment/plugins/<target>/`** — um dir por target. Padrão mínimo:
`__init__.py` (subclasse `Target` + `register_plugin(...)`), `parser.py` (fino,
delega num parser genérico), `rules.py`, `chains.json` (opcional). O
`apache_httpd/` também aloja **código de build partilhado** (ver invariante §6.3).

**`cli/`** — `main.py` é só o entry point (grupo + registo dos comandos;
re-exporta nomes históricos). Implementação em:
`_output.py` (terminal+SARIF), `_discovery.py` (auto-descoberta de plugins),
`_knowledge.py` (base RAG build-time), e `commands/{scan,plugin,build,report,
manage}_cmds.py`. **Adicionar um comando = `commands/*_cmds.py` + registar em
`main.py`.**

**Comandos:** scan, watch · plugin (add/fetch/manual) · build, fetch-exploits,
refresh · targets, diff, badge, explain, history, **trend**, report ·
suppress, doctor, fix, **promote** (`--stats`).

---

## 5. Features-chave recentes (para não reinventar)

- **Manifesto de reprodutibilidade** (`core/manifest.py`): cada `ScanResult`
  grava versão do CASPAR + **SHA-256 da base de conhecimento** + nº regras.
  Rodapé do scan e campo `manifest` no JSON. *Mesmo manifesto + mesmo input ⇒
  mesmos scores*, verificável por terceiros. **É a forma auditável da tese.**
- **RAG build-time** (`cli/_knowledge.py`): conhecimento (benchmark + manual +
  NISTIR) ingerido UMA vez (`plugin add --manual`, `plugin manual <target>
  <path|url>`), descoberto do disco em cada scan via `_find_knowledge_docs` —
  **sem flag de runtime**. `--docs` é só escape hatch. PDFs ganham um `.md`
  sidecar (pdftotext, determinístico, auditável) na ingestão.
- **`trend`** — deriva do score no tempo (sparkline por input; `history` grava
  cada scan automaticamente).
- **`promote --stats`** — mede o ciclo de aprendizagem: quantas regras vieram
  de candidatas promovidas (marcadas na justificação), quantas esperam revisão.
- **NISTIR 7502 viaja no repo e na imagem Docker** (excepção explícita a
  `*.pdf` em `.gitignore` e `.dockerignore`) — a base CCSS partilhada da
  Camada 3 tem de existir em qualquer máquina, offline.

---

## 6. Invariantes e armadilhas (LER antes de mexer)

1. **Runtime é determinístico e sem LLM.** Nada de rede/LLM/aleatoriedade no
   caminho do `scan`. RAG e LLM vivem só no build-time e na Camada 3 (opt-in,
   `--assess-unknown`, cujos resultados são candidatos de baixa confiança
   **nunca somados ao score CCSS**).

2. **Lookup é match EXACTO** `(target_name, directive, bad_value)`. Se o parser
   guardar um valor diferente do que está na DB, a regra não dispara. Isto já
   partiu o `LoadModule` (caminho `.so` vs nome do módulo) e o vocabulário
   Azure. **Ver invariante 7.**

3. **Código de build partilhado vive em `plugins/apache_httpd/`** mas serve
   vários plugins (`llm_pipeline.py`, `chain_pipeline.py`,
   `narrative_pipeline.py`). Nginx/SSH importam-no de lá. NÃO duplicar. Migrá-lo
   para `core/build/` é um refactor pendente (ver §8).

4. **Builds são idempotentes** (upsert por chave / delete-not-in). A lista
   `ENTRIES` de cada `build_*.py` é a fonte da verdade. `curated_build.py` e
   `build_azure.py` fazem upsert — re-correr não duplica.

5. **Worst-case para AV/Au:** um `Listen`/`listen` não-loopback ⇒ AV=Network
   para todas as misconfigs do serviço; KEV força GEL:High. IaC assume AV=N/Au=N.

6. **Plugins auto-registam-se no import.** `_discover_plugins()` importa cada
   `plugins.*`, disparando `register_plugin()`. Em testes que chamam
   `runtime.scan` directamente, importar `cli.main as m; m._discover_plugins()`
   primeiro (ver `tests/test_iac_plugins.py`, `test_azure_iac_plugin.py`).

7. **Azure IaC — o problema do vocabulário (importante para a defesa).** O CIS
   Azure fala língua de *portal* ("Ensure 'Secure transfer required' is
   Enabled"); os ficheiros falam `https_traffic_only_enabled` (Terraform) ou
   `supportsHttpsTrafficOnly` (Bicep/ARM). `build_azure.py` acrescenta um estágio
   de **mapeamento de vocabulário**: o LLM (ancorado via RAG no benchmark) mapeia
   cada controlo para o atributo exacto em AMBOS os vocabulários → 1 controlo =
   2 regras, 1 build serve `.tf`/`.bicep`/`.json`. Validações aprendidas em runs
   reais (qwen2.5): rejeita caminhos com pontos (guarda a folha — parsers põem
   pais no contexto), rejeita `bad_value` None/JSON-blob/prosa/pipe-alternativas
   (`_is_matchable_value`), rejeita impacto C:N/I:N/A:N (score 0 = regra morta).
   `canon.py` normaliza sinónimos booleanos (`off`/`OFF`/`Disabled` → `false`)
   nos DOIS lados (regra e config parseada), para casarem numa forma canónica —
   **sem tocar no runtime nem nos outros targets**.

8. **Regenerar a DB canónica após um build.** Depois de `build_azure`/curated
   gravarem em `ccss.db`, **tens de** regenerar o dump para as regras viajarem:
   ```bash
   # a caspar_meta é precisa (reseed) e o .dump só a inclui se existir na DB:
   sqlite3 ccss.db "CREATE TABLE IF NOT EXISTS caspar_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL); INSERT OR REPLACE INTO caspar_meta VALUES('base_db_version','2');"
   sqlite3 ccss.db .dump > data/ccss_canonical.sql
   ```
   Sem a `caspar_meta` no dump, `tests/test_reseed.py` parte. (Já mordeu.)

9. **PDFs de benchmark são material licenciado** — gitignored, NÃO viajam no
   git nem na imagem (excepto o NISTIR). Por isso 13 testes RAG do apache fazem
   *skip* num clone limpo/CI — normal, não é falha. Copiar os PDFs à mão só é
   preciso para correr um build LLM.

10. **Imagens Docker: `latest` primeiro, `full` depois** (`caspar:full` é
    `FROM caspar:latest`). Ordem inversa = código velho na `full`. O build LLM
    (`plugin add`, `build_azure`) precisa da `:full` (Ollama embutido). Os
    comandos/regras novos só entram nas imagens após **rebuild** — ver
    [GUIA_TESTE_MAQUINA.md](GUIA_TESTE_MAQUINA.md) §3.

---

## 7. Validação da metodologia (estado + resultados)

**Correr tudo:** `python -m scripts.evaluate` (relatório consolidado) e
`python -m scripts.baseline_compare [--oscap]` (comparação com baselines).

**Resultados verificados (2026-07-09):**
- **Correção — MAE vs ground truth CCE** (`plugins/apache_httpd/validate_mae.py`):
  Apache **20/20 matched, 0 mismatch (0.0%), gate PASS** contra as faixas de
  severidade DISA do dataset CCE oficial. É a evidência quantitativa mais forte.
  (Precisa de `openpyxl` — já instalado no venv.)
- **Deteção — recall nas fixtures vulneráveis** (`scripts/evaluate.py`):
  **100% (14/14)** — nginx, azure-iac, kubernetes, dockerfile.
- **Reprodutibilidade** (manifesto, §5): consistência interna verificável.
- **Baseline Trivy** (`scripts/baseline_compare.py`): CASPAR vs Trivy no MESMO
  ficheiro — `azure_storage_vulnerable.tf` (9 vs 13), `Dockerfile.vulnerable`
  (4 vs 5). Achado: o Trivy apanhou `https_traffic_only_enabled` que o build LLM
  perdeu (mapeou o sinónimo `secure_transfer_required`) — blind spots distintos.
- **Baseline OpenSCAP** (`--oscap`): corre `oscap` no sistema vivo (CIS L1),
  filtra o subconjunto config-based que o target `ubuntu` cobre. **Validado num
  Ubuntu 22.04 real (2026-07-09): 38 regras sobreponíveis, 24 fail / 1 pass
  REAIS** (no WSL de dev dava `notapplicable` — os probes OVAL precisam de um
  sistema real). A diferença de escopo (CASPAR pontua FICHEIROS; OpenSCAP audita
  ESTADO do sistema vivo) é ela própria um achado da tese.

**→ A PARTE PRÁTICA ESTÁ FECHADA E VALIDADA** num Ubuntu 22.04 real: 602 testes,
13/13 smoke, MAE 0%, recall 100%, e 3 baselines (Trivy IaC, Trivy Docker,
OpenSCAP OS com pass/fail reais). O material consolidado para a tese está em
[DISSERTACAO_REFERENCIA.md](DISSERTACAO_REFERENCIA.md).

**Fixtures de demonstração** em `test_target/`: `azure_storage_vulnerable.tf`,
`pod_vulnerable.yaml`, `Dockerfile.vulnerable`, `ubuntu_demo/sysctl.conf`.

**Opções por explorar** (para reforçar a tese): Precision/Recall/F1 num corpus
rotulado maior · `promote --stats` a medir o valor incremental do LLM ·
concordância inter-avaliador (Cohen's κ) nas submétricas CIA · ablação (com/sem
RAG, 7b vs 14b). **Limitação a declarar:** azure-iac/k8s/dockerfile/ubuntu não
têm ground truth CCE — validam-se por recall nas fixtures + baselines, não por MAE.

---

## 8. O que falta / próximos passos (por valor)

> **CÓDIGO FECHADO (2026-07-11).** A parte prática está completa e validada
> (ver §7). Os itens abaixo são **polimento opcional** — NENHUM bloqueia a tese.
> O foco passou a ser a **escrita da dissertação** ([[caspar-practical-closed]];
> material-fonte em [DISSERTACAO_REFERENCIA.md](DISSERTACAO_REFERENCIA.md)).
>
> ✅ **Feito** (já não pendente): avaliação empírica (MAE 0%, recall 100%, 3
> baselines — `scripts/evaluate.py` + `baseline_compare.py`); justificação das
> bandas de amplificação (DISSERTACAO_REFERENCIA §3.7 — é texto de tese, não
> código).

Polimento opcional que fica (por valor):
1. **Rebuild + push das imagens Docker** — só importa se as imagens PÚBLICAS
   forem usadas (a avaliação foi nativa). `latest`→`full` (invariante 10).
2. **Colisões Azure** — `pricing_tier Free/free` etc.: a `canon.py` cobre
   booleanos, faltam SKUs/tiers. Cosmético.
3. **Refactor:** mover build partilhado `apache_httpd/` → `core/build/`
   (invariante 3).
4. **Mais attack chains** (nginx/azure/k8s têm poucas; mecanismo já provado).
5. Dívidas menores: 2 warnings de deprecação do pytest (fixture class-scoped em
   `test_llm_pipeline.py`); versão `0.1.0` duplicada (`pyproject.toml` +
   `manifest.py`) — sincronizar num bump.

---

## 9. Verificação (corre isto para confirmar o estado)

```bash
cd ~/caspar && source .venv/bin/activate

python -m pytest tests/ -q                 # ~602 passed (uns skips se faltam PDFs)
caspar doctor                              # ✓ healthy
caspar targets                             # 11 targets (+ dummy), incl. ubuntu/azure-iac/k8s/dockerfile
caspar scan test_nginx.conf                # ≈5.7 [Medium]
caspar scan test_target/azure_storage_vulnerable.tf   # ≈8.5 [High] (Terraform)
caspar scan test_target/pod_vulnerable.yaml           # ≈10.0 [Critical] + chain
caspar scan test_target/ubuntu_demo/sysctl.conf       # ≈5.8 [Medium] (Ubuntu OS)

# avaliação + baselines (material da tese):
python -m scripts.evaluate                 # KB · MAE 0% · recall 100%
python -m scripts.baseline_compare --oscap # CASPAR vs Trivy / OpenSCAP

# contagens da DB (devem bater com a tabela do §2):
sqlite3 ccss.db "SELECT target_name, count(*) FROM misconfigurations GROUP BY target_name"
```

## 10. Preferências de trabalho

- **A dissertação é escrita em INGLÊS.** (Estes guias de projecto e os
  comentários/output do código estão em Português Europeu — mantê-los; só o
  texto académico da tese é que é em inglês.)
- Patches cirúrgicos > reescrever ficheiros inteiros. Validar SEMPRE com um
  teste/scan funcional real antes de dar por concluído.
- Testes: **um processo de cada vez** (RAM do WSL). Medir `free -h` à volta de
  builds LLM.
- Ao mexer em regras/DB: regenerar o dump (invariante 8) e correr a suite.
