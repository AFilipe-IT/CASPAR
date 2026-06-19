# CCSS-Scan — Briefing de Continuação (handoff para Claude Code / VSCode)

> Dá este ficheiro ao Claude no VSCode no início da sessão. Resume o estado do
> projeto, as decisões tomadas, as armadilhas conhecidas e o que falta. Para
> detalhe completo, lê `GUIA_TECNICO.md` e `README.md` (estão actualizados).

---

## O que é o projeto

CCSS-Scan: framework Python de scoring de configurações de segurança baseada no
NISTIR 7502 (CCSS). Projeto académico para submissão ao **INForum 2026** (ainda
não submetido). Lê a config de um serviço, compara contra o CIS Benchmark,
atribui um score 0–10 auditável e reprodutível.

**Decisão de arquitectura central (o argumento académico):** separação estrita
**build-time / runtime**. O trabalho pesado (LLM Ollama, RAG sobre o CIS PDF,
CVE lookup) acontece UMA vez no build e fica gravado em SQLite. Cada scan é
depois 100% determinístico: parse → lookup → aritmética → relatório. Sem LLM,
sem internet, mesmo resultado sempre.

## Ambiente

- WSL2 Ubuntu, projeto em `~/ccss_scan/`, venv em `.venv/` (`source .venv/bin/activate`)
- Comando `ccss` instalado via `pip install -e .`
- LLM: Ollama `qwen2.5:14b` (local; ~3 min/narrativa nesta máquina — CPU/GPU modesta)
- Base de dados: `ccss.db` (SQLite) na raiz do projeto
- `pytest tests/ -v` → 183 testes a passar

## Estado: Fase 1 ✅, Fase 2 ✅, Fase 3 funcional ✅

**Fase 2 — Apache (fechada, validada):**
- Plugin completo: parser, rules, 30 misconfigurations
- 3 stages LLM (métricas, attack chains, narrativas), CVE enrichment (NVD+KEV)
- 9 attack chains; 4 modos de scan; relatórios terminal/HTML/dashboard/JSON/SARIF
- 0% mismatch contra ground truth CCE (validação quantitativa via MAE)
- Teste de cobertura automatizado (`tests/test_full_coverage.py`)

**Fase 3 — Nginx (funcional, paridade de relatório):**
- Plugin em `plugins/nginx/`: parser próprio (sintaxe `{}`/`;`), rules, detecção, build
- 8 misconfigurations ancoradas em secções CIS NGINX v3.0.0 REAIS
- Build (Stage 1) + narrativas (Stage 3) funcionam para Nginx
- Validado em 3 imagens Docker reais (nginx:latest, nginx:1.25, bitnami/nginx)

## Arquitectura: o que mexer onde

- `core/` — genérico, NÃO depende de nenhum serviço:
  - `target.py` (interface `Target`: detect, parse_config, get_profile, metadata)
  - `models.py` (dataclasses: Directive, Misconfiguration[tem campo `narrative`], SystemProfile, ScanResult, TargetMetadata, AttackChain)
  - `ccss.py` (fórmulas NISTIR 7502), `runtime.py` (motor: scan, register_plugin, _select_plugin)
  - `rag.py` (BenchmarkIndex/TF-IDF sobre o CIS PDF), `cve_enricher.py`, `input_resolver.py`
  - `report_html.py`, `report_dashboard.py`, `report_dashboard_online.py`
  - `db/schema.sql`, `db/database.py`
- `plugins/apache_httpd/` — plugin Apache + **código de build genérico** (ver armadilha abaixo)
- `plugins/nginx/` — plugin Nginx (parser, rules, __init__, build_nginx.py, CIS PDF)
- `cli/main.py` — comandos scan/build/targets/refresh; `_discover_plugins()` importa cada `plugins.*`

## Armadilhas e invariantes (LER antes de mexer)

1. **Plugins auto-registam-se no import.** O `_discover_plugins()` do CLI importa
   cada `plugins.*` e isso dispara `register_plugin()`. Em testes isolados que
   chamam `runtime.scan` directamente, é preciso importar o plugin primeiro
   (ver a fixture `_register_plugins` em `tests/test_full_coverage.py`).

2. **Lookup é por match EXACTO** `(target_name, directive, bad_value)`. Se o
   parser guardar um valor diferente do que está no banco, não dispara. Foi
   isto que partiu o LoadModule (guardava o caminho `.so`; o banco tem só o
   nome do módulo). Corrigido no parser do Apache.

3. **Código de build genérico vive em `plugins/apache_httpd/`** mas serve AMBOS
   os plugins: `llm_pipeline.py`, `chain_pipeline.py`, `narrative_pipeline.py`,
   `build_llm.py`, `build_narratives.py`. O Nginx importa-os de lá. Idealmente
   migrariam para `core/` (refactor pendente). NÃO duplicar — reutilizar.

4. **Build é idempotente** (já corrigido): `db.delete_misconfigurations_not_in()`
   apaga órfãs antes de inserir. A lista `ENTRIES` de cada `build_*.py` é a
   fonte única da verdade. Reduzir a lista e refazer o build remove as antigas.

5. **Worst-case para AV/Au:** se há um `listen`/`Listen` não-loopback, AV=Network
   para todas as misconfigs do serviço. KEV força GEL:High.

6. **Numeração de secções CIS:** o regex do `rag.py` aceita IDs de 2+ níveis
   (`8.1` Apache, `2.5.1` Nginx). Cada `MisconfigEntry` deve apontar a uma
   secção REAL do PDF — verificar com o `BenchmarkIndex` antes do build, senão o
   LLM gera narrativas sem contexto (foi o que aconteceu e corrigimos).

7. **Prompts são target-agnostic:** `narrative_pipeline.py` recebe `service_name`.
   Não voltar a colar "Apache"/"httpd" hardcoded.

## Preferências de trabalho

- Patches `fix_*.py` cirúrgicos > reescrever ficheiros inteiros.
- Validar SEMPRE com teste funcional antes de aplicar.
- Escrita académica em **Português Europeu** (não brasileiro).
- Decisão tomada: **Nginx sem CCE/MAE** (validação por revisão manual; o Apache
  é o caso quantitativo). Só directivas com secção CIS dedicada.

## O que falta (candidatos, por valor)

- **Resultados para o artigo INForum** (provavelmente prioritário): números
  consolidados — nº misconfigs, MAE Apache, tempos de build, deteções em imagens
  Docker reais.
- **Attack chains do Nginx** (tem 0 vs 9 do Apache).
- **Teste de cobertura do Nginx** (como `tests/test_full_coverage.py` do Apache).
- **Refactor:** mover código de build genérico `apache_httpd/` → `core/`.
- **Fundamentação teórica das bandas de amplificação** das chains (×1.2–1.8) —
  é heurística original do trabalho, precisa de justificação na tese.
- Plugins SSH / Ubuntu / Docker.
- Fixes triviais: `datetime.utcnow()` deprecated em test_apache.py/test_runtime.py;
  limpar `*.Zone.Identifier`.

## Como verificar que está tudo bem

```bash
source .venv/bin/activate
pytest tests/ -v                              # deve dar 183 passed
ccss targets                                  # lista apache-httpd, dummy, nginx
ccss scan test_nginx.conf                     # 3 Medium
ccss scan docker://nginx:latest --report --format dashboard --output ~/relatorios/
```
