# AMiSA / CASPAR — Referência para a Dissertação

> **Propósito:** documento único e verificado com tudo o que a dissertação
> precisa — funcionalidades, arquitectura/implementação, e validação com
> resultados finais (verificados num Ubuntu 22.04 real). A tese escreve-se em
> **inglês**; este documento é o material-fonte em Português Europeu.
>
> **Metodologia:** AMiSA — *A methodology for the automated and quantitative
> assessment of security misconfigurations in systems and services*.
> **Prova de conceito:** CASPAR (o código deste repositório).
> **Estado:** parte prática FECHADA e validada (2026-07-09). Adenda pós-fecho:
> replicação NISTIR 7502 18/18 (2026-07-14) e experiência de determinismo da
> extração LLM (2026-07-18), motivadas pelo feedback dos revisores do INForum
> (§6).

---

## 1. A contribuição (o argumento científico)

**Problema.** Os benchmarks de segurança (CIS, DISA STIG) descrevem
recomendações em prosa; as ferramentas existentes dão veredictos binários
(pass/fail) sem uma medida de risco reproduzível e explicável.

**Contribuição (AMiSA).** Uma metodologia para transformar benchmarks em
**scores CCSS (NISTIR 7502) reproduzíveis e auditáveis** de misconfigurations,
com a separação **build-time / runtime** como garantia central:

- **Build-time** (uma vez, por serviço): um LLM local (**qwen2.5:14b** via
  Ollama, temperatura 0.1 — declarar sempre na tese, os revisores exigiram-no),
  ancorado por RAG no benchmark, extrai regras e atribui submétricas.
  Não-determinístico em teoria; estabilidade medida empiricamente em §4.7.
- **Runtime** (cada scan): parse → lookup exacto → aritmética CCSS. **100%
  determinístico, offline.** Mesmo input ⇒ mesmo score, sempre.

Esta separação é o que permite usar um oráculo não-determinístico (o LLM) e
ainda assim garantir scores determinísticos — verificável pelo *manifesto de
reprodutibilidade* (§3.6).

---

## 2. Funcionalidades (o que o sistema faz)

### 2.1 Análise e scoring
- **Score CCSS 0–10** por misconfiguration (base + temporal, NISTIR 7502).
- **4 modos de input:** ficheiro · directório (segue `include`s) · serviço
  instalado (`--live`) · imagem Docker (`docker://`).
- **Attack chains:** combinações de misconfigs que se amplificam (score
  amplificado, não somado).
- **Enriquecimento por CVE:** NVD + CISA KEV, cross-reference por versão;
  exploits (Exploit-DB) quando há versão detectada.
- **Detecção de directivas desconhecidas (3 camadas):** L1-2 determinísticas
  (surfacing + triagem heurística); L3 opt-in (`--assess-unknown`) via LLM+RAG,
  candidatos de baixa confiança **nunca somados ao score**.
- **Perfis de ambiente** (`--profile production|internal|dev`) ajustam a
  exposição (AV) no scoring.

### 2.2 Alvos suportados (11)
| Categoria | Alvos |
|---|---|
| Servidores web/app | apache-httpd, nginx, tomcat |
| Bases de dados | mysql, redis |
| Sistema / daemon | ssh, docker (daemon), **ubuntu** (OS hardening) |
| **IaC** | **kubernetes**, **dockerfile**, **azure-iac** (Terraform/Bicep/ARM) |

Formatos parseados: key-value, YAML, Dockerfile, HCL, Bicep, ARM JSON.

### 2.3 Gestão de conhecimento (build-time)
- `plugin add` (extrai de PDF CIS ou XCCDF STIG via LLM+RAG), `plugin fetch`
  (STIGs públicos, catálogo de 44 serviços), `plugin manual` (ingere manual do
  serviço na base RAG).
- `build_azure` — extração + **mapeamento de vocabulário** (§3.4).
- `curated_build` — build determinístico para rulesets curados.

### 2.4 Operação e ciclo de vida
- `watch` (auditoria contínua), `history`, `trend` (drift do score no tempo).
- `fix` (remediação assistida), `promote` (candidata→regra; `--stats` mede o
  ciclo de aprendizagem), `suppress` (aceitar risco).
- `explain` (origem de uma regra), `diff` (delta entre scans), `doctor`
  (integridade da DB).

### 2.5 Saída e integração
- Terminal, HTML, dashboard, JSON, **SARIF** (GitHub Code Scanning / PRs).
- Gates de CI: `--threshold`, `--exit-code`; `report --merge`, `badge`.

---

## 3. Arquitectura e implementação (como foi feito)

### 3.1 Dimensão (verificado)
~22.100 linhas de Python · **623 testes** · 6 parsers genéricos · 11 targets.

### 3.2 O contrato `Target` (extensibilidade)
O núcleo (`config_assessment/core/`) é agnóstico ao serviço. Adicionar um alvo =
criar um plugin que implementa 4 métodos (`detect`, `parse_config`,
`get_profile`, `metadata`) — **zero alterações ao core**. Foi assim que os 11
alvos (incl. os 4 de IaC/OS) foram adicionados.

### 3.3 As três proveniências de conhecimento
Todas alimentam o MESMO scoring determinístico:
1. **LLM-extraída** — apache, nginx, ssh, mysql, docker, azure-iac.
2. **Curada** — kubernetes, dockerfile, ubuntu (métricas revistas à mão,
   `build/curated_build.py`, sem LLM).
3. **Promovida** — ciclo `promote` (candidata da L3 → regra permanente).

### 3.4 Contribuição técnica: mapeamento de vocabulário (Azure IaC)
O CIS Azure fala língua de *portal* ("Ensure 'Secure transfer required' is
Enabled"); os ficheiros IaC falam atributos (`https_traffic_only_enabled` em
Terraform, `supportsHttpsTrafficOnly` em Bicep/ARM). O `build_azure.py`
acrescenta um estágio em que o LLM (ancorado via RAG) mapeia cada controlo para
o atributo exacto em **ambos** os vocabulários → 1 controlo = 2 regras, 1 build
serve `.tf`/`.bicep`/`.json`. Validações aprendidas em runs reais: rejeição de
caminhos com pontos, `bad_value` inválido (JSON/prosa/None), impacto nulo;
canonicalização de sinónimos booleanos (`off`/`Disabled`→`false`).

### 3.5 Fronteira de escopo: config vs estado do sistema
O CASPAR avalia **ficheiros de configuração**. Ferramentas como o OpenSCAP
avaliam o **estado do sistema vivo** (permissões, módulos de kernel, serviços).
O target `ubuntu` cobre o **subconjunto config-based** do CIS Ubuntu (sysctl,
login.defs) — o terreno sobreponível, onde a comparação é justa. Esta distinção
é, ela própria, um resultado da tese.

### 3.6 Manifesto de reprodutibilidade
Cada `ScanResult` grava versão do CASPAR + **SHA-256 da base de conhecimento** +
nº de regras (rodapé do scan, campo `manifest` no JSON). *Mesmo manifesto +
mesmo input ⇒ mesmos scores*, verificável por terceiros. É a forma auditável da
afirmação de determinismo.

### 3.7 Attack chains e a amplificação (heurística proposta)
Uma *attack chain* dispara quando (a) todas as suas directivas estão presentes e
(b) pelo menos uma é uma misconfiguration confirmada. O score amplificado é:

> `amplified = max(temporal_score dos constituintes) × factor`, capado a 10.0.

**Justificação do factor (×1.2–1.8) — a apresentar como contribuição, não como
valor derivado do NISTIR:**
- *Princípio:* o risco de uma combinação **excede** o do pior componente isolado
  — duas misconfigs podem abrir um caminho de ataque que nenhuma permite sozinha
  (ex.: `privileged + hostNetwork` no K8s → *node takeover*: escape do container
  E alcance dos serviços do nó). É o princípio de **attack graphs/trees**
  (Sheyner, Schneier) e do encadeamento reconhecido no CVSS/MITRE ATT&CK.
- *Porquê multiplicador (não soma):* somar seria arbitrário e sairia da escala;
  multiplicar o pior constituinte, com **cap em 10.0**, mantém a escala CCSS e
  reflecte que a chain *agrava* o pior problema, não que inventa um score novo.
- *A gama:* ×1.2 = agravamento marginal; ×1.8 = a combinação abre um caminho
  qualitativamente novo. O factor é **por-chain, declarado no `chains.json` com
  justificação textual** — cada chain diz *porquê* aquele valor.
- *Honestidade (para a defesa):* é uma **heurística de calibração qualitativa,
  curada por perito**; a validação empírica da gama fica como **trabalho futuro**.

### 3.8 Base de conhecimento RAG e o manual do serviço
Para a avaliação de directivas desconhecidas (Camada 3, opt-in), o LLM é ancorado
por RAG numa base de conhecimento por-target: o benchmark, o **manual do serviço**,
e a referência partilhada NISTIR 7502. Modelo: **ingerir uma vez (build-time),
consultar sempre (runtime)** — o documento é copiado para a pasta do plugin
(`manual_*`), *chunked* e indexado por TF-IDF; `_find_knowledge_docs` descobre-o
do disco em cada scan **sem flag**. Três caminhos de ingestão:
`plugin add --manual <path|url>` (na instalação), `plugin fetch --then-install
--manual` (via fetch), e `plugin manual <target> <path|url>` (retroativo). Aceita
ficheiro local ou URL. **Nunca toca no scoring determinístico** — só a Camada 3.

---

## 4. VALIDAÇÃO (resultados finais — Ubuntu 22.04 real, 2026-07-09)

Reproduzível com `python -m scripts.evaluate` e
`python -m scripts.baseline_compare --oscap`.

### 4.1 Base de conhecimento
**11 targets · 488 regras · 27 attack chains.**

### 4.2 Correção do motor CCSS — replicação NISTIR 7502 (18/18)
O motor de scoring foi validado contra os **18 exemplos resolvidos do próprio
NISTIR 7502 §4** (vetores da calculadora NVD): **18/18 exatos**
(`tests/test_nistir7502_examples.py`, 2026-07-14). O desvio conservador do
modelo temporal simplificado está documentado em VALIDACAO.md §1.0 e §7. É a
evidência de que a *aritmética* está certa, independente do LLM.

### 4.3 Correção das classificações — MAE vs ground truth CCE (Apache)
Scores do CASPAR vs faixas de severidade DISA do dataset **CCE oficial**:

| Métrica | Valor |
|---|---|
| Controlos CCE pontuados | 20 |
| **Matched (na faixa DISA)** | **20** |
| **Mismatched** | **0** |
| **Taxa de mismatch** | **0.0%** |
| Gate (≤20%) | **PASS** |

→ **Concordância total com o ground truth**. É a evidência quantitativa central.

### 4.4 Deteção — recall nas fixtures vulneráveis
| Fixture | Target | Recall | Score |
|---|---|---|---|
| nginx.conf | nginx | 100% | 7.5–8.9 |
| azure_storage_vulnerable.tf | azure-iac | 100% | 8.5 |
| pod_vulnerable.yaml | kubernetes | 100% | 10.0 |
| Dockerfile.vulnerable | dockerfile | 100% | 9.0 |
| **Total** | | **100% (14/14)** | |

### 4.5 Comparação com baselines

**Trivy (IaC / containers)** — mesmo ficheiro de input:
| Ficheiro | CASPAR | Trivy |
|---|---|---|
| azure_storage_vulnerable.tf | 9 findings · 8.5/10 CCSS | 13 findings · labels (2C/3H/7M/1L) |
| Dockerfile.vulnerable | 4 findings · 9.0/10 CCSS | 5 findings · labels (2H/2M/1L) |

*Achado:* o Trivy detectou `https_traffic_only_enabled` que o build LLM tinha
mapeado como sinónimo `secure_transfer_required` — ferramentas têm blind spots
distintos.

**OpenSCAP (Ubuntu OS hardening)** — subconjunto config-based sobreponível,
avaliado no sistema vivo (CIS L1 Server, `ssg-ubuntu2204-ds.xml`):
| Métrica | OpenSCAP | CASPAR |
|---|---|---|
| Controlos sobreponíveis | 38 | 18 regras (sysctl + login.defs) |
| **Veredicto** | **24 fail · 1 pass** (binário) | score CCSS 0–10 + narrativa |
| Avalia | estado do sistema vivo | ficheiro de configuração |
| Reprodutível | depende do estado da máquina | sim (manifesto) |

→ Ambos cobrem os mesmos controlos; o **diferencial do CASPAR** é o score
reproduzível + narrativa, contra o pass/fail binário do OpenSCAP.

### 4.6 Reprodutibilidade (runtime)
O manifesto (§3.6) garante que dois scans do mesmo input com a mesma base de
conhecimento produzem scores idênticos — verificado nos smoke tests
(`determinism` check: dois scans idênticos) e pelo `kb sha256` no rodapé.

### 4.7 Estabilidade da extração LLM (build-time) — experiência de determinismo
Resposta directa à objeção central dos revisores do INForum ("o LLM produz
classificações distintas se o build correr várias vezes?"). Experiência
(2026-07-18): **30 entradas do Apache × 5 execuções = 150 chamadas** com a
configuração de produção (qwen2.5:14b, temperatura 0.1, RAG determinístico).
Script: `scripts/determinism_experiment.py` (modos `run`/`analyze`); dados
brutos: `reports/determinism_runs.jsonl`.

| Métrica | Resultado |
|---|---|
| Entradas com vetor CCSS unânime (5/5) | **29/30 (96,7%)** |
| Concordância AC, C, I, A (métricas base) e GRL | **100%** |
| Concordância GEL | 98,7% (1 entrada: M↔H) |
| Amplitude base score e temporal score | **0,0 nas 30 entradas** |
| Banda DISA CAT estável | **30/30** |
| Fallbacks conservadores acionados | **0/150** |

A única divergência (GEL de `SSLProtocol +SSLv3`, 3×M/2×H) não alterou nenhum
score. **Porquê tão estável:** temperatura 0.1 ≈ decoding quase greedy; saída
categórica minúscula (6 métricas, 3–5 valores legais); prompt byte-idêntico
(RAG TF-IDF determinístico); few-shot que ancora arquétipos (os 30 vetores
colapsam em ~7 padrões). A divergência ocorreu na única métrica que depende de
conhecimento do mundo (GEL), não do texto do benchmark.

**Caveat a declarar (Threats to Validity):** 6 das 30 entradas aparecem
literalmente nos exemplos few-shot do prompt com a resposta incluída
(`ServerTokens=Full`, `User=root`, `AllowOverride=All`, `Options=FollowSymLinks`,
`LimitRequestLine=0`, `TraceEnable=On`). Excluindo-as: **23/24 unânimes
(95,8%)** — o resultado mantém-se; a tese deve reportar ambos os números.
Estabilidade ≠ correção: este resultado complementa (não substitui) o MAE §4.3
e o NISTIR §4.2.

### 4.8 Limitações (declaradas)
- **IaC/OS sem ground truth CCE:** azure-iac, kubernetes, dockerfile e ubuntu
  não têm dataset CCE oficial — validam-se por recall nas fixtures + baselines,
  não por MAE. O Apache é o caso quantitativo (CCE).
- **Escopo config-based:** o CASPAR não avalia estado de sistema (permissões,
  módulos), que é o domínio do OpenSCAP — por design.
- **Qualidade da extração LLM:** depende do modelo; o `--dry-run` + validações
  mitigam, e a L3/`promote` recuperam a cauda.
- **Estabilidade medida num único modelo:** a experiência §4.7 usou
  qwen2.5:14b a temperatura 0.1 (a configuração de produção); generalizar a
  outros modelos/temperaturas fica como trabalho futuro. Inclui o caveat da
  contaminação few-shot (6/30 entradas; ver §4.7).

---

## 5. Como reproduzir (para a defesa / anexos)

```bash
# setup (Ubuntu 22.04): ver GUIA_TESTE_MAQUINA.md e AVALIACAO_FUNCIONAL.md
python -m pytest tests/ -q                    # 623 passed (inclui NISTIR 18/18)
python -m scripts.functional_check            # 13/13 checks end-to-end
python -m scripts.evaluate                    # KB · MAE 0% · recall 100%
python -m scripts.baseline_compare --oscap    # Trivy + OpenSCAP (pass/fail reais)
python scripts/determinism_experiment.py analyze   # §4.7 (re-correr: run --runs 5, ~2h com Ollama)
```

## 6. Feedback dos revisores (INForum 2026) — obrigações de escrita

Artigo "Configuration Vulnerability Meter" (submissão 58): 2× weak accept,
1× weak reject. A tese DEVE cobrir estes pontos (quem escrever capítulos deve
tratá-los como checklist):

1. **Detalhe do processo LLM** (os 3 revisores): declarar modelo
   (qwen2.5:14b, Ollama local), temperatura (0.1), prompts em apêndice
   (system prompt + few-shot em
   `config_assessment/plugins/apache_httpd/llm_pipeline.py`), regras de
   validação de valores legais, retries (3×) e fallback conservador.
   → Respondido também com a experiência §4.7.
2. **Comparação experimental com alternativas** (R2: OpenSCAP, CIS-CAT, Trivy,
   LLMSecConfig): já feita para Trivy + OpenSCAP (§4.5). Justificar exclusão do
   CIS-CAT (licenciamento) e tratar LLMSecConfig qualitativamente (objetivo
   diferente: reparação, não medição).
3. **Mecânica de runtime pouco clara** (R1, R3): descrever inputs concretos e
   um exemplo fim-a-fim (ex.: check `PermitRootLogin` do SSH — geração no
   build → armazenamento no plugin → execução no scan). Corrigir a leitura
   errada do R1 de que os plugins só existem em build-time.
4. **Feeds de CTI** (R1): responder com o enriquecimento NVD + CISA KEV já
   existente (§2.1) e enquadrar EPSS/CTI mais amplo como trabalho futuro.
5. **Secção Threats to Validity / Limitations obrigatória** (R2): base = §4.8
   + caveat few-shot §4.7.
6. **Apresentação:** parágrafos curtos; afirmações da introdução com
   referências; a introdução deve antecipar como a metodologia será avaliada;
   evitar figura e tabela redundantes com a mesma informação.

## 7. Documentos relacionados
- [README.md](README.md) — vitrine + comandos
- [GUIA_CASPAR.md](GUIA_CASPAR.md) — guia de utilizador/demo
- [GUIA_TECNICO.md](GUIA_TECNICO.md) — arquitectura interna
- [GUIA_TESTE_MAQUINA.md](GUIA_TESTE_MAQUINA.md) — setup + build Docker
- [AVALIACAO_FUNCIONAL.md](AVALIACAO_FUNCIONAL.md) — roteiro de avaliação
- [HANDOFF.md](HANDOFF.md) — briefing técnico completo
