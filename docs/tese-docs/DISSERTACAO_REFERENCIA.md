# AEGIS — Referência para a Dissertação

> **Propósito:** documento único e verificado com tudo o que a dissertação
> precisa — funcionalidades, arquitectura/implementação, e validação com
> resultados finais (verificados num Ubuntu 22.04 real). A tese escreve-se em
> **inglês**; este documento é o material-fonte em Português Europeu.
>
> **Nomenclatura (actualizada 2026-08-02):** **AEGIS** é o nome único, usado
> tanto para a metodologia (a contribuição científica: a separação
> build-time/runtime que torna o CCSS aplicável automaticamente sem perder
> reprodutibilidade) como para a sua própria implementação de referência
> (prova de conceito, CLI `sca`). Já não existe um segundo nome — "AMiSA"
> (metodologia) e "CASPAR" (ferramenta) foram unificados sob AEGIS; ver
> primeira menção por capítulo em `tese/` para o enquadramento
> framework-vs-PoC. Zero ocorrências de AMiSA/CASPAR restam em `tese/*.tex`.
> **Estado:** parte prática FECHADA e validada (2026-07-09). Adenda pós-fecho:
> replicação NISTIR 7502 18/18 (2026-07-14), experiência de determinismo da
> extração LLM (2026-07-18), motivadas pelo feedback dos revisores do INForum
> (§6), e três gaps fechados na simulação de defesa de 2026-08-02 — IC de
> Wilson 95% nas proporções-chave, admissão explícita de falta de análise de
> sensibilidade, e nomeação do conflito CIS/STIG como assunção não testada
> (ver §4.8 e §4.9).

---

## 1. A contribuição (o argumento científico)

**Problema.** Os benchmarks de segurança (CIS, DISA STIG) descrevem
recomendações em prosa; as ferramentas existentes dão veredictos binários
(pass/fail) sem uma medida de risco reproduzível e explicável.

**Contribuição (AEGIS).** Uma metodologia para transformar benchmarks em
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
~22.100 linhas de Python · **647 testes** · 6 parsers genéricos · 11 targets.

### 3.2 O contrato `Target` (extensibilidade)
O núcleo (`config_assessment/core/`) é agnóstico ao serviço. Adicionar um alvo =
criar um plugin que implementa 4 métodos (`detect`, `parse_config`,
`get_profile`, `metadata`) — **zero alterações ao core**. Foi assim que os 11
alvos (incl. os 4 de IaC/OS) foram adicionados.

### 3.3 As três proveniências de conhecimento
Todas alimentam o MESMO scoring determinístico:
1. **LLM-extraída** — apache, nginx, ssh, mysql, redis, tomcat, docker, azure-iac.
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
modelo temporal simplificado está documentado em 06_VALIDACAO.md §1.0 e §7. É a
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

### 4.4 Deteção — recall, precisão e F1 (10 dos 11 alvos)
Suite alargada de 4 para 10 alvos (todos exceto `docker`, cujas regras são
maioritariamente estado do host/CLI, não chaves de `daemon.json` — fora de
âmbito para uma fixture de configuração, declarado explicitamente em vez de
omitido). Para cada alvo existe uma fixture **vulnerável** (recall — deteta
o que devia detetar) e uma fixture **hardened** (precisão/F1 — qualquer
finding é falso positivo, incluindo diretivas só avaliadas por *absence
rule*, que têm de estar presentes com valor aceitável, não apenas omitidas):

| Alvo | Fixture vulnerável | Recall | TP | FP | Precisão | F1 |
|---|---|---|---|---|---|---|
| nginx | nginx.conf | 100% | 2 | 0 | 100% | 100% |
| azure-iac | azure_storage_vulnerable.tf | 100% | 5 | 0 | 100% | 100% |
| kubernetes | pod_vulnerable.yaml | 100% | 4 | 0 | 100% | 100% |
| dockerfile | Dockerfile.vulnerable | 100% | 3 | 0 | 100% | 100% |
| apache-httpd | httpd.conf | 100% | 21 | 0 | 100% | 100% |
| ubuntu | ubuntu_demo/sysctl.conf | 100% | 9 | 0 | 100% | 100% |
| ssh | ssh_demo/sshd_config | 100% | 13 | 0 | 100% | 100% |
| mysql | mysql_demo/my.cnf | 100% | 16 | 0 | 100% | 100% |
| redis | redis_demo/redis.conf | 100% | 11 | 0 | 100% | 100% |
| tomcat | tomcat_demo/tomcat.conf | 100% | 12 | 0 | 100% | 100% |
| **Total** | | **100% (96/96)** | **96** | **0** | **100%** | **100%** |

Reproduzível com `python -m scripts.evaluate` (secções "Detection" e
"Precision & F1"). Nota de honestidade: o corpus é sintético e
deliberadamente worst-case/best-case; não substitui um corpus de
configurações reais recolhidas "em estado selvagem" — ver §4.8.

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

#### 4.7.1 Comparação com LLMSecConfig — duas estratégias para o mesmo problema
O LLMSecConfig (Cong et al.) enfrenta a mesma questão de fundo — *como confiar
num output de um LLM não-determinístico?* — mas resolve-a com uma arquitectura
diferente da do CASPAR, o que é instrutivo para a discussão de Related Work:

| | LLMSecConfig | CASPAR |
|---|---|---|
| **Tarefa do LLM** | reparar código (gerar YAML corrigido) | classificar severidade (atribuir AC/C/I/A/GEL/GRL) |
| **Oráculo de validação** | **Checkov (SAT) — determinístico e externo:** aceita/rejeita o output objectivamente (sem a vulnerabilidade → aceite) | **não existe oráculo automático de "severidade correcta"** — não há uma ferramenta que confirme que um AC=M está certo |
| **Loop de retry** | *externo*: gera → valida com Checkov → se falhar, tenta de novo (mede-se quantas tentativas: APS) | *interno* (`_call_llm`, `max_retries=3`): gera → `validate_metrics` (sintaxe/domínio dos valores) → se inválido, tenta de novo; sem retry após sucesso sintático — **não há segunda validação semântica** |
| **O que acontece ao esgotar tentativas** | falha reportada (a reparação não converge) | **fallback conservador** determinístico por secção CIS (`_conservative_fallback`), com `confidence=0.0` marcado — o pipeline nunca aborta |
| **Métrica de agregação** | PSR (parse success), PR (pass rate), APS (average pass steps), AUC | percentagem de vetores unânimes, concordância por métrica, amplitude de score, banda CAT estável, taxa de fallback (0/150) — ver tabela §4.7 |
| **Porque a diferença** | a tarefa deles é **verificável automaticamente** (o Checkov decide se a vulnerabilidade desapareceu) | a nossa tarefa é uma **atribuição de severidade**, sem verificador automático — daí precisarmos de medir *estabilidade* (repetir o build e comparar) como proxy da confiança, em vez de *correcção* directa |

**Resposta à pergunta "as métricas deles dão para medir o nosso determinismo?"**
Sim, em espírito — o princípio de "medir o comportamento agregado ao longo de
várias tentativas, porque uma tentativa isolada pode ser não-representativa" é
exactamente o mesmo motivador da nossa experiência §4.7. Concretamente:
- A **taxa de fallback** (0/150) é o nosso equivalente ao inverso da PSR/PR: mede
  quantas vezes o pipeline teve de recorrer ao valor conservador por não
  conseguir uma resposta válida do LLM em `max_retries` tentativas.
- Poderíamos reportar um **"Average Retry Steps"** análogo ao APS — quantas das
  3 tentativas internas (`_call_llm`) foram normalmente necessárias antes de um
  JSON válido — mas isto **não foi instrumentado no build actual** (o loop só
  regista sucesso/falha final, não o nº de iterações internas); fica identificado
  como extensão futura ao `scripts/determinism_experiment.py` (logging já expõe
  `attempt` em `_call_llm`, seria uma alteração pequena).
- A diferença estrutural que não se resolve por métrica: o LLMSecConfig tem um
  **validador externo determinístico** (Checkov) que valida o *conteúdo* da
  resposta contra a realidade (a vulnerabilidade desapareceu ou não); o CASPAR só
  tem validação de **forma** (`validate_metrics` — a resposta é um JSON com
  valores no domínio legal), não de **correcção semântica** da classificação
  CCSS. É por isso que a nossa mitigação de não-determinismo tem de ser, em
  última instância, *empírica* (repetir o build e medir estabilidade, §4.7) e
  não *estrutural* (um validador que rejeita respostas "erradas" antes delas
  saírem do pipeline). Vale a pena discutir isto explicitamente na secção de
  Threats to Validity/Limitations como uma limitação de desenho partilhada por
  qualquer classificação de severidade não binária (ao contrário de "há ou não
  há vulnerabilidade", que o Checkov consegue arbitrar).

#### 4.7.2 Como o CASPAR lida com o não-determinismo do LLM — síntese das cinco camadas
Resumo, para citação directa na tese, dos mecanismos que o CASPAR combina para
conter (não eliminar) o não-determinismo do LLM no build-time. Nenhum destes
é hipotético — todos estão implementados e são verificáveis no código citado.

1. **Temperatura baixa na fonte.** `temperature=0.1` (quase *greedy decoding*)
   no `qwen2.5:14b` via Ollama — estreita a distribuição de outputs antes de
   qualquer validação a jusante.
2. **RAG como redutor de variabilidade contextual — mas só parcialmente
   aplicado.** O `BenchmarkIndex` (`config_assessment/build/rag.py`,
   TF-IDF) ancora o prompt na secção exacta do CIS Benchmark
   (`llm_pipeline.py:392-455`), o mesmo princípio do LLMSecConfig (contexto
   técnico estruturado reduz o espaço de "improviso" do modelo — PR 90.3%
   com source code vs. 65.2% com documentação solta). **Limitação a
   declarar:** este RAG só indexa o benchmark CIS. As definições de CCSS
   (rubricas AC/C/I/A/GEL/GRL, tabela de calibração DISA CAT) **não são
   recuperadas via RAG** — estão hardcoded como texto fixo no
   `_SYSTEM_PROMPT` e nos 6 exemplos de `_FEW_SHOT`
   (`llm_pipeline.py:65-223`). O `nistir7502.pdf` **é** indexado via RAG,
   mas apenas no pipeline separado do Layer‑3 (`cli/_knowledge.py:78-135`,
   usado por `caspar promote`/`--assess-unknown`), não no build principal do
   Apache. Ou seja: há uma assimetria de desenho — o pipeline principal
   ancora no benchmark mas não na norma que define a própria classificação
   que está a produzir. **Porque isto é uma limitação real, não uma escolha
   deliberada:** o prompt estático (few-shot) funciona como substituto
   informal do que o RAG faria (dar à LLM o texto normativo relevante), mas
   é menos flexível — não se adapta a variações de fraseio do benchmark
   como o RAG faz para as secções CIS. Unificar os dois (indexar também o
   NISTIR no pipeline principal) é trabalho futuro natural, já com o
   precedente do Layer-3 a mostrar que é tecnicamente trivial (mesma classe
   `BenchmarkIndex`).
3. **Retry interno com validação de forma.** `_call_llm()` tenta até
   `max_retries=3`; cada tentativa passa por `_extract_json()` (JSON
   parsável) e `validate_metrics()` (valores no domínio legal). Validação
   **sintáctica**, não semântica — confirma "resposta bem formada", não
   "classificação correcta" (ver §4.7.1 para a distinção face ao Checkov).
4. **Fallback conservador determinístico.** Esgotadas as 3 tentativas,
   `_conservative_fallback()` devolve valores fixos por secção CIS com
   `confidence=0.0` explícito — o pipeline nunca propaga um erro de parsing
   para o score final, e o valor "não vem do LLM" fica marcado e
   auditável (0/150 acionados na experiência §4.7).
5. **Separação build-time/runtime como contenção estrutural (a camada mais
   importante).** Em vez de perseguir um oráculo externo tipo Checkov para
   tornar o LLM determinístico por validação de conteúdo, o CASPAR **isola**
   o não-determinismo na fase de build (corre uma vez, produz uma base de
   conhecimento estática) e garante, por construção, que o runtime — o que
   corre em cada scan — é 100% determinístico (parse → lookup exacto →
   aritmética CCSS, sem LLM). O manifesto de reprodutibilidade (§3.6, hash
   SHA-256 da base + versão) torna isto auditável: mesmo manifesto ⇒ mesmo
   resultado, sempre.

**Contraponto necessário a 5 — fiabilidade da própria base de conhecimento.**
A separação build/runtime resolve o não-determinismo *da execução*, mas não
resolve a questão de fundo: **e se a base de conhecimento gerada no build
estiver mal construída?** Um runtime perfeitamente determinístico só garante
scores *reprodutíveis*, não *correctos* — se o LLM classificar mal uma
directiva de forma consistente, o scan vai reproduzir esse erro de forma
igualmente consistente, 100% das vezes. Determinismo ≠ correcção (o mesmo
aviso já feito em §4.7 a propósito do MAE). O que o CASPAR tem hoje para
mitigar isto, verificado no código:
- **Validação de forma, não de conteúdo, na extração** (ponto 3 acima) —
  garante que a resposta é bem formada, não que está certa.
- **MAE contra ground truth externo** (§4.3): as classificações do Apache
  são comparadas contra o dataset CCE oficial
  (`cce-apache-httpd2.2-5.20130214.xlsx`, via `scripts/evaluate.py`) — a
  única verificação de *correcção* (não apenas de estabilidade) que existe
  hoje, e só cobre o Apache (o único plugin com CCE oficial disponível;
  ver §4.8).
- **Proveniência é documentação, não um campo de schema.** As "três
  proveniências" (LLM-extracted, curated, promoted) descritas em §3.3
  **não são impostas pela base de dados** — `scripts/evaluate.py` mapeia
  proveniência por um dicionário Python hardcoded, com o comentário
  explícito de que "provenance is documentation, not stored." Isto
  significa que, tecnicamente, uma regra `curated` mal escrita à mão entra
  na base sem qualquer verificação automática adicional — a única barreira
  é o cuidado humano de quem a escreveu.
- **`promote` exige confirmação humana, não é um gate automático.** O
  comando `caspar promote` (`cli/commands/manage_cmds.py`) corre a LLM sobre
  directivas desconhecidas mas **pede confirmação interativa** antes de
  escrever na base (`click.confirm`, salvo `--yes`), e avisa explicitamente
  o utilizador para rever `good_value` manualmente depois. É um travão
  humano, não uma validação automática de correcção.
- **O que ainda falta, honestamente:** não há um "Checkov da CCSS" — nenhuma
  ferramenta determinística que confirme que um `AC=M` atribuído está
  semanticamente certo (ao contrário de "esta YAML tem ou não uma
  vulnerabilidade", que é binário e verificável). Isto é uma limitação de
  desenho estrutural, não um detalhe de implementação: classificar
  *severidade* é uma tarefa sem oráculo automático na literatura geral, não
  só no CASPAR. Não existindo esse oráculo, a mitigação implementada (§4.7.3)
  ataca a pergunta adjacente e verificável — *quão bem o LLM concorda consigo
  mesmo* — como proxy parcial de confiança, combinada com (a) validação
  externa via MAE onde há CCE disponível e (b) revisão humana no `promote`.
  Concordância entre amostras não é o mesmo que correcção (uma LLM pode
  convergir de forma unânime e consistente para uma classificação errada) —
  distinção que se mantém, e que a tese deve defender de forma honesta.

#### 4.7.3 Self-consistency: votação de maioria de k amostras (implementado)
Resposta directa à pergunta "como resolver as limitações encontradas" —
em vez de aceitar cegamente a primeira resposta sintacticamente válida do
LLM (o comportamento até aqui descrito em §4.7.2, ponto 3), o pipeline de
build passou a suportar amostragem k-vezes independente com agregação por
votação de maioria **por métrica** (`ac`, `c`, `i`, `a`, `gel`, `grl`),
técnica conhecida na literatura de LLMs como *self-consistency*
(Wang et al., 2022) — a mesma ideia de fundo já usada, em modo de
*medição* post-hoc, pelo `scripts/determinism_experiment.py` (5 execuções
× 30 entradas), agora promovida a **mecanismo de build**, não apenas de
avaliação.

**Desenho** (`config_assessment/plugins/apache_httpd/llm_pipeline.py`):
- `LLMBuildPipeline.__init__` ganha um parâmetro `consensus_samples: int = 1`
  (default preserva o comportamento anterior: uma única chamada, sem overhead
  de votação — confirmado pela suite de testes, 633/633 sem regressões).
- `_call_llm_once()` é o antigo `_call_llm()`, isolado como a unidade de uma
  única tentativa (com o seu próprio retry sintáctico interno, ponto 3 de
  §4.7.2), devolvendo `None` em vez de calcular o fallback directamente.
- `_call_llm()` (novo, orquestrador): se `consensus_samples == 1`, chama
  `_call_llm_once` uma vez, como antes. Se `> 1`, dispara k chamadas
  independentes, filtra as que falharam, e agrega as restantes via `_vote()`.
  Se todas falharem, cai no mesmo fallback conservador de sempre
  (`confidence=0.0`).
- `_vote(samples)` (novo, `@staticmethod`): para cada uma das 6 métricas,
  conta os votos e escolhe o valor maioritário; a `confidence` final do
  vector agregado é a **taxa de concordância da métrica menos consensual**
  (o mínimo, não a média — um vector com 5 métricas unânimes e uma a 2/3 vale
  2/3, não a média das seis, porque o vector *completo* só é tão fiável
  quanto o seu elo mais fraco). Campos de texto livre (`justification`,
  `recommendation`, `cve_ids`) são copiados da amostra que mais concorda com
  o vector vencedor, nunca concatenados ou escolhidos arbitrariamente.
- **Desempate resolvido pela matemática CCSS real, não por uma tabela de
  severidade inventada.** A primeira versão deste código assumia que as
  legendas (`"H"`, `"M"`, etc.) formam uma escala de severidade previsível —
  suposição errada: em `core/ccss.py`, `GEL["M"] == GEL["H"] == 1.000`
  (empatados, não estritamente ordenados) e `GRL["H"] = 1.000` é o
  coeficiente *máximo* (pior caso), apesar de "H" em GRL ler-se
  intuitivamente como "existe correcção oficial documentada" (bom, não mau).
  Por isto, o desempate em `_vote()` não usa uma tabela hardcoded: para um
  empate numa métrica, calcula `temporal_score()` (importado directamente de
  `core/ccss.py`) para cada candidato empatado e escolhe o que produz o score
  mais alto — resultado sempre consistente com o motor de scoring oficial,
  nunca uma segunda fonte de verdade sobre severidade que possa divergir dele.
- **Persistência do `confidence`** (bug corrigido nesta mesma alteração): o
  campo já existia em `LLMMetrics` mas era descartado antes de chegar à base
  de dados — `Misconfiguration` não tinha o campo e `process_entry` nunca o
  propagava. Corrigido de ponta a ponta: novo campo
  `Misconfiguration.confidence: float = 1.0`, nova coluna
  `confidence REAL NOT NULL DEFAULT 1.0` no schema, migração idempotente em
  `database.py::_migrate` (`ALTER TABLE` + a migração de recriação de tabela
  para bases de dados antigas), leitura defensiva em `_row_to_misconfiguration`
  (compatível com bases sem a coluna). Verificado com 10 testes novos em
  `tests/test_llm_pipeline.py` (`TestConsensusVoting`,
  `TestConsensusPipelineIntegration`): unanimidade ⇒ confidence 1.0; maioria
  clara ⇒ fracção correcta; empate ⇒ vencedor confirmado contra
  `temporal_score()` real; campos de texto vêm da amostra vencedora; e
  round-trip completo através da base de dados.
- **O que isto é e o que não é.** `confidence` mede *concordância entre
  amostras independentes do mesmo modelo*, não *correcção face à realidade*
  — a mesma distinção honesta já feita acima. Um LLM sistematicamente
  enviesado pode votar unanimemente numa classificação errada (`confidence`
  1.0, MAE > 0). Por isso este mecanismo não substitui a validação MAE
  (§4.3) nem a revisão humana no `promote` — soma-se a elas como uma terceira
  camada, e é a única das três que corre automaticamente em **todas** as
  directivas extraídas por LLM (não só nas que têm CCE oficial ou passam por
  `promote`).
- **Custo:** k amostras multiplicam por k o número de chamadas ao LLM no
  build (não no scan — o runtime continua imutável e 100% determinístico,
  ponto 5 de §4.7.2). Este é um custo aceite conscientemente: o utilizador
  pediu para não condicionar esta escolha ao tempo até à defesa, priorizando
  rigor sobre expediência de calendário.

### 4.8 Limitações (declaradas)
- **IaC/OS sem ground truth CCE:** azure-iac, kubernetes, dockerfile e ubuntu
  não têm dataset CCE oficial — validam-se por recall nas fixtures + baselines,
  não por MAE. O Apache é o caso quantitativo (CCE).
- **Escopo config-based:** o CASPAR não avalia estado de sistema (permissões,
  módulos), que é o domínio do OpenSCAP — por design.
- **Corpus de fixtures é sintético, não "em estado selvagem":** a suite de
  recall/precisão/F1 (§4.4, 10/11 alvos, 96 findings) usa fixtures
  deliberadamente worst-case (vulnerável) e best-case (hardened) escritas
  para exercitar exatamente as regras da base de conhecimento — não uma
  amostra de configurações reais de produção. 100% de precisão/recall neste
  corpus mede correção do motor de scoring/parsing, não a taxa de falsos
  positivos/negativos que apareceria em configurações reais mais ruidosas
  (diretivas em ordens inesperadas, comentários inline, valores fora do
  domínio previsto). Validação num corpus real fica como trabalho futuro.
- **CTI para vulnerabilidades sem CVE é curado, não um feed ao vivo:** o
  `ttp_enricher.py` (§2.1, resposta ao Revisor 1 ponto 5) mapeia um conjunto
  pequeno e hand-curado de `(alvo, diretiva, valor)` → técnica MITRE
  ATT&CK — não substitui um feed de threat intelligence dinâmico
  (MISP/OTX), que introduziria uma dependência de rede inconsistente com o
  desenho offline do runtime. Cobertura hoje: 7 mapeamentos, extensível.
- **Qualidade da extração LLM:** depende do modelo; o `--dry-run` + validações
  mitigam, a L3/`promote` recuperam a cauda, e o `confidence` por
  self-consistency (§4.7.3) marca automaticamente as extracções onde as k
  amostras divergiram — mas concordância entre amostras não garante
  correcção (só o MAE, §4.3, valida contra ground truth externo).
- **Estabilidade medida num único modelo:** a experiência §4.7 usou
  qwen2.5:14b a temperatura 0.1 (a configuração de produção); generalizar a
  outros modelos/temperaturas fica como trabalho futuro. Inclui o caveat da
  contaminação few-shot (6/30 entradas; ver §4.7).
- **RAG não ancora CCSS no pipeline principal:** o `BenchmarkIndex` do build
  do Apache só indexa o benchmark CIS; as rubricas CCSS vivem hardcoded no
  prompt (few-shot), não no RAG. O NISTIR só é indexado via RAG no pipeline
  Layer-3/`promote` (ver §4.7.2). Unificar é trabalho futuro.
- **Proveniência não é imposta pela base de dados:** as três categorias
  (LLM-extracted, curated, promoted) são documentação/convenção, não um
  campo de schema validado — uma regra `curated` incorrecta entra sem
  verificação automática além da revisão humana (ver §4.7.2).
- **Conflito entre benchmarks (CIS vs STIG) não é resolvido, é evitado por
  construção:** a chave de unicidade da tabela `misconfigurations`
  (`UNIQUE (target_name, directive, bad_value, expected_value_prefix)`) não
  inclui a origem do benchmark. Nenhum plugin actual mistura duas famílias
  de benchmark para a mesma diretiva — mas isso nunca foi testado, é uma
  assunção não exercitada. O mesmo vale para versões sucessivas do mesmo
  benchmark (CIS Apache v2.1 vs v2.2): a proveniência $\pi$ por regra torna
  a discrepância rastreável a posteriori, mas nada no build a deteta.
  Nomeado explicitamente como limitação em `Chapter4_AEGIS.tex`
  §Trust and Threat Model e como trabalho futuro em
  `Chapter7_Conclusion.tex` §Future Work ("Cross-benchmark conflict
  resolution").

### 4.9 Três gaps fechados na simulação de defesa (2026-08-02)

Uma simulação de arguição (júri cético, várias personas) identificou três
lacunas genuínas — já corrigidas na tese, detalhe completo em
`caspar-defesa-simulada-qa` (memória da sessão):

1. **Intervalos de confiança de Wilson (95%)** para as três proporções-chave
   sobre universo finito: 20/20 (concordância CCE/DISA) → **[83.9%, 100%]**;
   96/96 (recall) → **[96.2%, 100%]**; 29/30 (estabilidade build-time) →
   **[83.3%, 99.4%]**. Adicionado a `Chapter6_Evaluation.tex` §Conclusion
   Validity. O intervalo largo do 20/20 é o ponto pedagógico: a amostra
   pequena não sustenta a leitura "100% populacional" que o ponto isolado
   sugere — o `06_VALIDACAO.md` já recomendava isto (linha 337-338) e agora
   está aplicado no capítulo.
2. **Análise de sensibilidade ausente + justificação de N=5**: admitido
   explicitamente como trabalho futuro em `Chapter7_Conclusion.tex`
   §Future Work — os resultados são pontuais sob os parâmetros actuais
   (thresholds, política worst-case, bandas $\phi$), não perturbados; e a
   escolha de N=5 no teste de determinismo nunca foi testada quanto a
   saturação do IC (10 ou 20 podiam apertar o intervalo).
3. **Conflito CIS/STIG e versionamento de benchmark**: ver último ponto de
   §4.8 acima.

Todas as três edições verificadas contra o código antes de escrever
(schema.sql, plugins/*/rules.py) e compilam sem referências indefinidas.

---

## 5. Como reproduzir (para a defesa / anexos)

```bash
# setup (Ubuntu 22.04): ver 03_GUIA_VM_UBUNTU22.md e 04_AVALIACAO_FUNCIONAL.md
python -m pytest tests/ -q                    # 647 passed (inclui NISTIR 18/18)
python -m scripts.functional_check            # 13/13 checks end-to-end
python -m scripts.evaluate                    # KB · MAE 0% · recall 100% · precisão/F1 100%
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
   build → armazenamento no plugin → execução no scan, incluindo agora a
   resolução worst-case de blocos `Match` em `ssh/parser.py`, §4.8/RESPOSTA_
   REVISORES.md ponto 4). Corrigir a leitura errada do R1 de que os plugins
   só existem em build-time.
4. **Feeds de CTI** (R1): resolvido — enriquecimento NVD + CISA KEV +
   Exploit-DB (F1) mais o novo `ttp_enricher.py` (mapeamento curado
   diretiva→MITRE ATT&CK como fallback para misconfigs sem CVE, §4.8);
   EPSS e feeds CTI dinâmicos (MISP/OTX) ficam como trabalho futuro,
   explicitamente fora de âmbito por introduzirem dependência de rede.
5. **Secção Threats to Validity / Limitations obrigatória** (R2): base = §4.8
   + caveat few-shot §4.7.
6. **Apresentação:** parágrafos curtos; afirmações da introdução com
   referências; a introdução deve antecipar como a metodologia será avaliada;
   evitar figura e tabela redundantes com a mesma informação.

## 7. Documentos relacionados
- [README.md](../../README.md) — vitrine + comandos (roteiro numerado 01-06)
- [02_GUIA_CASPAR.md](../02_GUIA_CASPAR.md) — guia de utilizador/demo
- [03_GUIA_VM_UBUNTU22.md](../03_GUIA_VM_UBUNTU22.md) — instalar + testar tudo + build Docker
- [04_AVALIACAO_FUNCIONAL.md](../04_AVALIACAO_FUNCIONAL.md) — roteiro de avaliação
- [05_GUIA_TECNICO.md](../05_GUIA_TECNICO.md) — arquitectura interna
- [06_VALIDACAO.md](../06_VALIDACAO.md) — plano de validação completo
- [HANDOFF.md](../HANDOFF.md) — briefing técnico completo
