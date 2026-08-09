# CASPAR

**Configuration Vulnerability Meter — framework genérico de scoring de configurações de segurança baseado em NISTIR 7502 (CCSS)**

O CASPAR é a implementação de referência de um *Configuration Vulnerability Meter* (CVM): uma
categoria de instrumento de segurança situada entre os scanners de conformidade (veredictos
binários pass/fail) e os scanners de vulnerabilidades (CVEs conhecidos), que mede quantitativamente
a vulnerabilidade introduzida pela configuração de um sistema.

> **Este documento é a vitrine e referência de comandos — é o "01" do roteiro.** A restante
> documentação vive em [docs/](docs/), numerada pela ordem de leitura recomendada; os documentos
> ligados à dissertação estão em [docs/tese-docs/](docs/tese-docs/).
>
> | # | Documento | Papel | Lê-o quando… |
> |---|---|---|---|
> | 01 | **README.md** (este) | Vitrine + referência de comandos | queres saber o que é e como usar |
> | — | [INSTALL.md](INSTALL.md) | Instalação validada: clone → instalar → semear → primeiro scan, com resultados esperados e troubleshooting | vais instalar numa máquina limpa |
> | 02 | [docs/02_GUIA_CASPAR.md](docs/02_GUIA_CASPAR.md) | Guia de utilizador + demonstração | queres perceber e demonstrar, do zero |
> | 03 | [docs/03_GUIA_VM_UBUNTU22.md](docs/03_GUIA_VM_UBUNTU22.md) | VM Ubuntu 22.04 limpa até à comparação final: instalar, inserir vulnerabilidade, scan+relatório, **todos os comandos do CLI**, Trivy/OpenSCAP | vais testar a ferramenta numa máquina — é o guia principal, ponta a ponta |
> | 04 | [docs/04_AVALIACAO_FUNCIONAL.md](docs/04_AVALIACAO_FUNCIONAL.md) | Roteiro de recolha de evidência para a tese (detect→fix→re-scan, checklist de artefactos) | já testaste (03) e vais recolher resultados para a dissertação |
> | 05 | [docs/05_GUIA_TECNICO.md](docs/05_GUIA_TECNICO.md) | Arquitectura interna | vais mexer no código |
> | 06 | [docs/06_VALIDACAO.md](docs/06_VALIDACAO.md) | Plano de validação completo (científica, funcional, fiabilidade, desempenho, tradeoffs) | queres saber como a ferramenta se valida e mede |
> | — | [DISSERTACAO_REFERENCIA.md](docs/tese-docs/DISSERTACAO_REFERENCIA.md) | Material-fonte consolidado para a tese | vais escrever a dissertação |
> | — | [HANDOFF.md](docs/HANDOFF.md) | Briefing de estado do projeto (histórico, não sequencial) | retomas o projeto noutra sessão/máquina |

---

## O que é

O CASPAR lê uma configuração de serviço (ficheiro, directório, serviço instalado, ou imagem Docker), analisa cada directiva contra o CIS Benchmark usando um LLM local, e atribui um score de segurança CCSS (0–10) a cada problema — com narrativa técnica completa, cenário de exploração, justificação de cada submétrica, recomendação de remediação, enriquecimento por CVE real (NVD + CISA KEV), e detecção de attack chains.

Não é um scanner Apache específico. É uma metodologia replicável para qualquer serviço com **CIS Benchmark (PDF)** ou **DISA STIG (XCCDF XML)** disponível — `caspar plugin add` auto-detecta o formato da fonte. O Apache HTTP Server 2.4 é o target de referência porque é o único com ground truth CCE disponível para calibração.

As fontes vivem em `sources/`: `sources/benchmarks/` (PDFs CIS) e `sources/stigs/` (XML DISA STIG). Os STIGs alargam a cobertura a 50+ produtos sem CIS Benchmark (Redis, Tomcat, MongoDB, Kubernetes, VMware, Splunk, …).

```bash
caspar plugin add --source sources/benchmarks/CIS_PostgreSQL_13.pdf       # PDF  (CIS)
caspar plugin add --source sources/stigs/U_Redis_Enterprise_6-x_STIG.xml  # XCCDF (DISA STIG)
```

Para descobrir e descarregar o benchmark automaticamente (sem procurar o ficheiro à mão), usa `caspar plugin fetch`. Descarrega o STIG do serviço a partir de fonte pública (stigviewer.com, via `/stigs/<slug>/export/json`), converte-o para XCCDF e — com `--then-install` — instala o plugin de imediato. `caspar plugin fetch --list` mostra os serviços catalogados (`config_assessment/fetch/catalog.json`).

```bash
caspar plugin fetch --list                     # serviços disponíveis
caspar plugin fetch nginx --then-install       # descarrega + instala
caspar plugin fetch mysql -o .                 # só descarrega (para o dir atual)
```

#### Base de conhecimento do serviço (RAG build-time)

Além do benchmark, cada alvo pode ter uma **base de conhecimento** própria — o manual do serviço, um STIG extra, o NISTIR 7502 (CCSS) — usada pela avaliação por LLM de directivas desconhecidas (Camada 3, `scan --assess-unknown`). Esse conhecimento é **ingerido uma vez, no build-time, e recuperado do disco em cada scan** — nunca se passa um documento por scan. Adiciona um manual (ficheiro local **ou** URL) com `--manual`, em qualquer dos caminhos de instalação:

```bash
caspar plugin add -s CIS_Apache.pdf --manual manual_apache.pdf
caspar plugin add -s CIS_Apache.pdf --manual https://archive.apache.org/dist/httpd/docs/manual.pdf
caspar plugin fetch nginx --then-install --manual https://.../nginx-docs.pdf
```

O manual é copiado para a pasta do plugin (no volume persistente, em Docker), *chunked* por estrutura e indexado por TF-IDF. Em cada scan, `_find_knowledge_docs` descobre-o do disco — sem flag de runtime. O RAG vive **apenas** no build-time e na Camada 3 (opt-in); **nunca** toca no scoring CCSS determinístico.

A referência partilhada **NISTIR 7502 (a especificação CCSS, ~285KB) viaja com o projeto**: está no
repo e é *baked* na imagem Docker (exceção explícita à exclusão de PDFs), por isso a Camada 3 tem o
conhecimento CCSS em qualquer máquina, offline, sem passo extra. Os benchmarks CIS grandes continuam
fora da imagem — chegam via `plugin add`/`fetch` e persistem no volume.

O catálogo cobre **43 alvos**, agrupados por categoria:

- **Web / app servers:** nginx, apache, apache-windows, tomcat, iis, iis-site, jboss
- **Bases de dados:** mysql, mariadb, postgresql, epas, oracle-db, sqlserver, db2, mongodb, redis
- **Contentores / orquestração:** kubernetes, openshift, rke2
- **Sistemas operativos:** rhel8/9, oracle-linux-8/9, ubuntu2004/2204/2404, sles12/15, solaris11, aix, macos-sonoma, windows-server-2019/2022/2025, windows-10/11
- **Equipamento de rede:** cisco-asa-ndm, cisco-asa-fw, cisco-ios, palo-alto-ndm, juniper-srx-alg, f5-bigip-ndm, arista-ndm

Alguns têm **fonte de fallback**: se a primária falhar (ex. HTTP 500), o fetcher passa automaticamente à seguinte. Adicionar um alvo é só acrescentar uma entrada `{ "slug": "..." }` ao catálogo — o slug é o segmento que aparece no URL de stigviewer.com. Corre `caspar plugin fetch --list` para a lista completa e atualizada.

> Nota: `plugin fetch --then-install` corre a extracção por LLM (Ollama), tal como `plugin add`. Na imagem Docker isto é encaminhado automaticamente para `caspar:full` (com Ollama embutido). Fetch só-download (sem `--then-install`) não precisa de LLM.

A decisão de design central é a separação entre **build time** (LLM + CVE lookup + RAG, corre uma vez) e **runtime** (determinístico, zero LLM, corre em cada scan). Scores idênticos para inputs idênticos — sempre.

---

## Estado do projecto

| Fase | Nome | Estado |
|---|---|---|
| **1** | Framework core — abstracções genéricas | ✅ Completo |
| **2** | Plugin Apache — target de referência | ✅ Completo |
| **3** | Plugins adicionais — Nginx funcional; SSH/Ubuntu/Docker a seguir | 🔄 Em curso |
| 4 | Automação (scheduler de refresh, CI/CD) | 🔜 |
| 5 | Report generator PDF | 🔜 |
| 6 | Validação científica inter-analista (MAE) | 🔜 |

**Gate Fase 2→3 passou:** 0% mismatch vs CCE XLS ground truth (limite: ≤20%).

### Dentro da Fase 2, o que está fechado

| Componente | Estado |
|---|---|
| Core genérico (parser, models, ccss.py, runtime) | ✅ |
| Plugin Apache (parser, rules, 30 misconfigurations) | ✅ |
| LLM pipeline — Stage 1 (métricas AC/C/I/A) | ✅ |
| LLM pipeline — Stage 2 (attack chains) | ✅ |
| LLM pipeline — Stage 3 (narrativas detalhadas) | ✅ |
| CVE enrichment (NVD API v2 + CISA KEV) | ✅ |
| 4 modos de scan (ficheiro, directório, live, Docker) | ✅ |
| Relatório terminal compacto | ✅ |
| Relatório HTML com narrativas completas | ✅ |
| Relatório SARIF / JSON | ✅ |
| 777 testes automatizados | ✅ |

---

## Instalação

> **O percurso completo e validado está em [INSTALL.md](INSTALL.md)** — do clone
> ao primeiro scan, com os resultados esperados transcritos de execuções reais e
> uma secção de resolução de problemas. O resumo abaixo é para quem já conhece o
> ecossistema Python.

```bash
git clone https://github.com/AFilipe-IT/CASPAR.git caspar
cd caspar

python3 -m venv .venv
source .venv/bin/activate       # Linux / macOS / WSL2
# .venv\Scripts\activate        # Windows

pip install --upgrade pip       # o pip de origem do Ubuntu 22.04 não resolve [dev]
pip install -e .

sqlite3 ccss.db < data/ccss_canonical.sql   # base de conhecimento — passo obrigatório

caspar --help
```

⚠️ Sem o passo do `sqlite3`, qualquer scan falha com `DB 'ccss.db' not found` e
sugere `caspar build`, que reconstrói a base com um LLM local e demora ~1h46min.
A base canónica já vem no repositório e aplica-se em menos de um segundo.

Requisitos: Python ≥3.10, `sqlite3`, `pdftotext` (poppler-utils) só para ler o PDF do benchmark, Docker (opcional, só para `caspar scan docker://...`).

```bash
sudo apt-get install poppler-utils   # Ubuntu / Debian / WSL2
```

### Instalação via Docker (recomendado para máquinas de teste)

Um one-liner instala as imagens e um wrapper `caspar` no PATH — sem clonar o repo, sem ambiente Python:

```bash
curl -fsSL https://raw.githubusercontent.com/AFilipe-IT/CASPAR/master/install.sh | sh
```

Existem duas imagens: **`alfilipe/caspar:latest`** (leve, para scan/runtime) e **`alfilipe/caspar:full`** (com Ollama embutido, para build-time: `plugin add` / `plugin fetch --then-install`). O wrapper escolhe a imagem certa consoante o comando.

**Persistência.** Plugins instalados via `plugin add` / `plugin fetch --then-install` e a base de dados que eles populam são gravados num volume Docker (`caspar_data`, montado em `/home/caspar/data`), pelo que **sobrevivem entre execuções** apesar do `--rm`. Na primeira utilização a DB é semeada a partir da versão canónica embutida na imagem (idempotente, nunca sobrepõe uma DB existente).

```bash
# instalar mongodb (usa o modelo por omissão, qwen2.5:14b)
caspar plugin fetch mongodb --then-install

# um container novo e separado continua a ver o plugin instalado
caspar targets            # mongodb aparece na lista
```

Para acelerar testes (à custa de qualidade de extracção), passa um modelo mais leve:

```bash
CASPAR_MODEL=qwen2.5:1.5b caspar plugin fetch mongodb --then-install
```

### Configurar a NVD API key (opcional mas recomendado)

```bash
cat > .env << 'EOF'
NVD_API_KEY=<a-tua-key>
EOF
```

Pede uma key gratuita em https://nvd.nist.gov/developers/request-an-api-key — sem ela o CVE enrichment usa 5 req/30s (lento mas funcional); com ela, 50 req/30s. O `.env` está no `.gitignore`, nunca é commitado.

---

### Primeiro passo após instalar: `caspar doctor`

Verifica a integridade da base de conhecimento antes do primeiro scan — regras órfãs, chains
a apontar para directivas inexistentes, scores fora de gama. Read-only, sai com 1 se houver erro:

```bash
caspar doctor            # verificação básica
caspar doctor --strict   # + auditoria de narrativas (afirmações de impacto sem cautela)
```

---

## Uso rápido — 4 modos de scan

### Modo 1 — ficheiro único

```bash
caspar scan /tmp/httpd.conf
```

### Modo 2 — directório completo (segue todos os Includes)

```bash
caspar scan /etc/apache2/
```

Detecta automaticamente o ponto de entrada (`apache2.conf`, `httpd.conf`) e o parser segue `Include`/`IncludeOptional` recursivamente — `conf-enabled/`, `sites-enabled/`, `mods-enabled/` são todos incluídos.

### Modo 3 — serviço instalado na máquina

```bash
caspar scan --live apache2
caspar scan --live httpd
```

Usa `apache2ctl -V` / `httpd -V` para encontrar o `ServerRoot` e o ficheiro de config real, com fallback para caminhos hard-coded por distro (Debian, RHEL, macOS Homebrew).

### Modo 4 — imagem Docker

```bash
caspar scan docker://httpd:2.4
caspar scan docker://my-custom-apache:latest
```

Faz `docker pull` se necessário, cria um container temporário (sem o correr), extrai os ficheiros de configuração via `docker cp`, e remove o container. Não precisa de Docker Desktop a correr no WSL2 só para inspeccionar — mas precisa para `docker create`/`docker cp`.

### Opções comuns a todos os modos

```bash
# Relatório HTML completo (default)
caspar scan /etc/apache2/ --report --output ./relatorios/

# Relatório JSON
caspar scan /etc/apache2/ --report --format json

# Relatório SARIF (GitHub Security tab)
caspar scan /etc/apache2/ --report --format sarif

# Gate CI/CD — exit 1 se score > 7.0
caspar scan /etc/apache2/ --threshold 7.0

# Base de dados alternativa
caspar --db outra.db scan /etc/apache2/
```

---

## IaC — Terraform / Bicep / ARM, Kubernetes e Dockerfile (shift-left)

O mesmo pipeline determinístico avalia **Infrastructure-as-Code antes do deploy**. Nenhuma flag —
o router de plugins escolhe o target sozinho:

```bash
caspar scan main.tf                # Azure/Terraform (deteta pelo provider azurerm)
caspar scan main.bicep             # Bicep (vocabulário ARM)
caspar scan azuredeploy.json       # ARM template (deteta pelo $schema)
caspar scan deployment.yaml        # K8s: privileged, hostNetwork, runAsUser 0, SYS_ADMIN, …
caspar scan Dockerfile             # USER ausente (root por omissão), :latest implícito, EXPOSE 22
caspar scan infra/ --report -f sarif  # diretório → SARIF p/ o PR (gate de CI)
```

Os findings apontam a **linha e o contexto exatos** (`main.tf:3 [azurerm_recovery_services_vault.backup]`,
`pod.yaml:13 [spec.containers[0].securityContext]`, `Dockerfile:3 [stage:build]`).

### Azure IaC: extração com mapeamento de vocabulário (build-time, LLM+RAG)

Os CIS Microsoft Azure Benchmarks falam a língua do **portal** ("Ensure that *'Secure transfer
required'* is set to *'Enabled'*"); os ficheiros IaC falam `https_traffic_only_enabled` (Terraform)
ou `supportsHttpsTrafficOnly` (Bicep/ARM). O build do target `azure-iac` resolve isso com um estágio
de **mapeamento de vocabulário**: o LLM, ancorado via RAG na própria secção do benchmark, mapeia cada
controlo para o atributo concreto em **ambos** os vocabulários — cada controlo vira duas regras, e um
único build serve `.tf`, `.bicep` e `.json`. Controlos sem expressão em IaC são declarados
"portal-only" e contados, não inventados; mapeamentos sem impacto ou com nomes implausíveis são
rejeitados na validação.

```bash
caspar-full python -m config_assessment.plugins.azure_iac.build_azure \
  -b CIS_Microsoft_Azure/CIS_..._Foundations_...pdf -b CIS_..._Storage_...pdf \
  --model qwen2.5:14b            # uma vez; runtime continua determinístico
```

### Kubernetes, Dockerfile e Ubuntu OS: regras curadas

K8s (CIS §5), Dockerfile (CIS Docker) e **Ubuntu** (CIS Ubuntu 22.04 L1 — subconjunto config-based:
`sysctl` kernel/rede + `/etc/login.defs`) usam regras **curadas à mão** com build 100% determinístico
(`build/curated_build.py`) — sem LLM nesse caminho. Inclui a chain curada privileged+hostNetwork e a
absence rule do `USER` (root por omissão).

```bash
caspar scan /etc/sysctl.conf         # Ubuntu OS: hardening de kernel/rede
caspar scan test_target/ubuntu_demo/sysctl.conf   # fixture de demo
```

> **Para a defesa:** a base de conhecimento tem **três proveniências** — LLM-extraída
> (apache/nginx/…/azure-iac), curada (kubernetes/dockerfile/ubuntu) e promovida (ciclo `promote`) —
> todas a alimentar o mesmo scoring determinístico, e tudo **sem tocar no core** (zero alterações a
> `runtime.py`).

---

## Avaliação e comparação com baselines

Dois scripts reproduzíveis produzem o material de avaliação (`scripts/`):

```bash
python -m scripts.evaluate                  # composição da KB · MAE vs CCE · recall nas fixtures
python -m scripts.baseline_compare --oscap  # CASPAR vs Trivy (IaC/Docker) e OpenSCAP (Ubuntu OS)
```

- **Correção:** MAE vs *ground truth* CCE oficial (Apache) — **0% mismatch (20/20)**.
- **Deteção:** recall nas fixtures vulneráveis — **100% (14/14)**.
- **Baselines:** o `baseline_compare` corre o **Trivy** (`.tf`, Dockerfile) e o **OpenSCAP**
  (Ubuntu OS, subconjunto config-based) no mesmo alvo. O contraste não é "quem encontra mais": ambos
  detetam misconfigs, mas o CASPAR anexa um **score CCSS reproduzível + narrativa** onde os outros dão
  um rótulo fixo / pass-fail. (Nota: em WSL o OpenSCAP dá `notapplicable` — precisa de VM Ubuntu para
  pass/fail reais.)

---

## Relatórios

### Terminal

Por omissão, um **resumo operacional**: painel de score, contagens por severidade, os piores findings, as cadeias disparadas, a recomendação e a cobertura da base de conhecimento. O detalhe completo fica atrás de `--verbose` (cada finding com base→temporal, GEL/GRL, CVEs, localização e recomendação) e `--show-chains`.

```
  CASPAR 0.1.0
  Configuration Vulnerability Meter · Reference Implementation

  ASSESSMENT SUMMARY                        ┌──────────────────────────────┐
  Service       : apache2 2.4.52            │ CONFIGURATION VULNERABILITY  │
  Plugin        : apache-httpd              │           SCORE              │
  Configuration : /etc/apache2/apache2.conf │          8.7 / 10            │
  Mode          : installed service         │  ████████████████████░░░░░   │
                                            │           HIGH               │
                                            └──────────────────────────────┘

  Highest finding 8.7   Highest chain 10.0   Chains triggered 9   → score from findings; chains not scored

  TOP FINDINGS

  #  Severity  Directive      Score  CCSS Vector                   File / Location
  ──────────────────────────────────────────────────────────────────────────────────
  1  HIGH      User             8.7  AV:N AC:L Au:N C:C I:C A:N    ...httpd.conf:19
  2  HIGH      Group            7.9  AV:N AC:L Au:N C:P I:C A:N    ...httpd.conf:20

  RECOMMENDATION

  !  This configuration scores 8.7 — HIGH overall vulnerability.
     Highest-value fix: User (8.7)
     → Set 'User apache' and 'Group apache' to run Apache unprivileged.

     Note: these findings compose into privilege-escalation, rated 10.0 —
     higher than any single finding.
```

O score vem sempre do pior finding individual, pelo que é rastreável a uma directiva corrigível. As cadeias têm score próprio e são reportadas como aviso — ver [Attack chains](#attack-chains-geradas-por-llm-stage-2).

### HTML (relatório completo)

Self-contained, funciona offline, dark mode automático. Cada issue é colapsável com:

- **Descrição narrativa** específica à directiva e valor concreto
- **Scores** (Base e Temporal) com barras visuais
- **Exploitability** (AV, Au, AC) — cada métrica com a sua justificação real, não genérica
- **Impact & Temporal** (C, I, A, GEL, GRL) — idem
- **Potential impact** — lista concreta de consequências
- **Exploitation scenario** — pré-requisitos, exemplo de código/config real, resultado
- **Recommendation** em destaque
- **CVEs e referências CIS/CCE**
- **Localização com snippet de configuração** — em vez de mostrar apenas `ficheiro:linha`, o relatório lê o ficheiro de configuração real e mostra o bloco de código com a linha da directiva destacada e 2 linhas de contexto acima/abaixo, com números de linha. Funciona em todos os modos, incluindo Docker (o directório temporário só é limpo depois dos relatórios serem escritos)

As attack chains mostram o score amplificado e a severidade, sem expor o multiplicador de amplificação (o factor está embutido no score, não é apresentado como número solto).

Filtros por severidade no topo. Exemplo de justificação real gerada para `AllowOverride=All`:

> AC=M: Exploitation requires write access to the web root directory, which is not trivial but possible through vulnerabilities like misconfigured file permissions.

(não "Medium complexity" genérico — a justificação explica o *porquê* específico a esta directiva).

```bash
caspar scan docker://ccss-test-apache:vulnerable --report --output ~/relatorios/
explorer.exe ~/relatorios/ccss_*.html   # WSL2
```

### JSON / SARIF

Disponíveis via `--format json` / `--format sarif`. O JSON inclui o **manifesto de
reprodutibilidade** (versão do CASPAR, SHA-256 da base de conhecimento, target e nº de regras):
dois scans com manifesto igual e `input_hash` igual têm, por construção, scores iguais — a
afirmação de determinismo torna-se auditável a partir do próprio relatório.

O SARIF integra directamente com o **GitHub Code Scanning** — os findings do CASPAR aparecem
na Security tab e como anotações nos PRs (*shift-left* para configs versionadas):

```yaml
# .github/workflows/config-audit.yml
- run: caspar scan configs/nginx.conf --report -f sarif -o out/
- uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: out/            # apanha o ccss_*.sarif gerado
```

---

## Acompanhamento contínuo e ciclo de aprendizagem

O scan pontual é metade da história; a outra metade é **direção e crescimento da base**:

```bash
caspar watch /etc/nginx/ --notify        # vigiar: re-scan a cada alteração, alerta se piorar
caspar history nginx.conf                # listar scans passados (gravados automaticamente)
caspar trend                             # drift quantificado: sparkline por input, 1º→último score
caspar trend nginx                       #   só inputs que contenham 'nginx'

caspar scan cfg --assess-unknown         # Camada 3: candidatas (LLM+RAG, nunca no score)
caspar promote cfg                       # candidata → regra permanente (com revisão)
caspar promote --stats                   # quanto da base veio do ciclo? o que falta rever?
caspar plugin manual nginx <pdf|url>     # juntar manual à base de conhecimento RAG (retroativo)
```

`trend` responde "para onde vai o risco desta config?"; `promote --stats` responde "quanto é
que o sistema já aprendeu para além do benchmark?" — as regras promovidas ficam marcadas na
`justification`, por isso a contagem é auditável.

---

## Arquitectura

```
BUILD TIME (uma vez por target)
────────────────────────────────────────────────────────────
  CIS Benchmark PDF  +  CCE XLS  +  NISTIR 7502
           │
           ▼
  RAG (TF-IDF sobre secções do benchmark)
           │
           ▼
  Stage 1 — LLM atribui AC, C, I, A          (llm_pipeline.py)
           │
           ▼
  Stage 2 — LLM gera attack chains            (chain_pipeline.py)
           │            calibradas pelos scores reais das partes
           ▼
  Stage 3 — LLM gera narrativas detalhadas    (narrative_pipeline.py)
           │            descrição + impacto + cenário + justificações
           ▼
  CVE enrichment — NVD API v2 + CISA KEV       (cve_enricher.py)
           │            GEL/GRL com dados reais de exploração
           ▼
  ┌──────────────────────────────────────────┐
  │  SQLite                                   │
  │  30 misconfigurations + narrativas        │
  │  attack chains geradas por LLM            │
  └──────────────────────────────────────────┘

RUNTIME (cada scan — zero LLM, zero chamadas externas)
────────────────────────────────────────────────────────────
  input (ficheiro / directório / --live / docker://)
    → input_resolver.py     → resolve para um path concreto
    → parse_config()        → list[Directive]
    → get_profile()         → AV, Au (regras determinísticas, worst-case)
    → lookup DB             → O(1) por (target, directive, bad_value)
    → ajuste AV/Au          → recomputa scores com perfil do sistema
    → chain detection       → subset match sobre directivas presentes
    → aggregate              → score global (pior caso)
    → ScanResult              → terminal / HTML / JSON / SARIF
```

### Interface de plugin

```python
class Target(ABC):
    def detect(self, path: str) -> bool: ...
    def parse_config(self, path: str) -> list[Directive]: ...
    def get_profile(self, directives: list[Directive]) -> SystemProfile: ...
    def metadata(self) -> TargetMetadata: ...
```

**Adicionar um novo target = criar `plugins/<nome>/` com 4 ficheiros. Zero mudanças no core.**

### Fórmulas CCSS (NISTIR 7502 §3.2)

```
f_impact  = 10.41 × (1 - (1-C[c]) × (1-C[i]) × (1-C[a]))
f_exploit = 20 × AV[av] × AU[au] × AC[ac]

BaseScore     = round(((0.6 × f_impact) + (0.4 × f_exploit) - 1.5) × 1.176, 1)
TemporalScore = round(BaseScore × GEL[gel] × GRL[grl], 1)
```

| Métrica | Valores e pesos |
|---|---|
| AV | L=0.395 · A=0.646 · N=1.000 |
| Au | M=0.450 · S=0.560 · N=0.704 |
| AC | H=0.350 · M=0.610 · L=0.710 |
| C/I/A | N=0.000 · P=0.275 · C=0.660 |
| GEL | N=0.900 · L=0.930 · M=1.000 · H=1.000 · ND=1.000 |
| GRL | U=0.900 · W=0.950 · H=1.000 · ND=1.000 |

---

## Estrutura de ficheiros

```
ccss_scan/
│
├── core/
│   ├── target.py                 # Interface abstracta Target
│   ├── models.py                 # Directive, SystemProfile, Misconfiguration (+ narrative)
│   ├── ccss.py                   # Fórmulas CCSS
│   ├── build.py                  # Pipeline build-time skeleton
│   ├── runtime.py                # Scan engine
│   ├── llm_client.py             # OllamaClient + StubLLMClient
│   ├── rag.py                    # TF-IDF sobre CIS Benchmark
│   ├── cve_enricher.py           # NVD API v2 + CISA KEV — GEL/GRL reais
│   ├── input_resolver.py         # 4 modos de scan (file/dir/live/docker)
│   ├── report_html.py            # Gerador HTML com narrativas completas
│   └── db/
│       ├── schema.sql            # 4 tabelas (+ campo narrative)
│       └── database.py           # Queries, upsert, update_narrative()
│
├── plugins/
│   ├── dummy/                    # Plugin fictício — valida a interface
│   └── apache_httpd/
│       ├── parser.py              # Parser httpd.conf
│       ├── rules.py               # Rule engine AV/Au
│       ├── chains.json            # Fallback de attack chains
│       ├── build_apache.py        # 30 misconfigs hard-coded (fallback)
│       ├── build_llm.py           # Entry point: Stage 1 + Stage 2
│       ├── llm_pipeline.py        # Stage 1 — métricas via LLM
│       ├── chain_pipeline.py      # Stage 2 — chains via LLM
│       ├── narrative_pipeline.py  # Stage 3 — narrativas via LLM
│       ├── build_narratives.py    # Entry point: Stage 3
│       ├── refresh_cve.py         # CVE enrichment standalone
│       └── validate_mae.py        # Validação vs CCE XLS
│
├── fetch/
│   ├── catalog.json             # serviço → STIG (slug stigviewer + fallback)
│   └── benchmark_fetcher.py     # descarrega STIG e converte para XCCDF
│
├── cli/
│   └── main.py                   # scan, build, targets, refresh, plugin add/fetch
│
├── tests/                         # 777 testes — fórmulas CCSS,
│   ├── test_ccss.py               #   parsers/regras por plugin, pipeline LLM
│   ├── test_runtime.py            #   (Stage 1/2/3), chains, enrichment CVE/TTP,
│   ├── test_apache.py             #   IaC (azure/k8s/dockerfile), CLI, RAG,
│   ├── test_llm_pipeline.py       #   NISTIR §4 replication, …
│   ├── test_chain_pipeline.py
│   └── test_cve_enricher.py
│
├── .env                          # NVD_API_KEY (gitignored)
├── .gitignore
└── pyproject.toml
```

---

## Target Apache HTTP Server 2.4

### Cobertura

**30 misconfigurations** em 26 secções CIS Benchmark v2.3.0, todas com narrativa completa gerada em Stage 3:

| Severidade | Nº | Exemplos |
|---|---|---|
| Critical (9–10) | 3 | `User=root`, `LoadModule dav_module` |
| High (7–8.9) | 2 | `Group=root`, `Options=All` |
| Medium (4–6.9) | 24 | `ServerTokens=Full`, `AllowOverride=All`, `SSLProtocol=All` |
| Low (0.1–3.9) | 1 | `SSLCompression=On` |

### Attack chains (geradas por LLM, Stage 2)

O LLM recebe a lista completa de misconfigurations com scores reais e identifica combinações perigosas, calibrando o factor de amplificação pela severidade das partes:

| Regra de amplificação | Factor |
|---|---|
| Todas as partes Medium | ×1.2 – ×1.4 |
| Pelo menos uma High | ×1.4 – ×1.6 |
| Pelo menos uma Critical | ×1.6 – ×1.8 |

Exemplos detectados: `privilege-escalation` (User+Group=root, ×1.6), `webdav-rce-chain` (LoadModule dav + AllowOverride All, ×1.7), `directory-traversal-chain` (Options+AllowOverride, ×1.5), `dos-amplification` (Timeout+KeepAliveTimeout+MaxKeepAliveRequests, ×1.4).

O factor de amplificação é um mecanismo interno de cálculo: o score final da chain (`amplified_score = base_da_pior_parte × factor`, cap em 10.0) reflecte-o, mas os relatórios não expõem o multiplicador como número solto — apresentam apenas o score resultante e a severidade. As bandas de amplificação são uma heurística proposta por este trabalho; o NISTIR 7502 define scoring de misconfigurations individuais mas não a sua composição em cadeias, pelo que esta é uma contribuição original que requer fundamentação na tese.

Fallback (`chains.json`) usado apenas se o LLM falhar repetidamente.

### CVE enrichment

Estratégia: lookup directo por CVE ID (não keyword search — a NVD não indexa por directiva Apache). Para os ~5 misconfigurations com CVEs já identificados pelo LLM (TraceEnable, SSLProtocol, SSLCompression), faz-se lookup real na NVD para obter CVSS score actualizado e verificar presença na CISA KEV. As restantes ~25 recebem GEL=Low directamente (risco de configuração sem CVE associado — correcto metodologicamente).

```bash
caspar refresh                    # actualiza GEL/GRL com dados NVD + KEV
caspar refresh --dry-run          # preview sem escrever
```

---

## Target Nginx

Plugin da Fase 3, demonstra a extensibilidade da arquitectura para um servidor
com sintaxe de configuração fundamentalmente diferente (blocos `{}` + `;` em vez
do estilo chave-valor do Apache), com zero alterações às fórmulas do core.

### Cobertura

**8 misconfigurations**, todas ancoradas em secções reais do CIS NGINX Benchmark
v3.0.0, com narrativa completa gerada em Stage 3:

| Directiva | Valor | Secção CIS |
|---|---|---|
| `server_tokens` | on | 2.5.1 |
| `keepalive_timeout` | 65 / 0 | 2.4.3 |
| `send_timeout` | 0 | 2.4.4 |
| `client_max_body_size` | 0 | 5.2.2 |
| `ssl_protocols` | TLSv1 TLSv1.1 / SSLv3 | 4.1.4 |
| `proxy_pass` | http://127.0.0.1:8080 | 2.5.4 |

### Decisões de design (e limitações honestas)

- **Sem validação CCE/MAE**: ao contrário do Apache, o NGINX não tem ground truth
  CCE publicado. O Nginx é validado por **revisão manual**; o Apache mantém-se como
  o caso de validação quantitativa (MAE vs CCE). Contribuições complementares.
- **Só directivas com secção CIS dedicada**: directivas sem âncora no benchmark
  (`autoindex`, `ssl_prefer_server_ciphers`) foram excluídas para manter cada
  misconfiguration rastreável à fonte.
- **Sem attack chains ainda**: 0 vs 9 do Apache (trabalho futuro).

### O que o segundo plugin refinou no core

Adicionar o Nginx expôs três acoplamentos implícitos ao formato Apache, todos
corrigidos — evidência concreta de que a arquitectura é extensível:

1. **Parser RAG** (`core/rag.py`): o regex de secções só aceitava IDs de 2 níveis
   (`8.1`); o CIS NGINX usa 3 (`2.5.1`). Generalizado para 2+ níveis.
2. **Prompt de build e de narrativas**: tinham "Apache HTTP Server" / "httpd.conf"
   fixos. Passaram a receber o nome do serviço dinamicamente.

O build é também **idempotente**: refazer com uma lista de misconfigurations mais
pequena remove as entradas órfãs em vez de as deixar no banco.

### Build do Nginx

```bash
# Stage 1 (métricas) — usa o branch nginx do comando build
caspar build --target nginx --benchmark plugins/nginx/CIS_NGINX_Benchmark_v3.0.0.pdf

# Stage 3 (narrativas) — pipeline genérico, target nginx
python3 -m plugins.apache_httpd.build_narratives --db ccss.db --target nginx

# Scan
caspar scan /caminho/para/nginx.conf --report --format dashboard
```

---

## LLM pipeline (build time) — 3 stages

### Instalar Ollama

```bash
curl -fsSL https://ollama.com/install.sh | sh   # Linux / WSL2
ollama serve
ollama pull qwen2.5:14b
```

| VRAM | Modelo |
|---|---|
| 16 GB+ | `qwen2.5:32b-instruct-q4_K_M` |
| 8 GB | `qwen2.5:14b` (usado neste projecto) |
| < 8 GB | `llama3.1:8b` |

### Stage 1 + Stage 2 — métricas e chains

```bash
caspar build --benchmark plugins/apache_httpd/Benchmark.pdf --model qwen2.5:14b
```

~2 minutos para 30 misconfigs + geração de chains (timeout de chains: 300s, prompt mais longo que métricas individuais).

### Stage 3 — narrativas detalhadas

```bash
python3 -m plugins.apache_httpd.build_narratives --db ccss.db --model qwen2.5:14b
```

~70 minutos para 30 narrativas (timeout de 300s por narrativa — prompt mais complexo, pede JSON estruturado com 4 secções). Corre uma vez; o resultado fica gravado no banco e é reutilizado em todos os scans seguintes sem nova chamada LLM.

**Enforcement de consistência métrica↔texto.** O Stage 3 garante que a justificação textual de cada métrica não contradiz o valor atribuído. O prompt inclui exemplos correctos/incorrectos de alinhamento (ex: AC=L deve descrever um exploit fácil, não "requer perícia"), e uma heurística pós-geração (`_ac_text_contradicts_value`) deteta sinais contraditórios no texto e substitui-os por um fallback determinístico coerente com o valor. Existe ainda um script standalone (`fix_ac_consistency.py`) que reverifica narrativas já gravadas sem re-chamar o LLM.

```bash
python3 fix_ac_consistency.py --db ccss.db --dry-run   # ver inconsistências
python3 fix_ac_consistency.py --db ccss.db              # corrigir
```

### Modo stub (sem GPU)

```bash
caspar build --benchmark Benchmark.pdf --stub
python3 -m plugins.apache_httpd.build_narratives --db ccss.db --stub
```

### Validar qualidade

```bash
python3 -m plugins.apache_httpd.validate_mae --db ccss.db --cce <CCE.xlsx>
```

Gate: mismatch rate ≤ 20% — actualmente **0%**.

---

## Testes

```bash
pytest tests/ -v               # todos
pytest tests/test_ccss.py -v   # só fórmulas
```

| Ficheiro | Testes | Cobre |
|---|---|---|
| `test_ccss.py` | 27 | Fórmulas NISTIR 7502 |
| `test_runtime.py` | 18 | Models, DB, scan engine |
| `test_apache.py` | 31 | Parser, rule engine |
| `test_llm_pipeline.py` | 41 | Stage 1 — RAG, JSON, métricas |
| `test_chain_pipeline.py` | 33 | Stage 2 — chains, normalização, dedup |
| `test_cve_enricher.py` | — | NVD client, KEV, GEL logic (offline, mocked) |
| **Total** | **150+** | **passing localmente** |

---

## Validação

### 1 — Testes automatizados

Cobre fórmulas, runtime, parser, rule engine, 3 stages do LLM pipeline, CVE enrichment, e determinismo (mesmo input → mesmo score sempre).

### 2 — Validação DISA vs CCE XLS

| DISA | Range CCSS esperado |
|---|---|
| CAT I (Critical) | 7.0 – 10.0 |
| CAT II (Medium) | 4.0 – 6.9 |
| CAT III (Low) | 0.1 – 3.9 |

**0 mismatches em 20 entries cruzados.** Gate: ≤20%.

### 3 — Determinismo runtime

O mesmo input produz o mesmo score em qualquer número de runs.

### 4 — Validação end-to-end com imagem Docker vulnerável

`tests/docker_fixtures/` contém uma imagem Apache deliberadamente insegura (`ServerTokens Full`, `User root`, `AllowOverride All`, SSL fraco, etc.) usada para validar os 4 modos de scan e o relatório completo end-to-end. Score obtido: 8.7 High (o pior finding, `User root`), 17 issues, 9 chains — a pior cadeia é cotada a 10.0 mas não entra no score. Confirma detecção correcta de todas as misconfigurations introduzidas deliberadamente.

---

## Gaps honestos

| Gap | Detalhe |
|---|---|
| Narrativas LLM — consistência mitigada, não garantida | O Stage 3 aplica enforcement de coerência entre o valor da métrica AC e o texto da justificação (prompt com exemplos + heurística de deteção + fallback determinístico). Isto resolve a classe de contradição mais comum, mas não garante ausência total de imprecisões noutras métricas — as narrativas continuam sujeitas a revisão humana antes de uso em produção. |
| CVE enrichment limitado a CVEs já conhecidos | Não há keyword search eficaz contra a NVD para misconfigurations sem CVE associado — é metodologicamente correcto (GEL=Low), mas significa que novos CVEs não identificados pelo LLM no Stage 1 não são descobertos automaticamente. |
| 85/105 CCE entries sem match | CCE XLS é da versão Apache 2.2 (2013); o banco cobre CIS v2.4 (2025). Sobreposição de 20 entries é o máximo possível. |
| Pydantic v2 | Data models usam dataclasses stdlib. Migração é substituir `@dataclass` por `BaseModel`. |
| PDF report | Disponíveis: HTML, JSON, SARIF. PDF previsto para Fase 5. |
| Plugins adicionais | Fase 3 — Nginx, SSH, Ubuntu, Docker. Metodologia validada, replicar é criar `plugins/<target>/` com 4 ficheiros. |

---

## Stack tecnológica

| Camada | Tecnologia |
|---|---|
| Linguagem | Python ≥3.10 |
| Interface plugin | `abc.ABC` |
| Data models | `dataclasses` stdlib |
| Base de dados | SQLite |
| RAG | TF-IDF stdlib |
| LLM (build time) | Ollama local — qwen2.5:14b |
| CVE enrichment | NVD API v2 + CISA KEV (stdlib `urllib`) |
| CLI | Click |
| Reports | HTML (self-contained) · JSON · SARIF 2.1.0 |
| Containers | Docker (modo de scan 4) |
