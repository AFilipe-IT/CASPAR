# CASPAR — Guia Comprensivo e Demonstração Prática

> Documento de leitura única para **perceber o que o CASPAR faz, porquê, e como usá-lo do zero**.
> Complementa o [GUIA_TECNICO.md](GUIA_TECNICO.md) (orientado à arquitectura interna) e o
> [README.md](README.md) (referência de comandos). Aqui o foco é *entender e demonstrar*.

**Índice**

*Fundamentos:* 1. [O que é](#1-o-que-é-o-caspar-em-duas-frases) · 2. [O problema](#2-o-problema-que-resolve) ·
3. [As duas metades](#3-as-duas-metades-do-sistema-a-decisão-de-design-central) ·
4. [Como o score é calculado](#4-como-o-score-é-calculado-ccss-resumido)

*Utilização:* 5. [Modos de scan](#5-os-quatro-modos-de-scan) · 6. [Formatos de relatório](#6-os-quatro-formatos-de-relatório) ·
7. [`add` vs `fetch`](#7-dois-modos-de-instalar-um-plugin-add-vs-fetch) ·
8. [Demonstração prática](#8-demonstração-prática) · 9. [Docker](#9-demonstração-via-docker-máquina-limpa-sem-clonar-o-repo) ·
10. [Fontes dos benchmarks](#10-de-onde-vêm-os-benchmarks-plugin-fetch)

*Aprofundamento:* 11. [Números do projeto](#11-números-do-projeto-a-base-de-conhecimento) ·
12. [Requisitos e tempos](#12-requisitos-de-sistema-e-tempos-esperados) · 13. [Attack chains em detalhe](#13-attack-chains-em-detalhe-exemplo-real) ·
14. [CI/CD](#14-integração-cicd-github-actions) · 15. [Comandos de produtividade](#15-comandos-de-produtividade) ·
16. [Directivas desconhecidas](#16-deteção-de-directivas-desconhecidas) ·
17. [Criar um plugin do zero](#17-criar-um-plugin-do-zero-utilizadores-avançados) ·
18. [Troubleshooting](#18-troubleshooting--erros-comuns) · 19. [vs outras ferramentas](#19-posicionamento-vs-outras-ferramentas) ·
20. [Roadmap](#20-roadmap--trabalho-futuro)

*Referência:* 21. [Onde mexer](#21-onde-mexer-mapa-rápido) · 22. [Resumo](#22-resumo-executivo)

---

## 1. O que é o CASPAR, em duas frases

CASPAR (*Configuration Assessment and Security Posture Automated Review*) lê a configuração de um
serviço — um ficheiro, um directório, um serviço instalado, ou uma imagem Docker — e atribui a cada
problema de configuração um **score de risco de 0 a 10**, com CVEs reais, narrativa técnica e cadeias
de ataque. O score baseia-se no **CCSS (Common Configuration Scoring System, NISTIR 7502)**, o
equivalente do CVSS mas para *misconfigurations* em vez de vulnerabilidades de código.

**A ideia-chave:** um benchmark de segurança (CIS ou DISA STIG) diz *"o quê"* está mal; o CASPAR
acrescenta *"quão grave"*, de forma **determinística e reproduzível** — o mesmo input dá sempre o
mesmo score.

---

## 2. O problema que resolve

Um administrador tem um `nginx.conf`. Sabe que existem benchmarks (CIS, STIG) com centenas de regras.
Mas:

- Ler 200 regras à mão e cruzá-las com a config é inviável.
- Nem todas as regras têm o mesmo peso — algumas são triviais, outras permitem RCE.
- Os benchmarks não dizem *quanto* risco cada desvio representa, nem se há CVEs/exploits associados.

O CASPAR automatiza isto: pega no benchmark, extrai as regras, e para cada uma calcula um score CCSS
com base em vector de ataque, autenticação, complexidade, impacto CIA, e maturidade de exploração.

---

## 3. As duas metades do sistema (a decisão de design central)

```
   BUILD TIME  (corre uma vez, por serviço)          RUNTIME  (corre em cada scan)
   ┌────────────────────────────────────┐            ┌──────────────────────────────┐
   │  Benchmark (PDF CIS / XML STIG)     │            │  Config do utilizador        │
   │        │                            │            │        │                     │
   │        ▼   extracção (heurística+LLM)│           │        ▼   parser            │
   │  Misconfigs + valores bad/good      │            │  Directivas detectadas       │
   │        │                            │            │        │                     │
   │        ▼   LLM (Ollama) + NVD/KEV    │            │        ▼   rule engine       │
   │  Scores CCSS + CVEs + narrativas    │──────DB────▶│  Match + score determinístico│
   │  + attack chains                    │  (SQLite)  │        │                     │
   └────────────────────────────────────┘            │        ▼                     │
                                                      │  Relatório (terminal/HTML/…) │
                                                      └──────────────────────────────┘
```

- **Build time** usa um LLM local (Ollama) e faz lookups de rede (NVD, CISA KEV). Corre **uma vez** e
  grava tudo numa base de dados SQLite.
- **Runtime** é **100% determinístico, zero LLM, zero rede**. Lê a DB e a config, faz o match, calcula
  o score. Scores idênticos para inputs idênticos — sempre. É isto que torna o CASPAR auditável.

Esta separação é o que distingue o CASPAR de "atirar a config a um ChatGPT": o julgamento de risco é
feito uma vez, revisto, e depois aplicado de forma reprodutível.

---

## 4. Como o score é calculado (CCSS, resumido)

Cada misconfiguration tem um **Base Score** derivado de 6 submétricas (NISTIR 7502 §3.2):

| Métrica | Significado | Valores |
|---------|-------------|---------|
| **AV** — Access Vector | de onde se explora | Local / Adjacent / Network |
| **Au** — Authentication | autenticação necessária | Multiple / Single / None |
| **AC** — Access Complexity | dificuldade de exploração | High / Medium / Low |
| **C / I / A** | impacto Confidencialidade / Integridade / Disponibilidade | None / Partial / Complete |

O **Temporal Score** ajusta o base com dois fatores de maturidade:

- **GEL** (General Exploit Level) — existe exploit? está no catálogo CISA KEV (exploração ativa)?
- **GRL** (General Remediation Level) — há correção oficial?

Exemplo real (do scan mais abaixo): `keepalive_timeout 65` → Base 5.0, GEL:M GRL:H → Temporal 5.0.
Directivas com CVE em KEV sobem; directivas com remediação oficial descem ligeiramente.

O score global do serviço agrega os individuais, e **attack chains** amplificam quando várias
misconfigs se combinam (ex.: TLS fraco + sem verificação de certificado = MITM viável).

---

## 5. Os quatro modos de scan

```bash
caspar scan /etc/nginx/nginx.conf          # 1. ficheiro único
caspar scan /etc/nginx/                     # 2. directório (segue Includes)
caspar scan --live nginx                    # 3. serviço instalado na máquina
caspar scan docker://nginx:1.25             # 4. imagem Docker (extrai a config)
```

Opções úteis: `--threshold 7.0` (sai com código 1 se o score exceder — para pipelines),
`--service-version 1.25` (cruza com CVEs dessa versão específica), `--report` (grava relatório —
ver §6).

---

## 6. Os quatro formatos de relatório

Por omissão o scan imprime no terminal. Com `--report` grava um ficheiro em `reports/`; o formato
escolhe-se com `-f`:

```bash
caspar scan nginx.conf                              # só terminal
caspar scan nginx.conf --report                     # + HTML (formato por omissão)
caspar scan nginx.conf --report -f dashboard        # + dashboard visual
caspar scan nginx.conf --report -f json             # + JSON estruturado
caspar scan nginx.conf --report -f sarif            # + SARIF (GitHub / CI)
caspar scan nginx.conf --report -f dashboard --online   # dashboard com gráficos via CDN
```

| Formato | Para quê | Conteúdo |
|---------|----------|----------|
| **terminal** | inspeção rápida | Compacto, por severidade (Critical→Low): score, barra, CIA, base→temporal, GEL/GRL, CVEs, localização, recomendação. |
| **html** *(por omissão)* | análise detalhada, partilha | Self-contained, offline, dark mode. Cada issue é **colapsável** com narrativa específica, justificação real de cada submétrica (não "Medium" genérico mas *porquê*), cenário de exploração com exemplo, **snippet da config real** com a linha destacada, CVEs e referências CIS/CCE. Filtros por severidade. |
| **dashboard** | visão executiva, apresentações | Painel visual com **gauges** (score global, distribuição), **donuts** (severidades, impacto CIA) e gráficos. `--online` usa ECharts via CDN (gráficos mais ricos); sem `--online` é self-contained. |
| **json** | automação, pipelines | Dump estruturado completo do resultado (todos os campos do modelo). |
| **sarif** | GitHub Code Scanning | Integra diretamente com o *Security tab* do GitHub e ferramentas CI que falam SARIF 2.1. |

O relatório é gravado em `<projeto>/reports/` por omissão (ou `-o <dir>`). Em WSL2, abre com
`explorer.exe reports/ccss_*.html`.

---

## 7. Dois modos de instalar um plugin: `add` vs `fetch`

Antes de fazer scan de um serviço, é preciso um **plugin** para ele. Há dois caminhos, para dois
cenários diferentes — **não são intermutáveis**:

| | `caspar plugin add` | `caspar plugin fetch` |
|---|---|---|
| **Entrada** | um **ficheiro que já tens** (`--source benchmark.pdf` ou `.xml`) | um **nome de serviço** (`nginx`, `mongodb`, …) |
| **O que faz** | extrai e instala a partir desse ficheiro | **descobre e descarrega** o benchmark de fonte pública, depois (com `--then-install`) instala |
| **Precisa de rede?** | Não | Sim (vai buscar ao stigviewer.com) |
| **Quando usar** | já descarregaste o PDF CIS / STIG à mão, ou tens um benchmark próprio | não queres procurar o ficheiro — deixas o CASPAR encontrá-lo |

```bash
# add — a partir de um ficheiro local (CIS PDF ou DISA STIG XML)
caspar plugin add --source sources/benchmarks/CIS_PostgreSQL_13.pdf
caspar plugin add --source sources/stigs/U_Redis_Enterprise_6-x_STIG.xml

# fetch — a partir do nome, descoberta automática
caspar plugin fetch --list                  # ver os 43 alvos disponíveis
caspar plugin fetch mongodb                  # só descarrega (para inspeção)
caspar plugin fetch mongodb --then-install   # descarrega + instala num passo
```

Na prática, **`fetch --then-install` é o `add` sem teres de arranjar o ficheiro primeiro** — por baixo,
o `fetch` descarrega o STIG, converte-o para XCCDF, e entrega-o exatamente ao mesmo pipeline do `add`.
Por isso os dois partilham toda a lógica de extracção; a única diferença é *de onde vem o ficheiro*.

Flags úteis do `add` (também aplicáveis ao que o `fetch --then-install` corre por baixo):
`--dry-run` (mostra o que extrairia sem instalar), `--no-llm` (só heurística, sem Ollama),
`-y` (sem confirmação), `--verbose` (lista todos os controlos extraídos).

---

## 8. DEMONSTRAÇÃO PRÁTICA

### 8.1 — Cenário: instalar um serviço novo e fazer scan, do zero

Suponhamos que queremos avaliar um MongoDB mas ainda não temos plugin para ele. Historicamente
teríamos de: encontrar o STIG certo, descarregá-lo, e correr `plugin add` à mão. Com `plugin fetch`,
é um comando.

**Passo 1 — ver o que está disponível (43 alvos catalogados):**

```bash
caspar plugin fetch --list
```

```
  SERVICE         BENCHMARK                              SOURCE
  ────────────────────────────────────────────────────────────
  nginx           NGINX                                  stigviewer
  mysql           MySQL                                  stigviewer
  postgresql      PostgreSQL                             stigviewer
  mongodb         MongoDB Enterprise Advanced 8.x        stigviewer
  rhel9           Red Hat Enterprise Linux 9             stigviewer
  windows-server-2022  Microsoft Windows Server 2022     stigviewer
  ...  (43 alvos: web/app, bases de dados, contentores, SOs, rede)
```

**Passo 2 — descobrir, descarregar e instalar automaticamente:**

```bash
caspar plugin fetch mongodb --then-install
```

Nos bastidores: descarrega o STIG do MongoDB de `stigviewer.com/stigs/mongodb_enterprise_advanced_8x/export/json`,
converte para XCCDF, extrai as ~55 regras (heurística + LLM Ollama), gera o plugin e popula a DB.

```
Fetching benchmark for 'mongodb'...
  ✓ Downloaded: /tmp/U_mongodb_enterprise_advanced_8x_V1R1_STIG.xml

Analysing U_mongodb_..._STIG.xml...
Identified: Mongodb (key_value — mongodb.conf)
STIG rules: 55 (12 high · 41 medium · 2 low)
Extracting controls...
  ✓ plugins/mongodb/{__init__,parser,rules,build_mongodb}.py

Plugin 'mongodb' installed successfully.
  Misconfigs: 16 | Chains: 2 | Narratives: 16/16
```

> O nº de misconfigs/chains depende do modelo LLM: `mistral:7b` (por omissão) extrai mais e gera
> chains; um modelo leve como `qwen2.5:1.5b` extrai menos e pode gerar 0 chains (bom para testar
> o fluxo depressa, não para produção).

**Passo 3 — confirmar que ficou disponível:**

```bash
caspar targets
```

```
  PLUGIN         VERSION   BENCHMARK
  ──────────────────────────────────────────────
  apache-httpd   2.4       CIS Apache HTTP Server 2.4 Benchmark v2.3.0
  nginx          3.0       CIS NGINX Benchmark v3.0.0
  ...
  mongodb        1.0       U mongodb enterprise advanced 8x V1R1 STIG   ← novo
```

**Passo 4 — fazer scan de uma config MongoDB (com relatório):**

```bash
caspar scan /etc/mongod.conf                          # resultado no terminal
caspar scan /etc/mongod.conf --report -f dashboard    # + painel visual em reports/
```

### 8.2 — Um scan real, comentado (nginx)

Correndo `caspar scan test_nginx.conf` sobre uma config nginx propositadamente vulnerável:

```
  5.7/10  [Medium]  [file]  test_nginx.conf
  █████████████████░░░░░░░░░░░░░
  AV:N=Network  Au:N=None  ·  16 directivas

  ISSUES  7 Medium

  5.7  add_header =                        C:P I:P A:N  AC:L
       Base 6.4 → Temporal 5.7  GEL:L GRL:W
       Without a Content-Security-Policy header, browsers apply only the
       Same-Origin Policy, which does not prevent XSS attacks…
       → Add a Content-Security-Policy header tailored to the application.

  5.0  keepalive_timeout = 65              C:N I:N A:P  AC:L
       Base 5.0 → Temporal 5.0  GEL:M GRL:H
       test_nginx.conf:12 [http]
       A high keep-alive timeout can lead to resource exhaustion…
       → Set 'keepalive_timeout' to 10 seconds or less. E.g. 'keepalive_timeout 10;'
```

Como ler cada bloco:
- **`5.7`** — score temporal (a barra é visual). **`[Medium]`** — categoria de severidade.
- **`C:P I:P A:N`** — impacto: Confidencialidade Partial, Integridade Partial, Disponibilidade None.
- **`Base 6.4 → Temporal 5.7`** — o ajuste temporal (GEL:L GRL:W) baixou ligeiramente o base.
- **A localização** (`test_nginx.conf:12 [http]`) aponta a linha e o contexto exatos.
- **`→`** é a recomendação de remediação acionável.

### 8.3 — Gerar os relatórios (os quatro formatos, ver §6)

```bash
caspar scan test_nginx.conf --report -f html         # HTML rico (colapsável) → reports/
caspar scan test_nginx.conf --report -f dashboard    # painel visual com gauges/donuts
caspar scan test_nginx.conf --report -f sarif        # GitHub Code Scanning / CI
caspar scan test_nginx.conf --threshold 7.0          # falha o pipeline se score > 7
```

Abre o HTML ou o dashboard no browser para ver as narrativas completas, os cenários de exploração e
os gráficos. Em WSL2: `explorer.exe reports/ccss_test_nginx.conf_*.html`.

---

## 9. Demonstração via Docker (máquina limpa, sem clonar o repo)

Ideal para uma máquina de testes: um comando instala tudo (imagens + wrapper).

```bash
# 1. instalar
curl -fsSL https://raw.githubusercontent.com/AFilipe-IT/CASPAR/master/install.sh | sh

# 2. instalar um alvo (usa Ollama embutido na imagem :full)
caspar plugin fetch mongodb --then-install

# 3. prova de persistência — um container NOVO continua a ver o plugin
caspar targets                     # mongodb aparece

# 4. scan
caspar scan /caminho/para/mongod.conf --report -f html
```

**Persistência:** os plugins instalados e a base de dados vivem no volume Docker `caspar_data`,
por isso sobrevivem entre execuções apesar de cada container correr com `--rm`. Na primeira vez a DB
é semeada a partir da versão canónica embutida na imagem.

**Modelo LLM:** o `--then-install` corre extracção por LLM. Por omissão usa `mistral:7b` (qualidade
alta, mas lento em CPU — pode levar minutos a horas conforme o nº de regras). Para testes rápidos:

```bash
CASPAR_MODEL=qwen2.5:1.5b caspar plugin fetch mongodb --then-install
```

(Modelo leve = mais rápido, mas menos misconfigs/chains extraídas — bom para validar o fluxo, não
para produção.)

---

## 10. De onde vêm os benchmarks (`plugin fetch`)

O CASPAR descobre benchmarks a partir do **stigviewer.com**, que expõe cada STIG como JSON estruturado
em `/stigs/<slug>/export/json`. O fetcher converte esse JSON num ficheiro XCCDF (o formato DISA STIG
padrão), que o `plugin add` já sabe consumir — por isso `fetch` e `add` partilham todo o pipeline de
extracção.

O catálogo (`config_assessment/fetch/catalog.json`) mapeia um nome amigável (`mongodb`) ao slug do
stigviewer, e cobre **43 alvos** em 5 categorias: web/app servers, bases de dados, contentores, sistemas
operativos e equipamento de rede. Alguns têm **fonte de fallback** (se a primária falhar, tenta a
seguinte). O stigviewer tem 400+ STIGs no total — adicionar mais é só acrescentar `{ "slug": "..." }`
ao catálogo.

> Nota sobre outras fontes investigadas: o `ComplianceAsCode/content` (GitHub) só tem conteúdo ao nível
> de SO, e o `public.cyber.mil` é uma SPA JavaScript sem links estáticos — por isso o stigviewer é a
> única fonte fiável *por serviço*.

---

## 11. Números do projeto (a base de conhecimento)

A base de dados canónica que vem na imagem (semeada de `data/ccss_canonical.sql`) contém:

| Métrica | Valor |
|---------|-------|
| Targets built-in | **7** (apache-httpd, nginx, mysql, redis, ssh, tomcat, docker) |
| Misconfigurations catalogadas | **228** (com score CCSS, narrativa e recomendação) |
| Attack chains | **26** (combinações que amplificam o risco) |
| Version-exploits pré-computados | **19** (mapeamento versão → CVEs/exploits) |
| Alvos disponíveis via `plugin fetch` | **43** (stigviewer.com) |
| Testes automatizados | **452** (a passar) |

Distribuição das 228 misconfigs pelos 7 targets: **docker 57 · tomcat 49 · apache-httpd 35 ·
redis 29 · mysql 23 · nginx 18 · ssh 17**. Estes números são **verificáveis** — inspeciona a DB com
`sqlite3 ccss.db "SELECT target_name, COUNT(*) FROM misconfigurations GROUP BY target_name"`.

---

## 12. Requisitos de sistema e tempos esperados

O **runtime** (scan) é leve; o **build-time** (extração por LLM) é que pesa, por causa do Ollama.

**Requisitos:**

| Recurso | Necessário |
|---------|-----------|
| Scan (runtime) | Python 3.11+, ~100 MB RAM. Determinístico, sem GPU, sem rede. |
| Build com LLM (`plugin add`/`fetch --then-install`) | Ollama + modelo. `mistral:7b` ⇒ **~5 GB RAM** (menos = swap lento). GPU acelera muito mas não é obrigatória. |
| Imagem Docker `:latest` | **~545 MB** |
| Imagem Docker `:full` (Ollama embutido) | **~4.5 GB** + o modelo (`mistral:7b` ≈ 4 GB, descarregado no 1º uso para o volume) |

**Tempos esperados (ordem de grandeza, em CPU):**

| Operação | Tempo |
|----------|-------|
| `caspar scan` | **~100–500 ms** (determinístico; escala com o nº de directivas) |
| Seed da DB canónica (1º arranque Docker) | **< 1 s** |
| `plugin fetch <svc>` (só download) | **~1–3 s** |
| `plugin fetch --then-install`, 1ª vez | **+5–15 min** (pull do modelo Ollama) **+ minutos a horas** de extração (1 chamada LLM por regra; ~25–45 s/regra em CPU com `mistral:7b`) |
| O mesmo com `CASPAR_MODEL=qwen2.5:1.5b` | **muito mais rápido** (~min), menos regras/chains extraídas — para testar o fluxo |

> Regra prática: em CPU, um STIG de 50 regras com `mistral:7b` demora facilmente **>1 h**. Usa o modelo
> leve para validar o fluxo e o `mistral:7b` só quando queres a qualidade final. O `scan` em si é
> sempre instantâneo — o custo é uma vez, no build.

---

## 13. Attack chains em detalhe (exemplo real)

Uma *attack chain* é um conjunto de misconfigs que, **combinadas**, valem mais do que a soma das
partes: o score da chain é amplificado por um fator. Exemplo real da DB (chain
`directory-traversal-chain`, target apache-httpd):

```
Chain: directory-traversal-chain            amplificação ×1.5
├─ Options FollowSymLinks     [Base 5.8]  AV:N Au:N AC:M
└─ AllowOverride All          [Base 5.8]  AV:N Au:N AC:M
   Justificação: Options FollowSymLinks ou Indexes combinado com
   AllowOverride All permite um .htaccess controlado pelo utilizador
   escalar privilégios e permitir directory traversal ou execução de
   scripts arbitrários.
```

Isoladamente, cada directiva é um Medium (~5.8). Juntas, a chain aplica ×1.5 porque uma habilita a
exploração da outra (o `AllowOverride All` deixa o atacante usar `.htaccess` para tirar partido do
`FollowSymLinks`). O relatório mostra o score amplificado, não o multiplicador solto — o fator está
embutido no resultado. As 26 chains da DB são geradas no build-time por LLM (com fallback para um
`chains.json` curado por plugin quando o LLM falha).

---

## 14. Integração CI/CD (GitHub Actions)

O formato SARIF integra diretamente com o *Security tab* do GitHub. Exemplo de workflow:

```yaml
name: CASPAR Config Scan
on: [push, pull_request]
jobs:
  caspar:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Run CASPAR (falha se score > 7.0)
        run: |
          docker run --rm -v "$PWD:/workspace:ro" -w /workspace \
            alfilipe/caspar:latest \
            scan nginx.conf --report -f sarif --threshold 7.0 -o /workspace/reports

      - name: Upload SARIF para o GitHub Security
        if: always()                        # envia mesmo se o threshold falhar
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: reports/
```

Notas: `--threshold 7.0` faz o job **falhar** (exit 1) se o score exceder — usa `if: always()` no
upload para o SARIF ir à mesma. O `-o /workspace/reports` grava dentro do repositório montado (a
imagem monta `/workspace` read-only, por isso aponta o output para lá explicitamente). Para JSON
programático em vez de SARIF, troca por `-f json`.

---

## 15. Comandos de produtividade

Além do `scan`, o CASPAR tem comandos que operam sobre os resultados — úteis em CI, hardening
iterativo e gestão de risco.

**`diff` — comparar dois scans no tempo.** Reutiliza o JSON; mostra resolvidas, novas e o delta de
score. Sai com código 1 se o score **piorou** (bom para bloquear PRs que degradam a config):

```bash
caspar scan nginx.conf --report -f json -o antes/
# … alterações ao nginx.conf …
caspar scan nginx.conf --report -f json -o depois/
caspar diff antes/ccss_*.json depois/ccss_*.json
#   Score: 5.7 → 6.9  ▲ 1.2      ← a última alteração piorou 1.2 pontos
#   Resolved: 1   New: 3
```

**`suppress` — aceitar um risco conhecido.** Marca uma misconfig como aceite (com justificação
obrigatória); scans futuros escondem-na com `--suppress-file` (ou `.caspar-suppress.json` no cwd):

```bash
caspar suppress keepalive_timeout -r "Aprovado por arquitetura em 2026-06-15"
caspar suppress --list
caspar scan nginx.conf --suppress-file .caspar-suppress.json   # keepalive escondido
```

**`explain` — a origem completa de uma regra, sem correr scan.** Secção do benchmark, submétricas
CCSS, CVEs e narrativa:

```bash
caspar explain keepalive_timeout --target nginx
```

**`history` — evolução do score.** Cada scan é gravado na DB; consulta o histórico:

```bash
caspar history                     # todos os scans recentes
caspar history nginx.conf --last 5
```

**`watch` — re-scan automático ao editar.** Feedback em tempo real durante hardening manual (mostra
o score a subir/descer a cada gravação do ficheiro):

```bash
caspar watch /etc/nginx/nginx.conf
```

**`badge` — badge de score para README** (estilo shields.io):

```bash
caspar badge reports/ccss_nginx.json          # markdown para colar no README
# ![CASPAR Score](https://img.shields.io/badge/CASPAR-5.7%2F10-yellow)
```

**`plugin fetch --search` — busca fuzzy no catálogo** (evita adivinhar o slug):

```bash
caspar plugin fetch --search postgres         # sugere postgresql, epas
```

**Exit codes diferenciados (CI).** `--exit-code` no scan dá **2** se houver Critical, **1** se acima
do `--threshold`, **0** caso contrário — controlo fino para pipelines:

```bash
caspar scan nginx.conf --exit-code --threshold 7.0
```

---

## 16. Deteção de directivas desconhecidas

**O problema:** o CASPAR só deteta misconfigurations que estão na base de conhecimento (o benchmark).
Uma directiva nova — introduzida numa versão mais recente do serviço, de um módulo de terceiros, ou
simplesmente fora do benchmark — não teria regra e seria **invisível** ao scanner. O parser lê-a, mas
nada a examina.

A solução funciona em **três camadas**, desenhadas para **não quebrar o determinismo** do runtime:

**Camada 1 — surfacing (determinística, sempre ligada).** Toda a directiva parseada que não tem
regra na base (nem *value* nem *absence*) é reportada num painel `UNCOVERED DIRECTIVES`. Não é
pontuada — é uma lacuna de cobertura, tornada visível. Puro conjunto-diferença, sem LLM.

**Camada 2 — triagem heurística (determinística).** Das não-cobertas, marca as *suspeitas* por regras
de padrão auditáveis: valor `*`, bind a `0.0.0.0`, permissões `777`, uma directiva com nome de
segurança (`ssl`, `verify`, `auth`…) posta a `off`, ou um nome que sugere não-produção (`debug`,
`experimental`, `test`). Continua sem LLM.

```
UNCOVERED DIRECTIVES  (5)  3 suspicious
  ⚠ listen = 0.0.0.0:8080          ← binds to all interfaces (0.0.0.0)
  ⚠ weird_perm = 0777              ← world-writable permissions (777)
  ⚠ experimental_debug_mode = on   ← directive name suggests non-production ('debug')
  · worker_processes = 1
  · worker_connections = 1024
```

**Camada 3 — avaliação por LLM + RAG (não-determinística, opt-in via `--assess-unknown`).** Para cada
directiva desconhecida, o LLM (Ollama) é *grounded* em contexto RAG — o benchmark do plugin **mais**
documentação opcional que forneças com `--docs` — e estima se é uma misconfiguration, com impacto e
justificação. Os resultados são **candidatos de baixa confiança, nunca somados ao score CCSS**: aparecem
marcados à parte. É essencialmente "gerar uma regra candidata em tempo de scan", que podes depois
validar e promover à base com `plugin add`.

```bash
caspar scan nginx.conf                              # Camadas 1+2 (determinístico)
caspar scan nginx.conf --assess-unknown             # + Camada 3 (LLM+RAG)
caspar scan nginx.conf --assess-unknown --docs manual_nginx_2.6.txt   # + docs próprias
```

> **Nota de honestidade:** isto **não** é um "detetor de zero-days". Uma directiva desconhecida pode ser
> nova, de terceiros, um typo, ou perfeitamente benigna — o mecanismo revela *lacunas de cobertura* e,
> opcionalmente, dá um palpite fundamentado. Nunca promete detetar exploits desconhecidos, e por isso
> mantém a credibilidade do scoring determinístico: o LLM fica confinado a candidatos claramente
> rotulados, fora do score.

---

## 17. Criar um plugin do zero (utilizadores avançados)

Além de `add` (de ficheiro) e `fetch` (descoberta), podes escrever um plugin à mão — útil para um
serviço não catalogado, um formato de config invulgar, ou um benchmark proprietário. Um plugin é um
directório em `config_assessment/plugins/<serviço>/` com quatro ficheiros:

```
config_assessment/plugins/myservice/
├── __init__.py          # regista o plugin (register_plugin) + metadata
├── parser.py            # lê a config → lista de Directive(nome, valor, ficheiro, linha, contexto)
├── rules.py             # infere o SystemProfile (AV/Au) a partir das directivas
└── build_myservice.py   # ENTRIES: lista de (directiva, bad, good, secção) → popula a DB
```

Caminho mais rápido — **copiar um plugin existente e adaptar**:

```bash
cp -r config_assessment/plugins/nginx config_assessment/plugins/myservice
# edita:
#  __init__.py      → muda target_id/service_name/config_filenames
#  parser.py        → ajusta ao formato da config (key-value, blocos, etc.)
#  build_*.py       → substitui ENTRIES pelas tuas regras (directiva, bad, good, secção)
# depois corre o build do plugin para popular a DB a partir das ENTRIES
caspar targets                                            # confirma que aparece
```

O `parser.py` já tem parsers genéricos reutilizáveis (`config_assessment/parsers/`) para formatos
key-value — na maioria dos casos é só delegar. O `rules.py` define como o serviço é exposto
(rede/local, autenticação) para o cálculo do AV/Au. Vê `plugins/nginx/` como referência mínima e
`plugins/apache_httpd/` como exemplo completo (com chains e narrativas).

---

## 18. Troubleshooting — erros comuns

| Sintoma | Causa provável | Solução |
|---------|----------------|---------|
| `Ollama not reachable at http://localhost:11434 — falling back to stub client` e **0 controls** extraídos | O comando correu sem Ollama disponível (ou na imagem `:latest` em vez da `:full`) | Usa a imagem `:full` (tem Ollama embutido) ou arranca o Ollama; o wrapper encaminha `plugin add`/`fetch --then-install` para `:full` automaticamente. |
| `model 'X' not found` no Ollama | O modelo pedido não está descarregado | `ollama pull <modelo>`, ou passa `CASPAR_MODEL=<modelo já instalado>`. Na imagem `:full` o entrypoint faz o pull automaticamente. |
| `plugin fetch` falha com erro de rede / HTTP | stigviewer.com inacessível | Descarrega o STIG à mão e usa `caspar plugin add --source ficheiro.xml`. Alguns alvos têm fonte de fallback automática (apache, mongodb, postgresql, rhel9, sqlserver, windows-server-2022). |
| `OSError: [Errno 30] Read-only file system` no fetch | Output apontado para um caminho read-only (ex. `/workspace` no container) | Usa `-o /tmp` (já é o default na imagem) ou outro dir com escrita. |
| `permission denied` no volume `caspar_data` | Permissões do volume Docker (uid do container ≠ dono do volume) | O volume é escrito pelo utilizador `caspar` (uid 1000). Se criaste o volume com outro dono, remove-o (`docker volume rm caspar_data`) e deixa o entrypoint recriá-lo. |
| Plugin instalado mas `caspar targets` **não o mostra** | A DB de scan está fora de sync, ou o plugin foi escrito para dentro do container sem volume | Confirma que corres com `-v caspar_data:/home/caspar/data`; um `plugin add`/`fetch` sem esse volume perde-se no `--rm`. Verifica a DB: `sqlite3 ccss.db "SELECT target_name FROM misconfigurations GROUP BY target_name"`. |
| `pdftotext: command not found` no `plugin add` de um PDF | Falta o poppler-utils | `sudo apt-get install poppler-utils` (a imagem Docker já o traz). |

---

## 19. Posicionamento vs outras ferramentas

> **Nota:** esta tabela é *posicionamento conceptual*, não um benchmark. Reflete o desenho do CASPAR;
> as colunas de terceiros são a nossa leitura de alto nível, não um teste comparativo. Confirma sempre
> as capacidades atuais de cada ferramenta na fonte respetiva.

| Ferramenta | Abordagem | Scoring quantitativo (CCSS) | Reproduzível |
|------------|-----------|:---:|:---:|
| **CIS-CAT** | Compliance scanning (pass/fail vs CIS) | Não (pontua % de conformidade) | Sim |
| **OpenSCAP** | Avaliação XCCDF/OVAL | Não | Sim |
| **Trivy** | Scanning de vulnerabilidades (CVE) em imagens/IaC | Não (usa CVSS de CVEs, não de config) | Sim |
| **CASPAR** | **Scoring quantitativo de risco de configuração (CCSS)** | **Sim** | **Sim (build/runtime)** |

A distinção do CASPAR não é "detetar" desvios (várias ferramentas fazem isso bem) mas **quantificar o
risco** de cada um num score 0–10 comparável, com attack chains e CVEs — e fazê-lo de forma
determinística e auditável.

---

## 20. Roadmap / trabalho futuro

> Visão de direção, sujeita a validação. Não são compromissos.

- **Infrastructure-as-Code:** estender o scan a Terraform, Kubernetes YAML e Dockerfiles (hoje o foco
  é config de serviços já instalados).
- **Modo offline para `fetch`:** cache local / mirror dos STIGs para quando o stigviewer.com estiver
  indisponível (hoje o fallback é manual via `plugin add`, ou automático via fonte secundária).
- **Score de confiança por misconfig:** expor uma medida de certeza da extracção LLM (ex. consenso
  entre múltiplas gerações), para transparência sobre o não-determinismo do build.
- **Exportação OSCAL / GRC:** interoperar com ferramentas de compliance enterprise (Vanta, Drata) via
  o formato OSCAL do NIST.
- **Refinamento do scoring:** calibração das submétricas com mais ground truth CCE (hoje só o
  apache-httpd tem CCE para calibração).

*(Já implementado nesta linha:* `diff`, `suppress`, `history`, `explain`, `watch`, `badge`,
`fetch --search`, exit codes diferenciados — ver §15.)*

---

## 21. Onde mexer (mapa rápido)

| Quero… | Ficheiro |
|--------|----------|
| Adicionar um alvo ao `fetch` | `config_assessment/fetch/catalog.json` (só o slug) |
| Perceber a lógica de download | `config_assessment/fetch/benchmark_fetcher.py` |
| Mudar a extracção de benchmarks | `config_assessment/build/benchmark_extractor.py` |
| Regras de deteção de directivas desconhecidas | `config_assessment/core/unknown_directives.py` |
| Mexer nas fórmulas CCSS | `config_assessment/core/ccss.py` |
| Adicionar um comando CLI | `cli/main.py` |
| Mudar um relatório (HTML/dashboard/SARIF) | `config_assessment/reports/` |
| Ver a interface de um plugin | `config_assessment/plugins/<serviço>/` |
| Config do Docker / persistência | `docker/caspar/` + `install.sh` |

---

## 22. Resumo executivo

O CASPAR transforma um benchmark de segurança (CIS/STIG) num scanner de configuração com scoring de
risco reproduzível. A separação **build-time (LLM, uma vez) / runtime (determinístico, sempre)** dá-lhe
auditabilidade. O comando **`plugin fetch`** fecha o último passo manual: descobre e instala o
benchmark certo para 43 alvos com um comando, e os plugins persistem em Docker. O resultado é um
relatório priorizado por risco real — não uma lista de regras, mas *"isto é o que interessa, e porquê"*.
