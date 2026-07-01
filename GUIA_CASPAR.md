# CASPAR — Guia Comprensivo e Demonstração Prática

> Documento de leitura única para **perceber o que o CASPAR faz, porquê, e como usá-lo do zero**.
> Complementa o [GUIA_TECNICO.md](GUIA_TECNICO.md) (orientado à arquitectura interna) e o
> [README.md](README.md) (referência de comandos). Aqui o foco é *entender e demonstrar*.

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

Opções úteis: `--report -f html` (relatório HTML completo), `-f json|sarif` (integração CI/CD),
`--threshold 7.0` (sai com código 1 se o score exceder — para pipelines), `--service-version 1.25`
(cruza com CVEs dessa versão específica).

---

## 6. DEMONSTRAÇÃO PRÁTICA

### 6.1 — Cenário: instalar um serviço novo e fazer scan, do zero

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

**Passo 4 — fazer scan de uma config MongoDB:**

```bash
caspar scan /etc/mongod.conf
```

### 6.2 — Um scan real, comentado (nginx)

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

### 6.3 — Gerar um relatório para partilhar

```bash
caspar scan test_nginx.conf --report -f html      # relatório HTML rico → reports/
caspar scan test_nginx.conf --report -f sarif     # para GitHub code scanning / CI
caspar scan test_nginx.conf --threshold 7.0       # falha o pipeline se score > 7
```

---

## 7. Demonstração via Docker (máquina limpa, sem clonar o repo)

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

## 8. De onde vêm os benchmarks (`plugin fetch`)

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

## 9. Onde mexer (mapa rápido)

| Quero… | Ficheiro |
|--------|----------|
| Adicionar um alvo ao `fetch` | `config_assessment/fetch/catalog.json` (só o slug) |
| Perceber a lógica de download | `config_assessment/fetch/benchmark_fetcher.py` |
| Mudar a extracção de benchmarks | `config_assessment/build/benchmark_extractor.py` |
| Mexer nas fórmulas CCSS | `config_assessment/core/ccss.py` |
| Adicionar um comando CLI | `cli/main.py` |
| Ver a interface de um plugin | `config_assessment/plugins/<serviço>/` |
| Config do Docker / persistência | `docker/caspar/` + `install.sh` |

---

## 10. Resumo executivo

O CASPAR transforma um benchmark de segurança (CIS/STIG) num scanner de configuração com scoring de
risco reproduzível. A separação **build-time (LLM, uma vez) / runtime (determinístico, sempre)** dá-lhe
auditabilidade. O comando **`plugin fetch`** fecha o último passo manual: descobre e instala o
benchmark certo para 43 alvos com um comando, e os plugins persistem em Docker. O resultado é um
relatório priorizado por risco real — não uma lista de regras, mas *"isto é o que interessa, e porquê"*.
