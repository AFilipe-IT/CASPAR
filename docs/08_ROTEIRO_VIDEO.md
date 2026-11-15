# CASPAR — Vídeo de demonstração (anexo à dissertação)

**Corte actual:** 5 cenas · 25 planos · **~4:50** (288 s) · 1920×1080 (16:9) · 30 fps ·
**sem faixa de áudio**. Alvo principal: **apache**, numa VM com uma configuração deliberadamente
vulnerável (cenas 1–4). A cena 5 mede um segundo serviço real, **nginx**, instalado na mesma
máquina, e mostra a consola web a corrigi-lo em directo. Gravação de ecrã ao vivo — ver
[10_GRAVACAO_PASSO_A_PASSO.md](10_GRAVACAO_PASSO_A_PASSO.md).

> O ficheiro em `assets/video/CVM-CASPAR-demo.mp4` é um corte **anterior** (5:00, 33 planos,
> 8 cenas, dez alvos, cartões de desempenho). Serve de referência de ritmo; o roteiro válido é
> este. O *pipeline* de `assets/video/pipeline/` pertence a esse corte antigo.

O vídeo é **mudo**: não tem voz-off, música nem efeitos. É suporte visual para narração ao vivo
em português (§2). As legendas no ecrã estão em **inglês**, para coerência com os slides e com a
dissertação; este documento, como os restantes guias do repo, fica em português.

**Regra editorial:** nada aparece no ecrã que não esteja documentado na dissertação, e nenhum
número entra por cartão — tudo o que se vê é output real de comandos corridos em quadro. Os
valores de desempenho do Cap. 6 (44,5 s/controlo no *build*, 14–158 ms na avaliação) **saíram**
do vídeo: eram dois números que o ecrã não podia sustentar, e passam a ser material de defesa.

**O arco, em quatro frases:** o instrumento existe → mede uma máquina real → explica cada número
que atribui → serve para corrigir, e a correcção vê-se no score → e o resultado é reproduzível.

**Porque um alvo só, até à cena 5.** Seguir o apache do princípio ao fim responde à objecção mais
provável do júri — "isto só funciona nos ficheiros que vocês escreveram" — melhor do que passar
por dez alvos. A cena 5 introduz deliberadamente um segundo serviço, nginx, mas instalado a sério
na máquina de gravação: mostra que o mesmo instrumento, com a mesma base de conhecimento, serve
outro produto sem código novo, e que a consola web fecha o ciclo detectar → corrigir → confirmar
sem passar pela linha de comandos. A experiência de determinismo do capítulo 6 (dez configurações,
cem execuções, um digest por configuração) não entra no vídeo — ver §3.

### Regras de edição aplicadas

| Regra | Como se faz |
|---|---|
| Sem áudio | gravar sem microfone e remover a faixa (`-an` no ffmpeg) |
| Legendas curtas | barra superior: número + título da cena + legenda de 3–6 palavras |
| Ritmo controlado | planos de 3 a 17 s; o output entra por blocos, nunca um ecrã inteiro de uma vez |
| Sem zoom | em vez de zoom, enquadrar só a janela de linhas relevante |
| Transições discretas | cortes secos; *fade* de 0,6 s à entrada e 0,8 s à saída |
| Sem cursor nem escrita ao vivo | comandos colados ou corridos por script; o rato fora do quadro |
| 16:9 | 1920×1080 |

---

## 1. Storyboard

`in → out` em segundos a partir do início. A legenda de cena é fixa na barra superior durante
toda a cena. Todos os valores desta grelha foram medidos (ver o anexo).

### Cena 1 — The instrument · legenda `CASPAR 1.0.0` · 0:00–0:25

| # | in → out | No ecrã |
|---|---|---|
| 1 | 0 → 4 | Cartão de abertura: **Configuration Vulnerability Meter**, "Reference implementation: CASPAR" |
| 2 | 4 → 13 | `caspar about` — identificação, versão, base de conhecimento |
| 3 | 13 → 25 | `caspar targets` — os doze alvos, cada um derivado de um CIS Benchmark ou DISA STIG |

### Cena 2 — A real host · legenda `Live service · apache-httpd 2.4.49` · 0:25–1:15

| # | in → out | No ecrã |
|---|---|---|
| 4 | 25 → 28 | Painel vazio com o comando `caspar scan apache2 --live` |
| 5 | 28 → 40 | `ASSESSMENT SUMMARY`: plugin `apache-httpd`, **Mode: live service**, versão detectada, e o painel **8.5 / 10 · HIGH** |
| 6 | 40 → 50 | `Highest finding 8.5 · Highest chain 10.0 · Chains triggered 8 → chains not scored` e a caixa de severidades |
| 7 | 50 → 62 | `TOP FINDINGS`: `User 8.5`, `Group 7.5`, `ServerTokens 6.0`… com `/opt/apache249/conf/httpd.conf:…` e `conf-enabled/99-cvm-demo.conf:…` na coluna de localização |
| 8 | 62 → 75 | `caspar scan apache2 --live --report -f dashboard -o reports` e a linha `Dashboard: …` do ficheiro escrito |

> **Sem `--online`.** O `--online` é outro *renderer* (`report_dashboard_online.py`), com outros
> painéis e **sem** o painel de exploits públicos — que é a batida 14 desta cena. O `-f dashboard`
> clássico é auto-contido (não precisa de rede), tem os separadores Score / C / I / A na tabela
> de issues, os botões *Details* e o painel de exploits. É o estilo dos relatórios de `reports/`.

### Cena 3 — Reading the report · legenda `Every number, explained` · 1:15–2:50

O dashboard aberto no browser. É a cena mais longa do vídeo, e é a que justifica o trabalho:
mostra que o instrumento não devolve um número, devolve a sua derivação.

| # | in → out | No ecrã |
|---|---|---|
| 9 | 75 → 87 | Cabeçalho: `CCSS Dashboard — apache-httpd — 8.5`, `apache-httpd · v2.4.49`, e o aviso `⚠ 7 public exploits` |
| 10 | 87 → 100 | Faixa de indicadores: *Highest Issue*, *Highest Chain*, *Directives*, *Scanned*, *Total Issues*, *Attack Chains*, `CCSS / 7502` |
| 11 | 100 → 112 | *Severity Distribution* — a distribuição por severidade, não só o máximo |
| 12 | 112 → 128 | *Top 10 Issues by Score*: severidade, directiva, valor encontrado, colunas **C / I / A** e **CVEs** |
| 13 | 128 → 145 | **Details** de um finding: a justificação métrica a métrica e o controlo de origem |
| 14 | 145 → 160 | Painel `⚠ Public Exploits for apache-httpd 2.4.49 (7)`, a abrir em `EDB-50383 / CVE-2021-41773 (verified)` — o *path traversal* com execução remota |
| 15 | 160 → 170 | Attack chains com justificação: `load-module-status-userdir` **10.0**, `privilege-escalation` **10.0**, `webdav-rce-chain` 8.5 |

### Cena 4 — Remediate and re-scan · legenda `8.5 → 5.5 → 0.0` · 2:50–4:07

| # | in → out | No ecrã |
|---|---|---|
| 16 | 170 → 175 | Painel vazio com `caspar fix apache2 --live --dry-run` |
| 17 | 175 → 190 | `AUTOMATIC FIXES (29)` — o diff: `- User root` / `+ User apache`, com directiva e score em cada bloco |
| 18 | 190 → 200 | O diff no drop-in e nos módulos: `ServerTokens Full → Prod`, `LoadModule → #LoadModule` |
| 19 | 200 → 210 | `MANUAL STEPS (3)` — as três regras de **ausência** (`Header`), com a razão pela qual não são aplicadas automaticamente |
| 20 | 210 → 218 | `caspar fix apache2 --live --in-place` e `apache2ctl configtest` → `Syntax OK` |
| 21 | 218 → 235 | Re-scan: **5.5 / 10 · MEDIUM**, `Chains triggered 0` |
| 22 | 235 → 247 | As linhas `Header` acrescentadas à mão e o re-scan final: **0.0 / 10 · NONE** |

### Cena 5 — Continuous monitoring · legenda `Watch · score updates live` · 4:07–4:48

| # | in → out | No ecrã |
|---|---|---|
| 23 | 247 → 253 | O mesmo rodapé `reproducible: caspar 1.0.0 · kb sha256:83b3ee01f415` em duas execuções distintas |
| 24 | 253 → 275 | Consola web, página **Watch**: `nginx` seleccionado em *Installed service*, sessão a arrancar em **5.0 / 10 · MEDIUM** (`server_tokens`); corte para `sudo nano /etc/nginx/nginx.conf`, `server_tokens on` → `off`, guardar; corte de volta à consola — **sem reiniciar nada** — a mostrar **0.0 / 10 · NONE** |
| 25 | 275 → 288 | Cartão final: título, `CASPAR 1.0.0`, `sha256:83b3ee01f415`, 514 regras · 32 chains · 12 alvos |

---

## 2. Guião oral (português, ao vivo)

Ritmo de referência: ~135 palavras por minuto. Cada bloco tem folga; se ficares à frente, pára —
o vídeo não precisa de palavra em cima de cada plano.

### Cena 1 · 0:00–0:25

> Isto é o CASPAR, a implementação de referência da metodologia *Configuration Vulnerability
> Meter*. Tudo o que vão ver foi executado em directo nesta máquina.
>
> *(plano 2)* O `about` identifica a ferramenta e a base de conhecimento em uso.
>
> *(plano 3)* O `targets` lista as tecnologias suportadas: doze alvos, cada um derivado de um CIS
> Benchmark ou de um DISA STIG publicado. Hoje seguimos **um** destes, do princípio ao fim — um
> servidor Apache instalado nesta máquina.

### Cena 2 · 0:25–1:15

> *(plano 5)* O comando não recebe um ficheiro: recebe o nome do serviço. O CASPAR localiza a
> árvore de configuração do Apache, segue os `Include`, identifica o produto e a versão, e avalia
> o que está realmente instalado. O resultado é oito vírgula cinco em dez — **High**.
>
> *(plano 6)* Reparem nesta linha, porque é uma decisão de desenho da metodologia: o pior finding
> individual vale 8,5, a pior cadeia de ataque vale 10,0, e o score global é **8,5**. A
> composição é reportada, não é somada. A dissertação é explícita quanto a isto.
>
> *(plano 7)* E cada finding é uma directiva concreta, com um valor concreto, num ficheiro e numa
> linha — `/opt/apache249/conf/httpd.conf`, `conf-enabled`. Não é uma lista de avisos genéricos.
>
> *(plano 8)* O mesmo comando escreve um relatório. É nele que vamos passar o próximo minuto e
> meio.

### Cena 3 · 1:15–2:50

> *(plano 9)* O relatório abre com a mesma avaliação, e com uma informação que o terminal resume:
> esta versão do Apache tem *exploits* públicos conhecidos.
>
> *(plano 10)* Aqui está o que foi medido: quantas directivas foram lidas, quantas foram
> avaliadas, quantos problemas, quantas cadeias. A cobertura é parte do resultado — o instrumento
> declara o que viu e o que não tinha regra para avaliar.
>
> *(plano 11)* A distribuição por severidade importa porque o número único esconde-a: uma
> configuração com um problema grave e outra com vinte problemas médios não são o mesmo risco.
>
> *(plano 12)* Esta é a tabela que faz o trabalho. Por cada problema: a directiva, o valor
> encontrado, a severidade, o impacto em confidencialidade, integridade e disponibilidade, e os
> CVE associados quando existem.
>
> *(plano 13)* E este é o ponto que quero que fique. Ao abrir os detalhes, o instrumento mostra
> **como** chegou ao número: métrica a métrica, porque é que o vector de acesso é a rede, porque
> é que não exige autenticação, qual o impacto, e qual o controlo do benchmark de onde a regra
> veio. Não é uma pontuação opaca — é uma derivação auditável.
>
> *(plano 14)* Aqui estão os *exploits* públicos para esta versão concreta, com identificador e
> estado de verificação. É esta evidência que move o score temporal acima do score base, segundo
> o modelo da norma.
>
> *(plano 15)* E as cadeias de ataque. Duas delas são **críticas**, valem dez: o módulo de status
> carregado em conjunto com o Apache a correr como root, e a escalada de privilégios entre o
> utilizador e o grupo. Nenhum destes problemas, isolado, é crítico. Juntos, são. É exactamente
> isto que um verificador que só olha para directivas uma a uma não vê — e é por isso que a
> cadeia é reportada, com justificação, mesmo não entrando no score.

### Cena 4 · 2:50–4:07

> *(plano 16)* Detectar sem corrigir não serve de muito. O `fix` gera a correcção a partir das
> mesmas regras que produziram a avaliação, e em modo de ensaio mostra só o diff.
>
> *(plano 17)* Vinte e três correcções automáticas. Cada bloco diz que directiva muda, de que
> valor para que valor, e quanto valia o problema que resolve.
>
> *(plano 19)* E três passos **manuais**, com a razão: são regras de ausência — cabeçalhos de
> segurança que não existem no ficheiro. O instrumento não inventa linhas que não estavam lá; diz
> o que falta e deixa a decisão a quem administra.
>
> *(plano 20)* Aplicamos, e validamos a sintaxe com a própria ferramenta do Apache.
>
> *(plano 21)* Re-scan: de 8,5 para **5,5**, e, mais importante do que o número, **zero cadeias
> de ataque**. A correcção automática quebrou todas.
>
> *(plano 22)* Acrescentando à mão os cabeçalhos que faltavam — os passos manuais que o relatório
> listou —, o mesmo servidor, o mesmo comando: **zero**. O instrumento desce quando a
> configuração melhora, e isto é a mesma máquina, não um segundo ficheiro preparado.

### Cena 5 · 4:07–4:48

> *(plano 23)* Todos os relatórios transportam a versão da ferramenta e um digest SHA-256 da base
> de conhecimento. Duas execuções, o mesmo rodapé: qualquer resultado pode ser reatado à base
> exacta que o produziu.
>
> *(plano 24)* Até aqui, tudo pela linha de comandos. A consola web fala com o mesmo motor —
> nenhuma lógica nova — e tem uma página que avalia continuamente: aqui está o nginx **instalado
> nesta máquina**, não um ficheiro preparado, a ausentar-se da versão em cada resposta HTTP. Cinco
> em dez. Vou corrigir uma linha na configuração real, fora da consola... e pronto. Sem recarregar
> a página, sem reiniciar sessão nenhuma: a consola voltou a ler o ficheiro e o score caiu para
> zero. É o mesmo ciclo detectar-corrigir-confirmar da cena 4, agora contínuo e visível em tempo
> real.
>
> *(plano 25)* Fica no ecrã a versão e o digest. Obrigado.

---

## 3. Anexo — verificação da grelha

Medido a 2026-11-15 em `/home/albertojf/caspar`, `ccss.db` `sha256:83b3ee01f415`, CASPAR 1.0.0.
A árvore do Apache foi replicada com a mesma estrutura de uma instalação Ubuntu (`apache2.conf`
+ `mods-enabled/*.load` + `conf-enabled/*.conf`, percorrida pelos `Include`), com a configuração
que o [`assets/demo-apache/vulneravel-249.sh`](../assets/demo-apache/vulneravel-249.sh) aplica sobre
o Apache 2.4.49 compilado por [`instalar-2.4.49.sh`](../assets/demo-apache/instalar-2.4.49.sh).

| Afirmação do vídeo | Resultado medido |
|---|---|
| Score da configuração vulnerável | **8.5 / 10 · HIGH** |
| Pior finding individual | `User root` **8.5** (base 9.4 na base de dados) |
| Pior cadeia | **10.0**, `load-module-status-userdir` e `privilege-escalation` |
| Cadeias disparadas | **8** |
| Severidades | 0 Critical · 2 High · 19 Medium · 2 Low |
| Correcções automáticas | **23** |
| Passos manuais | **3**, todos regras de ausência (`Header`) |
| Score depois do `fix` | **5.5 / 10 · MEDIUM**, `Chains triggered 0` |
| Score depois dos passos manuais | **0.0 / 10 · NONE** |
| Exploits públicos na versão | 7 para `apache-httpd 2.4.49` (81 CVEs, 3 em KEV, CVSS máx. 9.8); o primeiro é `EDB-50383 / CVE-2021-41773 (verified)`. Nota de risco no detalhe: `Apache 2.4.49 — 3 KEV-listed CVEs detected` |
| Determinismo (fora do vídeo, Cap. 6) | `total runs: 100`, `distinct digests per configuration: 1` |

**O tecto do apache é 8.5 — não há CRITICAL no score global, e isso é correcto.** A regra de topo
do apache na base de conhecimento é `User root`, com base 9.4 e temporal 8.5; a amplificação por
exposição de versão só se aplica a findings que revelam a versão (`ServerTokens`, 4.0 → 6.0), e
**O painel de *exploits* (plano 14) depende da versão detectada.** A base canónica traz linhas
`version_exploits` pré-resolvidas (CVEs do NVD + registos do Exploit-DB) para seis versões do
`apache-httpd` — 2.2.31, 2.2.34, 2.4.49, 2.4.50, 2.4.58 e 2.4.66 — e a procura é por versão
**exacta**. Com uma dessas versões o caminho é totalmente offline e determinístico; com qualquer
outra (a 2.4.52 do Ubuntu 22.04, por exemplo) o scan ainda consulta o NVD ao vivo pelos CVEs, mas
os *exploits* exigiriam um clone local do Exploit-DB, pelo que o painel não é desenhado. O plano 9
O guião resolve isto instalando genuinamente a **2.4.49** na VM, compilada a partir do código-fonte
verificado por SHA-256 (`assets/demo-apache/instalar-2.4.49.sh`). Nenhum comando leva
`--service-version`: o `apache2 -v` da máquina diz 2.4.49, o relatório diz 2.4.49, e o painel é
resolvido a partir da base, offline. A alternativa — fixar a versão por flag — foi descartada por
mostrar `Service: apache-httpd 2.4.52` no cabeçalho e `v2.4.49` no relatório, contradição em quadro.

A árvore da build de origem foi medida e dá **o mesmo arco** da árvore Debian: 8.5 HIGH, 23 achados
(0 CRITICAL / 2 HIGH / 19 MEDIUM / 2 LOW), 8 chains com a pior a 10.0; depois do `fix`, 5.5 MEDIUM
com `Chains triggered 0`; e 0.0 NONE depois das cinco linhas `Header`. A única diferença é a
contagem de correcções automáticas — **27**, não 23, porque o `httpd.conf` de origem tem mais
ocorrências de `Options` e `AllowOverride` do que o `apache2.conf` do Debian.

nenhum deles chega aos 9.0. Verificado com `--service-version` vazio, `2.4.58`, `2.4.49` e
`2.2.34`: **8.5 em todos**. O **CRITICAL** aparece onde a metodologia diz que tem de aparecer —
nas duas cadeias de 10.0 — e a cena 2 usa precisamente essa diferença como argumento. Se fosse
preciso um score global crítico, teria de ser outro alvo (kubernetes 10.0, mysql 9.4,
dockerfile 9.0), o que custaria o arco de alvo único.

**Fora do vídeo, para a defesa:** fidelidade (20/20 e 17/20), detecção (96/96, 0 falsos
positivos), estabilidade do *build* (29/30), posicionamento face ao Trivy, e os dois números de
desempenho (44,5 s/controlo; 14–158 ms). Sobre estes últimos, nota que o instrumento que produziu
os 14–158 ms não está no repositório: o que está é o `scripts/perf_scan.py`, que mede o relógio
de parede de um subprocesso novo e dá 0,130 s (WSL2) / 0,100 s (VM nativa), publicados no
[06_VALIDACAO.md](06_VALIDACAO.md) §4.1. A diferença é o arranque do interpretador e a abertura
do SQLite.

### Verificação da cena 5 — nginx real

Medido a 2026-11-15, nginx 1.24.0 instalado na VM via `apt`, a correr fora de qualquer contentor.
O CASPAR avalia-o montando `/etc/nginx` do anfitrião, só de leitura, no contentor de
demonstração (`install.sh`, commit `2b9c9fb`) — a avaliação nunca escreve na configuração real.

Antes de gravar, a configuração do nginx já tem os quatro cabeçalhos de segurança (CSP, HSTS,
X-Content-Type-Options, Referrer-Policy) e mantém `ssl_protocols TLSv1.3`, que já traz de fábrica.
A única directiva deliberadamente errada é `server_tokens on` — é essa, e só essa, que se corrige
em câmara.

| Afirmação do plano 24 | Resultado medido |
|---|---|
| Score antes da correcção | **5.0 / 10 · MEDIUM**, 1 finding (`server_tokens`) |
| Score depois da correcção (`server_tokens off`) | **0.0 / 10 · NONE** |
| Cadeia disparada antes da correcção | `server-info-to-tls-downgrade` **7.0** (não entra no score global) |

**Nota para a defesa:** a cadeia `server-info-to-tls-downgrade` dispara por `server_tokens` e
`ssl_protocols` estarem ambos **presentes** no ficheiro — a condição 1 do motor de cadeias
(`attack_chain.py:detect_chains`) exige a presença de todas as directivas da cadeia, não que todas
sejam más. A condição 2 exige só que pelo menos uma seja de facto um finding. Aqui `ssl_protocols
TLSv1.3` é um valor **bom**; é `server_tokens on` que é o finding, e é ele que arma a cadeia. Não é
um erro: é a regra documentada do motor, e vale a pena a saber de antemão se for perguntado.

**Porque nenhuma outra directiva entra em jogo.** As regras de valor do nginx (`ssl_protocols`,
`send_timeout`, `client_max_body_size`, `keepalive_timeout`, `ssl_session_tickets`, `proxy_pass`…)
só disparam se a directiva estiver **presente com um valor mau** — ausência não é falha, ao
contrário das quatro regras de `add_header`, que são de ausência e disparam sempre que o cabeçalho
não existe. Por isso a preparação da cena exige os quatro cabeçalhos escritos antes de gravar: sem
eles, o score de partida seria sempre 5.5 (o `Content-Security-Policy` em falta), e corrigir só o
`server_tokens` não moveria o número no ecrã.

**Pendente, fora do vídeo:** o `README.md` §12 ainda anuncia 488 regras / 27 chains / 647 testes.
A base e a dissertação dizem **514 / 32 / 12**.
