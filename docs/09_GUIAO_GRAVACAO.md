# Guião de gravação de ecrã (vídeo-anexo, gravado por ti)

Complementa [08_ROTEIRO_VIDEO.md](08_ROTEIRO_VIDEO.md): as **cinco** cenas, as legendas inglesas
e o guião oral em português são os mesmos (~4:50 de alvo). O alvo da demonstração é **um só**: um
Apache instalado numa VM, com uma configuração deliberadamente vulnerável. Este documento trata só da **gravação ao vivo numa
máquina**: como a preparar, o que escrever, por que ordem, e o que não pode aparecer no ecrã.

---

## 0. Gravar com `pip install cvm-caspar`

O pacote publicado passou a ser o que a dissertação descreve. Estado em 2026-11-15:

| | `cvm-caspar` **1.0.0** (publicada) | 1.1.1 (anterior) | Dissertação |
|---|---|---|---|
| kubernetes, mysql, dockerfile, azure-iac, ssh, nginx, ubuntu, redis, tomcat | iguais | iguais | iguais |
| **apache-httpd** | **8.5** | 8.7 | **8.5** |
| endurecidos (todos) | 0.0 | 0.0 | 0.0 |
| `kb sha256` | **`83b3ee01f415`** | `f595efe56da0` | `83b3ee01f415` |
| `verificar.sh` | **16 ok, 0 falhas** | 15 ok, 1 falha | — |

A divergência do `httpd` vinha do commit `ec42921` — *fix(ccss): align GEL/GRL coefficients with
NISTIR 7502 §3.2.2* —, que existia só no repositório `caspar` e não no `cvm`, de onde sai o PyPI.
Está portado (`cvm`, commit `eb1e1ce`, suíte 1172 passed / 23 skipped), o dump canónico foi
regenerado com os 104 `temporal_score` afectados recalculados — é isso que faz o digest voltar a
ser o que a dissertação cita — e `base_db_version` subiu 4 → 5 para a correcção chegar a volumes
Docker já existentes. A versão publicada é **1.0.0**, o número que a dissertação documenta;
1.1.0 e 1.1.1 ficam *yanked* no PyPI (continuam disponíveis para quem as tenha fixadas, mas o pip
deixa de as escolher).

Verificado a partir do PyPI numa venv limpa: `pip install cvm-caspar` → `caspar 1.0.0` →
`caspar init` → 16 ok, 0 falhas.

Funciona de origem: o wheel traz a base de conhecimento canónica (`caspar init`, menos de um
segundo) e as consolas web. **Não** é preciso o `ccss.db` de 595 MB desta máquina — esse é grande
por causa do histórico de scans, não do conhecimento.

### O que o pip não traz, e o kit que resolve isso

O wheel leva o pacote; não leva o **corpus experimental** (`test_target/`, os dez pares) nem o
directório `scripts/`. Para reproduzir as medições está preparado
[`assets/reproducao/kit-reproducao.tar.gz`](../assets/reproducao/kit-reproducao.tar.gz) (11 KB), com:

* `test_target/` — os dez pares vulnerável/endurecido, idênticos aos do repositório;
* `verificar.sh` — a verificação dos dez pares contra os valores publicados;
* `determinismo.py` — versão autónoma de `scripts/determinism_scan.py` (mesma medição, sem
  depender do repositório), que é o que a cena 5 precisa;
* `LEIA-ME.md` — os comandos na ordem certa.

O corpus também viaja no *sdist* publicado, pelo que o kit é uma conveniência, não a única via.

### Nota de proveniência, para a defesa

O terminal gravado vai dizer `caspar 1.0.0 · kb sha256:83b3ee01f415` — o mesmo número e o mesmo
digest que a dissertação documenta. Os cartões do vídeo deixaram de mostrar número de versão e
mostram o digest, que é a identidade que não muda entre empacotamentos: é ele, e não o número,
que atesta que os resultados são comparáveis.

---

## 1. Preparar a máquina

O guião é para gravar em **qualquer** máquina — incluindo uma nova, sem nada deste repositório.
A via normal é uma linha:

```bash
curl -fsSL https://raw.githubusercontent.com/AFilipe-IT/cvm/master/scripts/reproducao/preparar.sh | bash
```

Corre `scripts/reproducao/preparar.sh` do repositório `cvm`: cria `~/cvm-reproducao` (ou o directório
passado como argumento), monta o venv, instala `cvm-caspar[api]==1.0.0`, extrai o corpus do
*sdist* publicado, busca `determinismo.py` e `verificar.sh`, corre o `caspar init`, corre
o pré-voo e, no fim, **aborta se o digest não for `83b3ee01f415`**. Não usa `sudo` nem escreve
fora do directório de trabalho; só precisa de Python ≥ 3.10 com o módulo `venv`, e de `curl` ou
`wget`. Verificado numa máquina limpa: termina em **16 ok, 0 falhas**.

A versão é fixada em `==1.0.0` de propósito: assim a instalação não depende do índice do PyPI em
cache na máquina. O extra `[api]` traz o uvicorn do `caspar serve`, que já não entra no vídeo mas
continua a ser a via de quem quiser abrir a consola.

Em câmara ficam duas linhas: `caspar --version` (tomada 1.2) e `caspar init` (514 regras, 32
chains, 12 alvos, em menos de um segundo). O `preparar.sh` já corre o `init`; para a tomada,
apaga o `ccss.db` e volta a correr o comando em quadro.

### A VM do apache — o que a demonstração precisa

As cenas 2 a 4 avaliam um serviço instalado, não um ficheiro do corpus. Numa VM descartável
(Ubuntu 22.04 serve), **sem exposição à rede** e com **snapshot feito antes**:

```bash
sudo bash assets/demo-apache/instalar-2.4.49.sh   # compila o Apache 2.4.49 em /opt/apache249
sudo useradd -r -s /usr/sbin/nologin apache       # o valor seguro da base é 'User apache'
sudo bash assets/demo-apache/vulneravel-249.sh    # aplica a configuração vulnerável
caspar scan apache2 --live                        # pré-voo: 2.4.49 · 8.5 / 10 HIGH · 7 exploits
sudo bash assets/demo-apache/restaurar-249.sh     # desfaz, no fim
```

### Porque é que a versão tem de ser a 2.4.49

A base canónica traz linhas de exploitabilidade **pré-resolvidas** (CVEs do NVD + registos do
Exploit-DB) para seis versões do `apache-httpd` — `2.2.31`, `2.2.34`, `2.4.49`, `2.4.50`, `2.4.58`
e `2.4.66` — e a correspondência é por versão **exacta**. O Apache do Ubuntu 22.04 é o `2.4.52`,
que não tem linha: o scan cai no NVD ao vivo, obtém os CVEs mas não os *exploits* (isso exigiria
um clone local do Exploit-DB), e o painel da batida 3.6 não é desenhado.

A `2.4.49` tem a linha mais forte da base: **81 CVEs, 3 em KEV, CVSS máx. 9.8 e 7 exploits
públicos**, a começar no `EDB-50383 / CVE-2021-41773` — *path traversal* com execução remota,
verificado. Como a versão passa a ser **genuinamente a instalada**, nenhum comando do guião leva
`--service-version`: o `apache2 -v` da máquina diz 2.4.49 e o relatório diz 2.4.49. Era essa a
alternativa que se descartou — fixar a versão por flag mostrava `Service: apache-httpd 2.4.52` no
cabeçalho e `v2.4.49` no relatório, uma contradição em quadro.

O [`instalar-2.4.49.sh`](../assets/demo-apache/instalar-2.4.49.sh) descarrega o *tarball* de
`archive.apache.org`, **confere o SHA-256** (o ficheiro publicado refere o nome da candidata,
`httpd-2.4.49-rc1.tar.gz`, pelo que se compara o valor, não o nome), compila com
`--prefix=/opt/apache249`, e cria dois *links* em `/usr/local/bin` — `apache2` e `apache2ctl`.
São eles que decidem a detecção: o resolver procura `apache2` no PATH e deduz a configuração de
`apache2ctl -V` (`HTTPD_ROOT` + `SERVER_CONFIG_FILE`); `/usr/local/bin` vem antes de `/usr/sbin`,
pelo que a build de origem responde primeiro. O serviço `apache2` do sistema é parado e
desactivado, e o binário da 2.4.49 **nunca é arrancado**.

O [`vulneravel-249.sh`](../assets/demo-apache/vulneravel-249.sh) monta, dentro de
`/opt/apache249/conf`, a mesma estrutura de inclusões do Debian — `mods-enabled/*.load` e
`conf-enabled/*.conf` —, activa os módulos que a base pontua (`dav`, `dav_fs`, `status`, `info`,
`userdir`, `autoindex`), põe `User root` e `Group root`, alinha os blocos `<Directory>` do
`httpd.conf` de origem com o resto da configuração, e escreve um único drop-in identificável,
`conf-enabled/99-cvm-demo.conf`. Não arranca o serviço — **não é preciso**: o scan lê a árvore de
configuração, segue os `Include` e avalia o que está escrito em disco.

Quatro avisos que valem uma tomada repetida:

- **A 2.4.49 tem um RCE conhecido** (`CVE-2021-41773`). O serviço não é arrancado em nenhum plano
  do vídeo e não deve ser. VM descartável, sem porta aberta, snapshot antes.
- **O `useradd apache` antes da cena 4.** O valor seguro que a base de conhecimento tem para
  `User` é `apache`, não o `www-data` do Debian. Sem o utilizador existir, o `apachectl
  configtest` do plano 20 reclama em quadro.
- **A compilação demora.** Faz o `instalar-2.4.49.sh` muito antes da gravação, e confirma o
  pré-voo; não é coisa para fazer com a câmara a andar.
- **O `restaurar-249.sh` apaga `/opt/apache249` e os dois *links*.** Se algo ficar inconsistente,
  repõe o snapshot — não tentes desfazer à mão. Com um `PREFIX` dado por ti (ver abaixo) a árvore
  **não** é apagada: desfazem-se só os *links* e o que a demonstração acrescentou à configuração.

### Se a 2.4.49 já estiver compilada

Quem já tenha uma build de origem noutro sítio não precisa de recompilar: os três *scripts* aceitam
o prefixo em `PREFIX`. Com uma build em `/usr/local/apache-2.4.49`, por exemplo:

```bash
sudo ln -sf /usr/local/apache-2.4.49/bin/httpd     /usr/local/bin/apache2
sudo ln -sf /usr/local/apache-2.4.49/bin/apachectl /usr/local/bin/apache2ctl
hash -r
apache2ctl -V | grep -E 'HTTPD_ROOT|SERVER_CONFIG_FILE'   # tem de apontar para essa árvore
sudo PREFIX=/usr/local/apache-2.4.49 bash assets/demo-apache/vulneravel-249.sh
```

Os **dois** *links* são indispensáveis, e é o segundo que costuma faltar. O resolver tira a versão
do `apache2 -v` e a configuração do `apache2ctl -V`: com só o primeiro trocado, o relatório diz
`v2.4.49` — a versão certa — mas lê a árvore do `/etc/apache2` do Debian, e o score que sai é o
dessa árvore, não o da demonstração. É uma falha silenciosa: nada no relatório avisa que as duas
metades vêm de instalações diferentes. O `apache2ctl -V` acima é a verificação que a apanha.

### Se o venv já existir

O script não reinstala nada num venv que já esteja montado. Depois de qualquer correcção aos
scripts, o mais limpo é `rm -rf ~/cvm-reproducao` e correr a linha outra vez.

### Variante: na máquina que tem os repositórios

Neste PC os ficheiros que o pip não traz já estão em disco, e dispensa-se a rede:

```bash
mkdir -p ~/cvm-reproducao && cd ~/cvm-reproducao
cp -r ~/cvm/test_target ~/cvm/scripts/reproducao/determinismo.py ~/cvm/scripts/reproducao/verificar.sh .
python3 -m venv .venv && source .venv/bin/activate
pip install "cvm-caspar[api]"
caspar init
```

### Variante: máquina sem rede

[`assets/reproducao/kit-reproducao.tar.gz`](../assets/reproducao/kit-reproducao.tar.gz) (11 KB) leva o corpus e
os dois scripts; `tar xzf kit-reproducao.tar.gz --strip-components=1` em vez da linha do `cp`. Nesse
caso o pacote tem de vir de outra forma — um wheel copiado à mão, ou `pip install` com um índice
local.

Tudo a partir **deste** directório: é o que põe `test_target/` e `ccss.db` nos caminhos relativos
que os comandos das cenas usam, e o que dispensa `export CASPAR_DB` — o valor por omissão do
`--db` já é `./ccss.db`. Não é preciso nenhuma base de dados desta máquina: o `caspar init`
materializa a canónica a partir do próprio wheel, e é essa que dá o digest `83b3ee01f415`.

### Porque é que não há mais passos

Linhas que estiveram aqui e saíram, com a razão:

| Linha | Porque saiu |
|---|---|
| `apt-get install … sqlite3` | nada na gravação usa o `sqlite3`; era herança da via "repositório", que semeava a base à mão |
| `pip install --upgrade pip` | o `ResolutionTooDeep` do Ubuntu 22.04 dava-se a instalar o repositório com os extras `[dev]`; o wheel publicado tem três dependências (`pydantic`, `click`, `pyyaml`). Não foi possível reproduzir aqui o par pip-antigo + Python 3.10 do 22.04 — se o `pip install` demorar mais do que uns segundos, interrompe e faz o upgrade |
| `export CASPAR_DB=$PWD/ccss.db` | desnecessário correndo tudo neste directório |
| `caspar demo` | existe no pacote, mas escreve só quatro ficheiros (apache e nginx), não os dez pares da dissertação — não substitui o corpus |

O que **não** pode sair: o venv. Sem ele, em Ubuntu 23.04+ o pip recusa-se a instalar no Python
do sistema (PEP 668) e em 22.04 o `caspar` vai parar a `~/.local/bin`, que pode não estar no
`PATH`.

> `pip install cvm-caspar`, sem mais nada, dá 1.0.0. O índice do PyPI é servido com
> `max-age=600`, por isso uma máquina que tenha instalado o pacote nos dez minutos anteriores
> pode ainda servir a lista antiga — passado esse tempo revalida sozinha. O pré-voo do §2 apanha
> o caso; se tiveres pressa, `pip install --no-cache-dir cvm-caspar`.

### Opções globais vêm antes do subcomando

`caspar --db X scan f.conf` funciona; `caspar scan f.conf --db X` é silenciosamente outra coisa.
Correndo no directório da base, não escreves `--db` nenhuma vez em frente à câmara.

### Ficheiro que precisa de nome canónico

```bash
mkdir -p ~/demo/ssh_hardened && cp test_target/ssh_demo/sshd_config_hardened ~/demo/ssh_hardened/sshd_config
```

A detecção do plugin ssh exige o nome `sshd_config`; com o sufixo `_hardened` o ficheiro não é
reconhecido e o par não fecha em 0.0.

---

## 2. Pré-voo — correr antes de gravar

```bash
bash verificar.sh caspar
```

Confirma os dez pares, as contrapartes a 0.0, a linha de agregação de pior caso e o manifesto.
O par do nginx é verificado com `--service-version 1.24.0`, para que o resultado não dependa de
haver nginx instalado na máquina (ver a nota da cena 3).
Com 1.0.0 saem **16 ok, 0 falhas** e a última linha é
`reproducible: caspar 1.0.0 · kb sha256:83b3ee01f415 · 18 rules (nginx)`. Se saírem **15 ok, 1
falha (httpd 8.7)**, estás numa 1.1.x — reinstala. Qualquer outra falha: **não graves**, alguma
coisa na base ou no corpus está diferente.

> Se gravares a partir do repositório em vez do pip, o mesmo script aceita o comando alternativo:
> `bash assets/reproducao/verificar.sh ".venv/bin/python -m cli.main"`.

E, para as cenas 2 a 4, o pré-voo do alvo da demonstração:

```bash
caspar scan apache2 --live
```

Esperado: **8.5 / 10 · HIGH**, `Highest finding 8.5` (`User`), `Highest chain 10.0`,
`Chains triggered 8`, 0 Critical · 2 High · 19 Medium · 2 Low. Se o score não for 8.5, o
`vulneravel-249.sh` não foi aplicado ou a build de origem não é a que responde ao PATH — **não
graves**, confirma primeiro.

---

## 3. Técnica de gravação

| Item | Valor |
|---|---|
| Resolução | 1920×1080, gravar o ecrã inteiro ou uma janela fixa de 16:9 — nunca redimensionar a meio |
| Terminal | tema claro, fonte mono ≥ 16 pt, **100 colunas** (`COLUMNS=100`), janela sem abas nem título com caminhos pessoais |
| Prompt | reduzir a `$ ` (ex.: `PS1='$ '`) — um prompt com utilizador@máquina e caminho rouba meia linha e identifica a máquina |
| Rato | fora do enquadramento; nada se faz com o cursor |
| Escrita | **não escrevas ao vivo**: cola cada comando ou usa um script com pausas; erros de escrita obrigam a repetir a tomada |
| Áudio | grava sem microfone. O ficheiro final não leva faixa de áudio |
| Limpeza | `clear` entre tomadas, e corta-o na montagem |

Na via pip o `caspar` já é um binário no PATH da venv: não é preciso alias nenhum em frente à
câmara.

### O que não pode aparecer

1. **O `caspar watch`**, que o bloco `NEXT STEPS` sugere no fim do scan ao lado do `fix`. O
   `fix` entra no vídeo (cena 4); o `watch` não está na dissertação de todo — não o deixes em
   quadro. Corta o scroll antes da linha, ou corta na edição.
2. Caminhos com dados pessoais no cabeçalho do relatório, se a VM não for a tua. O dashboard
   escreve o caminho completo da configuração avaliada — em `--live` é `/opt/apache249/conf/...`, que é
   neutro, mas confirma o cabeçalho antes de gravar.
3. Qualquer `--db` escrito à mão (ver §1).

---

## 4. Lista de tomadas

Uma tomada = um comando. Grava cada uma isolada, com três segundos de margem antes e depois: na
montagem cortas o excesso. Os tempos são os da grelha do
[08_ROTEIRO_VIDEO.md](08_ROTEIRO_VIDEO.md) §1 — serve-te deles como alvo, não como obrigação.

**São cinco cenas e um alvo só.** O vídeo já renderizado tem oito cenas e dez alvos; é outro
corte. Todos os valores abaixo foram medidos — estão na tabela do §3 do roteiro.

### Cena 1 — The instrument (~25 s)

| # | Comando | Mostrar | Duração |
|---|---|---|---|
| 1.1 | *(cartão de abertura)* | título, sem número de versão | 4 s |
| 1.2 | `caspar about` | identidade, versão, base de conhecimento | 9 s |
| 1.3 | `caspar targets` | os 12 alvos e o benchmark de origem de cada um | 12 s |

> Em `targets`, a última linha diz que há 1 plugin sem regras nesta base. Não é um problema — mas
> se não quiseres explicá-lo em directo, corta a tomada antes dessa linha.

### Cena 2 — A real host (~50 s)

| # | Comando | Mostrar | Duração |
|---|---|---|---|
| 2.1 | `caspar scan apache2 --live` | `ASSESSMENT SUMMARY`, `Service: apache-httpd 2.4.49`, `Mode: live service`, **8.5 / 10 HIGH** | 12 s |
| 2.2 | *(mesmo output)* | `Highest finding 8.5 · Highest chain 10.0 · Chains triggered 8` + caixa de severidades | 10 s |
| 2.3 | *(mesmo output, scroll)* | `TOP FINDINGS` com `/opt/apache249/conf/...` e `conf-enabled/99-cvm-demo.conf:…` na coluna de localização | 12 s |
| 2.4 | `caspar scan apache2 --live --report -f dashboard -o reports` | a linha `Dashboard: …` | 13 s |

> **Não uses `--online`.** Não é o mesmo dashboard com gráficos melhores: é outro *renderer*,
> com painéis diferentes (*Aggregate Impact*, *Score vs Exploitability*) e **sem o painel de
> exploits públicos**, que é a batida 3.6. O `-f dashboard` clássico é o estilo dos relatórios
> que já estão em `reports/`, é auto-contido e não precisa de rede.
>
> O `-o reports` não é opcional numa instalação por pip: sem ele o ficheiro vai para dentro do
> `site-packages` do venv, e o caminho que aparece em quadro é impróprio.

### Cena 3 — Reading the report (~95 s)  ·  `-f dashboard`, nunca `--online`

Browser, não terminal. Abre o ficheiro **antes** de gravar e grava só a navegação; o diálogo de
abertura de ficheiros não é material de vídeo. Rola devagar: esta é a cena que o júri vai querer
ver duas vezes.

| # | Onde | Mostrar | Duração |
|---|---|---|---|
| 3.1 | topo | `CCSS Dashboard — apache-httpd — 8.5`, `apache-httpd · v2.4.49`, badge `⚠ 7 public exploits` | 12 s |
| 3.2 | faixa de indicadores | *Highest Issue*, *Highest Chain*, *Directives*, *Scanned*, *Total Issues*, *Attack Chains* | 13 s |
| 3.3 | *Severity Distribution* | a distribuição, não só o máximo | 12 s |
| 3.4 | *Top 10 Issues by Score* | directiva, valor, severidade, colunas C/I/A, CVEs | 16 s |
| 3.5 | botão **Details** de um finding | a justificação métrica a métrica e o controlo de origem | 17 s |
| 3.6 | painel de exploits | `⚠ Public Exploits for apache-httpd 2.4.49 (7)`; pára em `EDB-50383 / CVE-2021-41773 ✓` e desce a lista | 15 s |
| 3.7 | attack chains | `load-module-status-userdir` 10.0, `privilege-escalation` 10.0, com justificação | 10 s |

### Cena 4 — Remediate and re-scan (~77 s)

| # | Comando | Mostrar | Duração |
|---|---|---|---|
| 4.1 | `caspar fix apache2 --live --dry-run` | `AUTOMATIC FIXES (23)`, `- User root` / `+ User apache` | 15 s |
| 4.2 | *(mesmo output, scroll)* | o diff no drop-in e nos módulos (`LoadModule` → `#LoadModule`) | 10 s |
| 4.3 | *(mesmo output, fim)* | `MANUAL STEPS (3)` — as regras de ausência `Header`, com a razão | 10 s |
| 4.4 | `sudo caspar fix apache2 --live --in-place` e `apache2ctl configtest` | `Syntax OK` | 8 s |
| 4.5 | `caspar scan apache2 --live` | **5.5 MEDIUM**, `Chains triggered 0` | 17 s |
| 4.6 | acrescentar as linhas `Header` e repetir o scan | **0.0 NONE** | 12 s |

As cinco linhas que fecham o par em 0.0 (as três dos passos manuais mais duas de cabeçalhos que a
base também pontua por ausência), para colar no drop-in:

```apache
Header always append Content-Security-Policy "frame-ancestors 'self'"
Header set Referrer-Policy "strict-origin-when-cross-origin"
Header set Permissions-Policy "geolocation=(), microphone=(), camera=()"
Header always set Strict-Transport-Security "max-age=63072000; includeSubDomains; preload"
Header always set X-Content-Type-Options "nosniff"
```

> **O `fix --in-place` escreve em `/opt/apache249/conf`.** Snapshot feito, `useradd apache` feito (ver
> §1), e o `configtest` em quadro não é decoração: se a sintaxe quebrar, queres isso resolvido em
> quadro e não cortado.
>
> Variante segura, se não quiseres escrever no `/etc`: `caspar fix apache2 --live -o /tmp/apache2-fixed`
> e faz o re-scan sobre esse directório. Perde-se o "live" nos planos 4.5 e 4.6; ganha-se não
> tocar na máquina.

### Cena 5 — Reproducibility (~41 s)

| # | Comando | Mostrar | Duração |
|---|---|---|---|
| 5.1 | `caspar scan apache2 --live \| tail -2` (duas vezes) | o mesmo rodapé `reproducible:` | 10 s |
| 5.2 | `cp ccss.db ccss_alt.db` e `python determinismo.py --runs 10 --db ccss.db --alt-db ccss_alt.db` | `total runs: 100` · `distinct digests per configuration: 1` | 18 s |
| 5.3 | *(cartão final)* | título, `CASPAR 1.0.0`, `sha256:83b3ee01f415`, 514 regras · 32 chains · 12 alvos | 13 s |

A experiência corre em ~1,7 s; a tomada é longa porque o output fica em quadro a ser lido. O
`determinismo.py` corre sobre as dez configurações do corpus — é a única altura em que o corpus
aparece, e chega.

---

## 5. Montagem

- Cortes secos entre tomadas; *fade in* 0,6 s no início e *fade out* 0,8 s no fim.
- Sem faixa de áudio — não "silêncio gravado": remove a faixa (`-an` no ffmpeg).
- Legendas inglesas curtas, as da tabela de cada cena em [08_ROTEIRO_VIDEO.md](08_ROTEIRO_VIDEO.md).
- Os cartões (1.1 e 5.3) mostram o **digest**, não o número de versão: é o digest que atesta que
  os resultados são comparáveis. O terminal gravado diz `caspar 1.0.0`; não há contradição.
- Alvo de **~4:50** (288 s). Se passar dos 5:15, corta primeiro em 3.3 e 2.2. O que não se corta
  é o 3.5 (os *Details*) nem o 4.5 — são os dois planos que carregam o argumento.

```bash
ffmpeg -y -f concat -safe 0 -i list.txt -t 288 \
  -vf "fps=30,format=yuv420p,fade=t=in:st=0:d=0.6,fade=t=out:st=287.2:d=0.8" \
  -c:v libx264 -preset slow -crf 18 -movflags +faststart -an video.mp4
```

---

## 6. Plano B

| Falha | Resposta |
|---|---|
| O score ao vivo não é 8.5 | pára e corre o pré-voo (§2); confirma que o `vulneravel-249.sh` foi aplicado. Não "arredondes" na narração |
| Diz `v2.4.49` mas os achados citam `/etc/apache2/...` | só o *link* do `apache2` está trocado; falta o do `apache2ctl`. Confirma com `apache2ctl -V \| grep SERVER_CONFIG_FILE` |
| O `configtest` falha depois do `fix` | quase sempre é o utilizador `apache` que não existe: `sudo useradd -r -s /usr/sbin/nologin apache` e repete |
| O Apache não arranca depois do `fix` | é indiferente para a demonstração — o scan lê ficheiros, não o processo, e esta versão não deve ser arrancada |
| O dashboard não tem o painel de exploits | duas causas: geraste-o com `--online` (repete com `-f dashboard`), ou a versão detectada não é a 2.4.49 — corre `apache2 -v` e confirma os *links* de `/usr/local/bin` (ver §1) |
| O `determinismo.py` não corre | confirma que estás na raiz do kit e que o `ccss_alt.db` foi copiado; sem o `--alt-db` só provas metade |
| Falta de tempo | corta 3.3 e 2.2 |
| A VM ficou inconsistente | `restaurar-249.sh`; se não chegar, repõe o snapshot |

---

## 7. Antes de publicar o anexo

- `README.md` §12 ainda diz 488 regras / 27 chains / 647 testes; a base e a dissertação dizem
  **514 / 32 / 12**. Se o README aparecer em quadro, ou se o júri o abrir, a discrepância nota-se.
- `data/ccss_canonical.sql` deste repo também é a base antiga (488/27/11).
- `ec42921` continua por fazer *push* no repositório `caspar` (`master` está `ahead 1`). No
  repositório `cvm` já está portado (commit `eb1e1ce`), também sem *push*.
- **Yank de 1.1.0 e 1.1.1 no PyPI** (pypi.org → cvm-caspar → Manage → Releases → Options →
  Yank). Sem isso, `pip install cvm-caspar` sem versão fixada ainda serve a 1.1.1, que dá
  `httpd 8.7` — e a demonstração do apache deixa de bater com a dissertação.
- Nada em `assets/` está comprometido no git.
