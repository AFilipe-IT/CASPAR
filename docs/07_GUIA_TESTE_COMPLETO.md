# Guia de teste completo — CVM/CASPAR

Este guia percorre **toda** a plataforma: serviços reais instalados, os 20
comandos do CLI, a API REST e a consola de gestão Web. Serve dois propósitos:
validar uma instalação e produzir evidência reproduzível para a dissertação.

Ao contrário do [INSTALL.md](../INSTALL.md), que é o percurso mínimo até ao
primeiro scan, aqui assume-se que a instalação já funciona.

> **Regista o que corre mal.** Cada divergência entre o que este guia promete e
> o que a tua máquina faz é um resultado, não um contratempo. A validação em
> ambientes limpos já expôs sete problemas que a máquina de desenvolvimento
> nunca mostraria.

**Antes de começar**, confirma qual instalação estás a testar:

```bash
which caspar          # .venv/bin/caspar (pip) ou ~/.local/bin/caspar (Docker)
caspar targets        # tem de listar 11 alvos
```

Cada scan imprime no fim uma linha `reproducible: … kb sha256:…`. **Anota-a.**
É o que permite comparar resultados entre máquinas: scores só são comparáveis
entre bases de conhecimento idênticas.

---

## Parte 1 — Preparar serviços reais

O modo ficheiro (`caspar scan f.conf`) exercita o parser e o motor de scoring.
O modo `--live` exercita muito mais: descoberta do serviço instalado,
localização da configuração, detecção da versão em execução e cruzamento com
CVEs e exploits conhecidos. É a diferença entre avaliar um ficheiro e avaliar
um sistema.

### 1.1 Instalar Apache e NGINX

```bash
sudo apt-get update
sudo apt-get install -y apache2 nginx
```

**Os dois disputam a porta 80 e não podem estar activos ao mesmo tempo.** Quem
arrancar primeiro fica com ela; o outro falha o arranque. Alterna conforme o
serviço que estás a testar:

```bash
# testes ao Apache
sudo systemctl stop nginx && sudo systemctl start apache2

# testes ao NGINX
sudo systemctl stop apache2 && sudo systemctl start nginx
```

Se preferires os dois a correr — útil para fazer `--live` a ambos sem andar a
parar serviços — muda a porta do NGINX para 8080 em
`/etc/nginx/sites-enabled/default` (`listen 8080;`) e reinicia-o.

**Confirma sempre antes de cada scan `--live`:**

```bash
systemctl is-active apache2      # tem de dizer "active"
```

> **Porque é que isto não é um detalhe.** Com o serviço parado, o
> `caspar scan --live apache2` não falha nem avisa: recai na leitura da
> configuração em disco e devolve um score plausível. Os números saem
> comparáveis, mas não medem o que julgas — e a distinção ficheiro-vs-serviço é
> precisamente uma das propriedades em avaliação. Ver §1.3.

Confirma as versões — são elas que o CASPAR cruza com CVEs:

```bash
apache2 -v
nginx -v
```

### 1.2 Estado inicial: quanto vale uma instalação por omissão?

Antes de degradar seja o que for, mede o ponto de partida. Este número é
interessante por si só: mostra o que uma instalação Debian/Ubuntu típica traz.

```bash
caspar scan --live apache2
```

Anota o score. Uma instalação por omissão do Ubuntu não é uma configuração
endurecida, mas também não é o pior caso — espera um valor intermédio.

### 1.3 O que o `--live` observa (e o que não observa)

Vale a pena ter isto claro antes de interpretar qualquer resultado, porque
define o alcance das conclusões que podes tirar.

O `--live` **descobre o serviço instalado**: localiza o binário, pergunta-lhe a
configuração efectiva (no Apache via `apache2ctl -V`, que devolve o `ServerRoot`
real mesmo que não seja o do pacote), detecta a versão em execução e cruza-a com
CVEs e exploits conhecidos. Nada disto é observável a partir de um ficheiro
solto, e é a diferença que justifica o modo.

O que **não** faz é verificar se o serviço está a correr — `resolve_live_service`
em `config_assessment/core/input_resolver.py` não consulta o `systemctl`. Um
scan a um Apache parado corre até ao fim e devolve um score normal, identificando
o modo como `installed service`, que é literalmente verdade: o serviço está
instalado. Verificado: com o `apache2` em estado `failed`, o
`caspar scan --live apache2` devolveu `7.1/10` sem qualquer aviso.

A consequência prática é a da §1.1 — confirma o `systemctl is-active` antes de
cada scan `--live`, senão arriscas-te a comparar medições que julgas serem de
serviço em execução e são de configuração em disco.

A consequência conceptual interessa mais: **a configuração ser válida e o
serviço estar a correr são propriedades independentes**, e o CASPAR avalia a
primeira. Um caso concreto surgiu durante a preparação deste guia — uma
degradação deliberada com `SSLProtocol +SSLv3` produziu configuração que o
OpenSSL 3.0 do Ubuntu 22.04 recusa carregar (`SSLv3 not supported by this
version of OpenSSL`): o Apache não arrancava, mas a configuração continuava a
ser avaliável e a pontuar. Note-se ainda que `apache2ctl configtest` devolver
`Syntax OK` também não garante arranque — a validação de cifras só acontece na
inicialização real do módulo SSL.

### 1.4 Introduzir vulnerabilidades de forma controlada

**Faz cópia de segurança primeiro.** Vais editar configuração de um serviço
real:

```bash
sudo cp /etc/apache2/apache2.conf /etc/apache2/apache2.conf.orig
sudo cp /etc/apache2/conf-available/security.conf \
        /etc/apache2/conf-available/security.conf.orig
```

O Ubuntu põe as directivas de segurança do Apache em
`conf-available/security.conf`. Degrada-as uma a uma, para veres cada uma
mover o score:

```bash
sudo tee -a /etc/apache2/conf-available/security.conf >/dev/null <<'EOF'

# --- Degradação deliberada para teste CVM (remover depois) ---
ServerTokens Full
ServerSignature On
TraceEnable On
EOF

sudo systemctl reload apache2
caspar scan --live apache2
```

> **Se o `reload` disser `apache2.service is not active, cannot reload`** — o
> serviço já estava em baixo *antes* desta alteração; estas três directivas
> passam `configtest` sem problema (verificado num Ubuntu 22.04 limpo). O
> `reload` só recarrega um serviço a correr, e não te diz porque é que ele não
> está. Diagnostica antes de continuar:
>
> ```bash
> sudo apache2ctl configtest      # erro de sintaxe? diz o ficheiro e a linha
> sudo ss -lptn 'sport = :80'     # outro processo (nginx!) na porta 80?
> sudo tail -20 /var/log/apache2/error.log
> ```
>
> As duas causas que apanhámos nesta VM foram (1) `SSLProtocol +SSLv3` num
> passo anterior — o OpenSSL 3.0 removeu o SSLv3 do código, não o desactivou,
> logo o `configtest` falha; e (2) o nginx do §1.1 ainda a segurar a porta 80,
> caso em que o `configtest` diz `Syntax OK` e mesmo assim o arranque falha com
> `AH00072: could not bind to address [::]:80`. Ver §1.1 e §1.4.
>
> Depois de corrigir: `sudo systemctl start apache2 && systemctl is-active apache2`.

O score tem de subir face a 1.2, e deve aparecer a cadeia
`info-disclosure-chain`: `ServerTokens` e `ServerSignature` isoladas são
divulgação de informação; juntas dão ao atacante a versão exacta *e* a
confirmação do software.

**Segundo passo — permissões e listagem de directórios:**

```bash
sudo tee -a /etc/apache2/conf-available/security.conf >/dev/null <<'EOF'
<Directory /var/www/html>
    Options Indexes FollowSymLinks
    AllowOverride All
</Directory>
EOF

sudo systemctl reload apache2
caspar scan --live apache2
```

**Terceiro passo — TLS obsoleto:**

```bash
sudo a2enmod ssl
sudo tee -a /etc/apache2/conf-available/security.conf >/dev/null <<'EOF'
SSLProtocol all -SSLv2
SSLCipherSuite AES128-SHA
EOF

sudo apache2ctl configtest && sudo systemctl reload apache2
systemctl is-active apache2
caspar scan --live apache2 --report -f json -o live-degraded
```

> **Não uses `SSLProtocol +SSLv3` nem cifras RC4 aqui**, por muito tentador que
> seja como degradação. O OpenSSL 3.0 do Ubuntu 22.04 removeu-os do código, não
> apenas os desactivou: o `SSLv3` faz falhar o próprio `configtest`
> (`SSLv3 not supported by this version of OpenSSL`) e o Apache deixa de
> arrancar — ficas sem serviço para testar, e os scans `--live` seguintes
> passam a ler configuração em disco sem to dizerem (§1.3).
>
> `all -SSLv2` deixa TLSv1.0 e TLSv1.1 activos e `AES128-SHA` não tem forward
> secrecy: continuam a ser más configurações, que é o que o teste precisa, mas
> arrancam.

### 1.5 O mesmo alvo, dois modos

Compara o modo `--live` com o modo ficheiro sobre a mesma configuração:

```bash
caspar scan /etc/apache2/apache2.conf --report -f json -o modo-ficheiro
caspar scan --live apache2             --report -f json -o modo-live
caspar diff modo-ficheiro/*.json modo-live/*.json
```

Espera diferenças, e são informativas: o modo `--live` segue os `Include` do
Apache (portanto vê o `security.conf` que degradaste) e conhece a versão em
execução, o que activa o cruzamento com CVEs. O modo ficheiro vê só o ficheiro
que lhe deste.

### 1.6 NGINX

```bash
sudo cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.orig
sudo sed -i 's/# server_tokens off;/server_tokens on;/' /etc/nginx/nginx.conf
sudo nginx -t                      # valida a sintaxe antes de recarregar
caspar scan /etc/nginx/nginx.conf
```

Este scan é em modo ficheiro, portanto não precisa do NGINX a correr. Se
quiseres também o modo `--live`, troca os serviços primeiro (§1.1):

```bash
sudo systemctl stop apache2 && sudo systemctl start nginx
systemctl is-active nginx
caspar scan --live nginx
```

### 1.7 Restaurar (não saltes este passo)

```bash
sudo cp /etc/apache2/apache2.conf.orig /etc/apache2/apache2.conf
sudo cp /etc/apache2/conf-available/security.conf.orig \
        /etc/apache2/conf-available/security.conf
sudo cp /etc/nginx/nginx.conf.orig /etc/nginx/nginx.conf
sudo a2dismod ssl                   # só se o activaste no terceiro passo
sudo apache2ctl configtest && sudo systemctl restart apache2
systemctl is-active apache2         # confirma antes de medir (§1.3)
caspar scan --live apache2          # tem de voltar ao valor de 1.2
```

O regresso ao valor inicial é, ele próprio, uma verificação: confirma que o
score reflecte a configuração e não estado acumulado. **Só é uma verificação
válida com o serviço `active`** — a comparar com o serviço parado, estarias a
medir outra coisa e a obter um número parecido na mesma.

Se testaste também o NGINX, repõe o estado que preferires para a máquina:

```bash
sudo systemctl start nginx          # implica parar o apache2 (§1.1)
```

---

## Parte 2 — Comandos de avaliação

### 2.1 `scan` — os quatro modos

```bash
caspar demo                                        # gera alvos de exemplo
caspar scan caspar-demo/apache-vulnerable.conf     # ficheiro
caspar scan caspar-demo/                           # directório (recursivo)
caspar scan --live apache2                         # serviço instalado
caspar scan docker://httpd:2.4                     # imagem de container
```

### 2.2 Formatos de relatório

`-o` é uma **pasta**, não um ficheiro:

```bash
caspar scan caspar-demo/apache-vulnerable.conf --report -f html      -o relatorios
caspar scan caspar-demo/apache-vulnerable.conf --report -f dashboard -o relatorios
caspar scan caspar-demo/apache-vulnerable.conf --report -f json      -o relatorios
caspar scan caspar-demo/apache-vulnerable.conf --report -f sarif     -o relatorios
ls relatorios/
```

O SARIF é o formato que o GitHub Code Scanning consome; o `dashboard` é o
relatório visual de infraestrutura.

### 2.3 Portões de CI

```bash
caspar scan caspar-demo/apache-hardened.conf --threshold 1.0 >/dev/null 2>&1
echo "saída: $?"     # 1 — 4.7 excede o limite de 1.0

caspar scan caspar-demo/apache-hardened.conf --threshold 5.0 >/dev/null 2>&1
echo "saída: $?"     # 0 — 4.7 está abaixo de 5.0

caspar scan caspar-demo/apache-vulnerable.conf --threshold 8.0 >/dev/null 2>&1
echo "saída: $?"     # 1 — 8.7 excede o limite de 8.0

caspar scan caspar-demo/apache-vulnerable.conf --exit-code >/dev/null 2>&1
echo "saída: $?"     # 0 — 8.7 é HIGH, não CRITICAL
```

> **Não uses `| tail` nem `| grep` para ler o código de saída.** Num pipe, `$?`
> é o código do *último* comando da cadeia, não o do `caspar` — vais ver sempre
> 0. Redirecciona para `/dev/null` como acima.

`--threshold` devolve 1 se o score global exceder o limite. `--exit-code`
acrescenta um patamar: devolve 2 quando o resultado é CRITICAL.

Com a base de conhecimento canónica (logo após o seed, sem `refresh` nem
`fetch-exploits`) nenhuma das configurações de demonstração chega a CRITICAL,
pelo que `--exit-code` devolve 0 em todas — usa `--threshold` para ver o portão
a reprovar. Depois de enriquecer a base com dados de exploração pública os
scores sobem e `--exit-code` passa a disparar.

Repara também que o portão reprova por um **finding individual**, nunca por uma
cadeia: o score global vem sempre do pior finding e as cadeias não entram nele.
A configuração Apache vulnerável dispara 4 cadeias, uma delas cotada em 10.0,
sem que isso mexa no score. Se quiseres um portão sensível à composição, lê a
secção `ATTACK CHAINS TRIGGERED` do output em vez do código de saída.

### 2.4 Versão do serviço e exploits

```bash
caspar scan caspar-demo/apache-vulnerable.conf --service-version 2.4.49
```

A 2.4.49 tem CVEs conhecidos (path traversal, CVE-2021-41773). Compara com uma
versão recente para ver a amplificação temporal em acção.

### 2.5 Directivas desconhecidas (requer Ollama)

```bash
caspar scan caspar-demo/apache-vulnerable.conf --show-uncovered
caspar scan caspar-demo/apache-vulnerable.conf --assess-unknown
```

O primeiro lista o que a base não cobre; o segundo pede a um LLM local que o
avalie. Sem Ollama, o segundo falha — e é assim que deve ser: o caminho
determinístico nunca depende de rede nem de modelo.

---

## Parte 3 — Estado e ciclo de vida

### 3.1 `suppress` — aceitar um risco conhecido

```bash
caspar suppress ServerTokens -r "Mitigado no WAF à frente do servidor"
caspar suppress --list
caspar scan caspar-demo/apache-vulnerable.conf     # o finding desapareceu
caspar suppress --remove ServerTokens
caspar suppress --list
```

A supressão fica num ficheiro `.caspar-suppress.json` na pasta actual, com o
motivo e a data — é uma decisão auditável, não um silenciamento.

### 3.2 `fix` — remediação

```bash
caspar fix caspar-demo/apache-vulnerable.conf --dry-run    # só mostra o diff
caspar fix caspar-demo/apache-vulnerable.conf              # escreve .fixed
diff caspar-demo/apache-vulnerable.conf caspar-demo/apache-vulnerable.conf.fixed
caspar scan caspar-demo/apache-vulnerable.conf.fixed       # o score desceu?
```

O `--in-place` reescreve o original. Testa-o só numa cópia.

### 3.3 `history`, `trend`, `diff`

```bash
caspar history -n 20
caspar trend -n 20
caspar scan caspar-demo/apache-vulnerable.conf --report -f json -o antes
caspar scan caspar-demo/apache-hardened.conf   --report -f json -o depois
caspar diff antes/*.json depois/*.json
```

O `diff` mostra problemas resolvidos, problemas novos e a variação do score —
é o que sustenta a afirmação de que o CVM mede evolução, não só estado.

### 3.4 `explain` e `badge`

```bash
caspar explain ServerTokens -t apache-httpd
caspar badge caspar-demo/apache-vulnerable.conf
caspar badge caspar-demo/apache-vulnerable.conf --url-only
```

O `explain` mostra a proveniência completa de uma regra — secção do benchmark,
CCE, justificação — sem precisar de scan. É o mecanismo de auditoria da base
de conhecimento.

### 3.5 `doctor`

```bash
caspar doctor
caspar doctor --strict
```

### 3.6 `watch` — monitorização contínua

Numa sessão de terminal:

```bash
caspar watch caspar-demo/apache-vulnerable.conf -i 10 --log watch.log
```

Noutra, edita o ficheiro e observa o alerta aparecer:

```bash
echo "ServerTokens Prod" >> caspar-demo/apache-vulnerable.conf
```

Termina com `Ctrl-C`. O `watch` só pára com interrupção — a pausa e a paragem
existem apenas através da API e da consola, uma assimetria deliberada.

---

## Parte 4 — Base de conhecimento

### 4.1 Inspeccionar

```bash
caspar targets            # 11 alvos com regras
caspar targets --all      # inclui os que não têm regras construídas
```

### 4.2 `plugin`

```bash
caspar plugin --help          # subcomandos: add, fetch, manual
caspar plugin fetch --help
caspar plugin manual --help
```

Não existe `plugin list` — a listagem de alvos instalados é o `caspar targets`
acima. O `plugin add` instala um alvo novo a partir de um PDF de benchmark
(requer Ollama, ver §4.3); o `plugin fetch` descarrega benchmarks de fontes
públicas; o `plugin manual` acrescenta documentação do serviço à base RAG de um
plugin já instalado.

### 4.3 Construção (requer Ollama, demora horas)

**Não corras isto a meio de uma validação** — muda a base de conhecimento e
invalida a comparação de scores com os passos anteriores.

```bash
caspar build --benchmark <ficheiro.pdf> --target <nome> --dry-run
```

O `--dry-run` mostra o plano sem escrever. É a forma segura de verificar que o
caminho de build funciona sem esperar horas.

### 4.4 Enriquecimento por rede

Mesma advertência: muda os scores.

```bash
caspar refresh --target apache-httpd --dry-run
caspar fetch-exploits --product apache-httpd
```

Depois de um `refresh` real, os findings sobem — a base canónica traz `GEL:L
GRL:H` (valores por omissão) e o enriquecimento substitui-os por dados reais
do NVD e do CISA KEV. Confirma comparando a linha `reproducible:` antes e
depois: o `kb sha256` **tem** de mudar.

---

## Parte 5 — API REST

```bash
caspar serve
```

Na imagem Docker e no `install-native.sh` as dependências da API já vêm
instaladas. Só num `pip install -e .` feito à mão é que precisas do extra:
`pip install -e ".[api]"`.

Noutra sessão:

```bash
curl -s localhost:8000/api/v1/health | python3 -m json.tool
curl -s localhost:8000/api/v1/targets | python3 -m json.tool
curl -s -X POST localhost:8000/api/v1/scans \
     -H 'Content-Type: application/json' \
     -d '{"input_path": "'$PWD'/caspar-demo/apache-vulnerable.conf"}' \
     | python3 -m json.tool | head -30
```

A especificação completa está em `http://localhost:8000/docs` — 44 operações
sobre 38 caminhos.

**Autenticação**, activa só quando a variável está definida:

```bash
CASPAR_API_KEY=segredo caspar serve
curl -s localhost:8000/api/v1/scans                       # 401
curl -s -H 'X-API-Key: segredo' localhost:8000/api/v1/scans   # 200
```

**Verificação que interessa à tese** — o CLI e a API têm de produzir o mesmo
score para o mesmo input:

```bash
caspar scan caspar-demo/apache-vulnerable.conf --report -f json -o via-cli
# compara o global_temporal_score do JSON com o devolvido pelo POST acima
```

---

## Parte 6 — Consola de gestão Web

### 6.1 Arrancar a consola

**Não há nada a instalar nem a construir.** A consola vem pronta nas duas formas
de instalação, e nenhuma delas precisa de Node na tua máquina:

- **Docker** — a imagem constrói a consola durante a build, numa etapa própria;
- **Nativa** (`install-native.sh`) — `frontend/dist` está versionado no
  repositório, portanto um `git clone` já o traz construído.

```bash
caspar serve
```

O arranque imprime os URLs da API (`/docs`) e da consola CVM (`/app`). Se a
consola faltar — só acontece num source tree a que alguém apagou o `dist` — a
linha do `/app` é substituída por um aviso explícito, em vez de te dar um
endereço que responde 404. Nesse caso: `git checkout frontend/dist`.

> Só precisas de Node se fores **editar** o código React (`frontend/src`). Aí
> corres `npm install && npm run build` para regenerar o `dist` — que deve ser
> commitado, senão a consola versionada fica desactualizada face ao código.

### 6.2 Percorrer as oito páginas

Abre `http://localhost:8000/app`.

| Página | O que verificar |
|---|---|
| **Dashboard** | score global, findings por severidade, cadeias activas, scans recentes |
| **Assessment** | correr um scan (upload e caminho de servidor), histórico, comparação, Remediate |
| **Knowledge Base** | navegar alvos, regras e cadeias; a proveniência de cada regra |
| **Plugins** | plugins instalados |
| **Build** | formulário de construção com registo de execução ao vivo |
| **Watch** | sessões activas, pausar, retomar, parar |
| **Reports** | gerar e descarregar relatórios |
| **Settings** | tema, preferências, riscos aceites (suppressions), saúde da base |

**Verificações específicas:**

1. **Remediate mostra mas não aplica.** Em Assessment → Remediate, gera a
   pré-visualização do patch. O ficheiro no disco **não pode** mudar — a
   escrita por HTTP é deliberadamente inexistente.
2. **Suppressions em Settings → Accepted risks.** Cria uma, confirma que
   aparece no ficheiro; remove-a, confirma que desaparece.
3. **Watch tem pausa e paragem** que o CLI não tem. Confirma que pausar
   interrompe os batimentos e que a sessão fica inactiva.
4. **Tema claro e escuro** com o selector.

Se preferires o dashboard servido pelo Jinja2 (a interface anterior, mantida):
`http://localhost:8000/dashboard`.

---

## Parte 7 — Suite de testes

```bash
pip install -e ".[dev]"
python3 -m pytest tests/ -q
```

O critério é **zero falhas e zero erros**. O total varia com os ficheiros-fonte
presentes (ver [INSTALL.md §5](../INSTALL.md)); `passed` acompanhado de
`skipped` é um resultado válido.

Para ver o motivo de cada skip:

```bash
python3 -m pytest tests/ -q -rs 2>&1 | grep SKIPPED | sort | uniq -c
```

---

## Parte 8 — Registo de resultados

Preenche à medida que avanças. É esta tabela que sustenta a secção de
validação da dissertação.

| # | Verificação | Esperado | Obtido | ✓/✗ |
|---|---|---|---|---|
| 1 | `caspar targets` | 11 alvos | | |
| 2 | Apache por omissão (`--live`) | score de referência | | |
| 3 | Após degradação 1 (info disclosure) | score sobe, cadeia activa | | |
| 4 | Após degradação 2 (permissões) | score sobe | | |
| 5 | Após degradação 3 (TLS) | score sobe | | |
| 6 | Após restauro | volta ao valor de #2 | | |
| 7 | Determinismo (5 scans) | hash idêntico | | |
| 8 | Os quatro formatos de relatório | 4 ficheiros gerados | | |
| 9 | `--threshold` / `--exit-code` | saída 1 / 2 | | |
| 10 | `suppress` cria e remove | finding desaparece e volta | | |
| 11 | `fix --dry-run` não escreve | ficheiro intacto | | |
| 12 | `diff` entre vulnerável e endurecido | delta negativo | | |
| 13 | API: score igual ao CLI | valores idênticos | | |
| 14 | API: `X-API-Key` | 401 sem chave, 200 com | | |
| 15 | Consola: as 8 páginas carregam | sem erros de consola | | |
| 16 | Consola: Remediate não escreve | ficheiro intacto | | |
| 17 | Suite de testes | 0 falhas, 0 erros | | |

**Ambiente:** distribuição, versão do Python, método de instalação (pip ou
Docker) e a linha `reproducible:` de um scan. Sem isso, os números não são
comparáveis entre máquinas.
