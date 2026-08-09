# CASPAR — Testar numa VM Ubuntu 22.04 limpa, do zero até à comparação final

> **Papel deste documento:** percurso único e sequencial — VM acabada de instalar, sem nada do
> projeto, até: instalar o CASPAR, **inserir uma vulnerabilidade real** num serviço, correr o scan,
> abrir o relatório, percorrer **todos os comandos do CLI**, e terminar com a **comparação final
> contra Trivy e OpenSCAP** no mesmo alvo. Não precisas de saltar entre ficheiros — tudo o que é
> preciso está aqui, por ordem.
>
> Este é o **guia 03** do roteiro (ver [README.md](../README.md) para a lista completa). Depois
> deste, segue para o **guia 04** ([04_AVALIACAO_FUNCIONAL.md](04_AVALIACAO_FUNCIONAL.md)) para
> recolher os resultados no formato usado na dissertação. Conceitos/arquitetura em
> [02_GUIA_CASPAR.md](02_GUIA_CASPAR.md); protocolo de medições de desempenho em
> [06_VALIDACAO.md](06_VALIDACAO.md).

Assume-se acesso à internet normal (`apt`, `curl`, `docker pull`, `ollama pull` — sem proxy nem
rede isolada).

---

## 0. Roteiro

1. Atualizar o sistema
2. Instalar o CASPAR (Docker, um comando)
3. Instalar um serviço real (nginx) e **inserir uma vulnerabilidade** na config dele
4. Scan + relatório HTML — ver o resultado
5. Percorrer **todos os comandos do CLI**
6. Instalar Trivy + OpenSCAP e correr a **comparação final**
7. Checklist de fecho

---

## 1. Atualizar o sistema

```bash
sudo apt-get update && sudo apt-get upgrade -y
```

---

## 2. Instalar o CASPAR — Docker, um comando

### 2.1 Docker Engine

O Ubuntu 22.04 traz um `docker.io` desatualizado nos repositórios padrão; usa o repositório oficial
da Docker:

```bash
sudo apt-get install -y ca-certificates curl gnupg

sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
```

Correr sem `sudo` (recomendado):

```bash
sudo usermod -aG docker "$USER"
```

⚠️ Só aplica numa **sessão nova** — logout/login (ou `newgrp docker` na sessão atual):

```bash
docker version   # deve responder sem sudo e sem erro de permissão
```

### 2.2 Instalar o CASPAR

```bash
curl -fsSL https://raw.githubusercontent.com/AFilipe-IT/CASPAR/master/install.sh | sh
export PATH="$HOME/.local/bin:$PATH"   # só se o script avisar que não está no PATH ainda
```

Isto confirma que o Docker existe, faz `docker pull` das duas imagens públicas
(`alfilipe/caspar:latest` leve, `alfilipe/caspar:full` com Ollama embutido) e instala o wrapper
`caspar` em `~/.local/bin`.

### 2.3 Clonar o repositório (para teres os fixtures de exemplo e os scripts de comparação)

```bash
git clone https://github.com/AFilipe-IT/CASPAR.git caspar
cd caspar
```

O wrapper `caspar` (§2.2) já funciona sem isto — mas os passos 5 e 6 abaixo usam ficheiros deste
repositório (`test_target/`, `scripts/baseline_compare.py`).

### 2.4 Validar a instalação

```bash
caspar doctor       # integridade da DB
caspar targets      # 13 plugins listados: apache-httpd, azure-iac, docker, dockerfile, dummy,
                     # kubernetes, mysql, nginx, postgresql, redis, ssh, tomcat, ubuntu
```

✓ **Esperado:** `doctor` devolve `✓ Database is healthy`; `targets` lista os 13 plugins.

### 2.5 (Opcional) Construir as imagens a partir do código local, em vez das publicadas

Só necessário se estiveres a testar alterações ao código-fonte (não o caso normal de utilizador —
salta para a secção 3 se instalaste com `install.sh` sem alterações).

A `caspar:full` é `FROM caspar:latest` → **constrói sempre a `latest` primeiro**, senão a `full`
fica com código antigo. O contexto de build é a raiz do repo clonado em §2.3:

```bash
cd caspar

# 1º — imagem runtime (leve: scan/report/watch/trend; sem Ollama)
docker build -t caspar:latest -f docker/caspar/Dockerfile .

# 2º — imagem build-time (com Ollama embutido: plugin add/fetch --then-install, build azure)
docker build -t caspar:full -f docker/caspar/Dockerfile.full .
```

O wrapper `caspar` usa os nomes `alfilipe/caspar:latest|full` — dá esses nomes às imagens locais:

```bash
docker tag caspar:latest alfilipe/caspar:latest
docker tag caspar:full   alfilipe/caspar:full
```

⚠️ Reinstalar com `install.sh` normal faria `docker pull`, o que **substituiria** as imagens que
acabaste de construir pelas publicadas no Docker Hub. Para continuar a usar as imagens locais,
salta o pull ao (re)instalar o wrapper:

```bash
sed '/docker pull/d' install.sh | sh
```

Publicar no Docker Hub (quando quiseres atualizar as imagens públicas):

```bash
docker login
docker push alfilipe/caspar:latest
docker push alfilipe/caspar:full
```

---

## 3. Instalar um serviço real e inserir uma vulnerabilidade

Em vez de usar só os fixtures de exemplo, instala um serviço real na VM e desconfigura-o à mão —
é o teste mais convincente de que o CASPAR lê configuração viva, não um caso de laboratório.

### 3.1 Instalar o nginx

```bash
sudo apt-get install -y nginx
sudo systemctl status nginx --no-pager   # confirma que está a correr
```

### 3.2 Scan à config por omissão (baseline, antes de mexer em nada)

```bash
caspar scan /etc/nginx/nginx.conf
```

Guarda mentalmente o score — vais comparar depois de inserires a vulnerabilidade.

### 3.3 Inserir a vulnerabilidade

Edita `/etc/nginx/nginx.conf` (`sudo nano /etc/nginx/nginx.conf` ou editor à escolha) e dentro do
bloco `http { ... }` adiciona/altera estas linhas (todas são misconfigurations reais cobertas pela
base de conhecimento do plugin `nginx`):

```nginx
http {
    # ... (linhas existentes ficam) ...

    server_tokens on;              # expõe a versão do nginx nos headers/erros (information disclosure)
    autoindex on;                  # listagem de diretório sem index.html — expõe ficheiros
    keepalive_timeout 300;         # timeout excessivo — facilita exhaustion (DoS de baixo esforço)
    ssl_protocols TLSv1 TLSv1.1;   # protocolos SSL/TLS obsoletos e inseguros
}
```

Confirma a sintaxe antes de recarregar (o nginx recusa-se a arrancar com um erro de sintaxe):

```bash
sudo nginx -t
sudo systemctl reload nginx
```

### 3.4 Scan depois da vulnerabilidade — comparar

```bash
caspar scan /etc/nginx/nginx.conf
```

✓ **Esperado:** score bem mais alto do que o baseline de §3.2, com 4 findings novos
(`server_tokens`, `autoindex`, `keepalive_timeout`, `ssl_protocols`), cada um com narrativa,
vetor CCSS e a linha `reproducible: caspar … · kb sha256:… · N rules (nginx)` no rodapé.

---

## 4. Relatório — ver o resultado num browser

```bash
caspar scan /etc/nginx/nginx.conf --report -f html -o relatorios
ls relatorios/
```

Abre o HTML gerado (`ccss_nginx.conf_<timestamp>.html`):

```bash
# se tiveres ambiente gráfico na VM:
xdg-open relatorios/ccss_nginx.conf_*.html
# se a VM for headless, copia para a máquina anfitriã:
python3 -m http.server 8000 --directory relatorios   # depois abre http://<IP-da-VM>:8000 no browser do host
```

✓ **Esperado:** dashboard com score global, gráfico por submétrica (AV/AC/Au/C/I/A/GEL/GRL), lista
de findings ordenada por severidade e, se aplicável, attack chains destacadas.

Também vale a pena gerar em `dashboard` (gráficos interativos) e `sarif` (formato standard,
integração CI/GitHub Code Scanning):

```bash
caspar scan /etc/nginx/nginx.conf --report -f dashboard -o relatorios
caspar scan /etc/nginx/nginx.conf --report -f sarif -o relatorios
```

---

## 5. Percorrer todos os comandos do CLI

Com a vulnerabilidade já inserida (§3.3), todos os comandos abaixo têm dados reais para trabalhar.
Corre por ordem — os de histórico/tendência dependem dos scans anteriores já teres corrido.

### 5.1 Descoberta / estado geral

```bash
caspar --help
caspar targets
caspar doctor
caspar doctor --strict    # audita também narrativas com claims de impacto sem linguagem condicional
```

### 5.2 Scan — os 4 modos

```bash
caspar scan /etc/nginx/nginx.conf                       # modo 1: ficheiro único (já corrido acima)
caspar scan test_target/                                # modo 2: diretório completo (fixtures do repo)
caspar scan --live nginx                                 # modo 3: serviço live, deteta a config sozinho
caspar scan docker://nginx:latest                        # modo 4: imagem Docker (pull automático se preciso)
```

Opções úteis (todas sobre o mesmo alvo, para veres o efeito de cada flag):

```bash
caspar scan /etc/nginx/nginx.conf --show-uncovered        # lista TODAS as diretivas fora da base
caspar scan /etc/nginx/nginx.conf --profile internal       # AV:Adjacent em vez de Network
caspar scan /etc/nginx/nginx.conf -f json --report         # gera JSON (usado por diff/report/badge — próximos passos)
caspar scan /etc/nginx/nginx.conf --threshold 5.0           # exit 1 se score > 5 (uso em CI)
caspar scan /etc/nginx/nginx.conf --exit-code                # exit 2 se Critical, 1 se > threshold, 0 caso contrário
caspar scan /etc/nginx/nginx.conf --assess-unknown           # LLM avalia diretivas desconhecidas (requer Ollama — ver §5.7)
```

### 5.3 Explicar uma regra sem correr scan

```bash
caspar explain server_tokens --target nginx
caspar explain ssl_protocols --target nginx
```
✓ **Esperado:** bad→good value, vetor CCSS completo, score base/temporal, benchmark de origem,
narrativa e justificação por submétrica.

### 5.4 Correção automática

```bash
caspar fix /etc/nginx/nginx.conf --dry-run    # mostra o diff, não escreve nada
```
✓ **Esperado:** diff `@@ line N (directiva, score)` com o valor inseguro riscado e o valor seguro
proposto para cada uma das 4 misconfigurations inseridas.

Se quiseres ver a correção aplicada a um ficheiro (sem tocar no `/etc/nginx` real):

```bash
cp /etc/nginx/nginx.conf /tmp/nginx_test.conf
caspar fix /tmp/nginx_test.conf              # escreve /tmp/nginx_test.conf.fixed
diff /tmp/nginx_test.conf /tmp/nginx_test.conf.fixed
```

### 5.5 Histórico, tendência, diff, badge, relatório combinado

```bash
caspar history --last 10
caspar trend
```
✓ **Esperado (`trend`):** sparkline do input `/etc/nginx/nginx.conf` com score inicial (baseline
§3.2) → final (§3.4) e direção `▲` (piorou).

```bash
# gera dois JSONs para o diff: um antes, um depois da vulnerabilidade
# (se ainda tiveres o git stash/backup da config original, ou usa dois fixtures diferentes)
caspar scan test_target/nginx_hardened.conf -f json --report -o relatorios
caspar scan /etc/nginx/nginx.conf -f json --report -o relatorios
caspar diff relatorios/ccss_nginx_hardened.conf_*.json relatorios/ccss_nginx.conf_*.json
```
✓ **Esperado:** `Resolved: N   New: M   Unchanged: K` e o delta de score entre os dois JSONs.

```bash
caspar report relatorios/*.json
```
✓ **Esperado:** resumo executivo combinado — score médio, pior alvo, totais de issues/chains.

```bash
caspar badge relatorios/ccss_nginx.conf_*.json
```
✓ **Esperado:** markdown pronto para README, ex.
`![CASPAR Score](https://img.shields.io/badge/CASPAR-...)`.

### 5.6 Risco aceite (suppressions)

```bash
caspar suppress --list                                          # "No suppressions." se vazio
caspar suppress server_tokens -r "Aprovado pela arquitetura"
caspar suppress --list                                           # agora lista a entrada
caspar scan /etc/nginx/nginx.conf                                 # score mais baixo — server_tokens excluído
caspar suppress --remove server_tokens
```

### 5.7 Monitorização contínua

```bash
caspar watch /etc/nginx/nginx.conf --log /tmp/watch.log &   # em background
# noutro terminal: reverte uma das linhas inseridas em §3.3 e faz `sudo systemctl reload nginx`
cat /tmp/watch.log     # deve mostrar a alteração detetada com o novo score
kill %1                # para o watch em background
```

### 5.8 Build-time — Ollama e construção da base de conhecimento

Na primeira utilização de um comando de build-time (`plugin add`, `build`, `fetch --then-install`),
o wrapper troca sozinho para a imagem `:full`, que arranca o Ollama e descarrega `qwen2.5:14b`
(~9GB — demora, depende da ligação) antes de correr o comando. Não precisas de instalar Ollama à
parte na VM.

```bash
ollama list 2>/dev/null || echo "(Ollama corre dentro do container :full, não na VM diretamente)"
```

```bash
caspar fetch-exploits -p nginx                # pré-busca NVD/Exploit-DB (rede)
caspar refresh -t nginx --dry-run             # atualiza GEL/GRL com NVD+KEV, sem escrever
caspar promote --stats                        # scoreboard do learning loop (0% é normal sem promoções)
```

```bash
caspar build --benchmark <caminho-para-um-Benchmark-CIS.pdf> --target apache-httpd --dry-run
```
> **Atenção:** `--benchmark` espera um **PDF de benchmark CIS/STIG real** (extraído via
> `pdftotext`), não um ficheiro de configuração — não corras isto contra `test_target/*.conf`. Sem
> um PDF real à mão, confirma apenas que o comando aparece em `caspar --help` e segue em frente.

### 5.9 Plugins novos

```bash
caspar plugin --help
caspar plugin add --benchmark <PDF>            # instala plugin a partir de um benchmark CIS (LLM)
caspar plugin fetch <fonte>                    # descarrega benchmark público conhecido
caspar plugin manual nginx <manual.pdf>        # acrescenta manual de serviço ao RAG de um plugin já instalado
```

---

## 6. Comparação final — CASPAR vs Trivy vs OpenSCAP

Este é o teste de fecho: o mesmo tipo de alvo avaliado pelo CASPAR e por duas ferramentas
estabelecidas, para posicionar qualitativa e quantitativamente a metodologia.

### 6.1 Instalar o Trivy

```bash
sudo apt-get install -y wget apt-transport-https gnupg
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo gpg --dearmor -o /usr/share/keyrings/trivy.gpg
echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb $(. /etc/os-release && echo "$VERSION_CODENAME") main" | \
  sudo tee /etc/apt/sources.list.d/trivy.list
sudo apt-get update
sudo apt-get install -y trivy
trivy --version
```

### 6.2 Instalar o OpenSCAP

```bash
sudo apt-get install -y libopenscap8
```

O conteúdo SCAP (`ssg-ubuntu2204-ds.xml`) **não está disponível via apt em Ubuntu 22.04 "jammy"**
(só a partir de 24.04 "noble"). Obtém-se diretamente do release oficial:

```bash
LATEST_URL=$(curl -s https://api.github.com/repos/ComplianceAsCode/content/releases/latest \
  | grep "browser_download_url.*tar.gz" | cut -d '"' -f4)
wget -q "$LATEST_URL" -O /tmp/scap-content.tar.gz
tar xzf /tmp/scap-content.tar.gz -C /tmp
sudo mkdir -p /usr/share/xml/scap/ssg/content/
sudo cp /tmp/scap-security-guide-*/ssg-ubuntu2204-ds.xml /usr/share/xml/scap/ssg/content/
ls -la /usr/share/xml/scap/ssg/content/ssg-ubuntu2204-ds.xml
```

### 6.3 Correr a comparação qualitativa (overlap/blind spots)

```bash
cd caspar   # raiz do repositório clonado em §2.3
source .venv/bin/activate 2>/dev/null || true   # se tiveres a via nativa também instalada; opcional
python3 -m scripts.baseline_compare --oscap
```

✓ **Esperado:** para cada fixture comparável (Terraform, Dockerfile), uma secção com as
descobertas do CASPAR (score + narrativa) lado a lado com as do Trivy (severidade fixa) e, se o
datastream estiver presente, o resultado do `oscap` na avaliação do sistema live. O objetivo não é
"quem encontra mais" — é mostrar que ambos detetam, mas só o CASPAR atribui uma pontuação CCSS
reprodutível com narrativa a cada finding.

### 6.4 Correr a comparação de desempenho (latência/CPU/RAM/energia)

```bash
python3 -m scripts.perf_baseline --runs 10 --json > /tmp/perf_baseline_native.json
cat /tmp/perf_baseline_native.json
```

✓ **Esperado:** JSON com `caspar`, `trivy` e (se o datastream OpenSCAP estiver presente)
`oscap_live_eval`, cada um com mediana/média±σ/p95 de latência, CPU total, RAM pico e energia
estimada, por fixture. Este é o mesmo protocolo documentado em
[06_VALIDACAO.md §6.2](06_VALIDACAO.md) — os números que colhes aqui são comparáveis aos já lá
reportados (mesma metodologia, N=10, 1 warm-up descartado).

> Se quiseres reportar estes números na tese, copia o JSON e a saída de `--oscap` do passo 6.3 tal
> como fizeste para os dados de §4.1/§6.2 já presentes em 06_VALIDACAO.md.

---

## 7. Checklist final

| # | Verificação | Como | Esperado |
|---|---|---|---|
| 1 | Docker sem sudo | `docker version` | responde sem erro de permissão |
| 2 | CASPAR instalado | `caspar doctor` | ✓ healthy |
| 3 | Plugins | `caspar targets` | 13 |
| 4 | Vulnerabilidade inserida | `caspar scan /etc/nginx/nginx.conf` | score mais alto que o baseline de §3.2, 4 findings novos |
| 5 | Relatório HTML | `relatorios/ccss_nginx.conf_*.html` abre num browser | dashboard com score, submétricas, findings |
| 6 | Todos os comandos do CLI | secção 5 completa, sem traceback | cada comando devolve o esperado |
| 7 | Reprodutibilidade | rodapé `reproducible:` com o MESMO `kb sha256` entre execuções sucessivas | manifesto igual ⇒ scores iguais |
| 8 | Persistência Docker | `docker volume ls` | `caspar_data`, `caspar_ollama_models` existem |
| 9 | Trivy instalado | `trivy --version` | responde |
| 10 | OpenSCAP + datastream | `ls /usr/share/xml/scap/ssg/content/ssg-ubuntu2204-ds.xml` | ficheiro presente |
| 11 | Comparação qualitativa | `python3 -m scripts.baseline_compare --oscap` | overlap/blind spots reportados para os 3 |
| 12 | Comparação de desempenho | `python3 -m scripts.perf_baseline --runs 10 --json` | latência/CPU/RAM/energia por ferramenta |

---

## Troubleshooting rápido

- **`permission denied` ao correr `docker`** → falta logout/login (ou `newgrp docker`) depois do
  `usermod -aG docker`.
- **`docker: command not found`** após instalar → confirma `dpkg -l | grep docker-ce`; em VMs sem
  virtualização aninhada ativa, o `containerd` pode falhar a arrancar — confirma
  `sudo systemctl status docker`.
- **`curl: (6) Could not resolve host`** → a VM não tem rede — confirma o adaptador de rede (NAT/
  bridged) nas definições do hipervisor.
- **`nginx -t` falha depois de editar** → revê a sintaxe (chavetas, `;` no fim de cada diretiva);
  o nginx não recarrega com erro de sintaxe, o que é esperado e seguro.
- **Download do modelo Ollama lento/interrompido** → `caspar_ollama_models` é um volume
  persistente; repetir o comando retoma sem re-descarregar as camadas já obtidas.
- **`ssg-debderived`/`ssg-base` "Unable to locate package"** → normal em jammy (22.04); é
  precisamente por isso que §6.2 usa o release do GitHub em vez do apt.
- **`ssg-ubuntu2204-ds.xml` não encontrado por `baseline_compare.py`/`perf_baseline.py`** → confirma
  que ficou exatamente em `/usr/share/xml/scap/ssg/content/` (é aí que `_oscap_datastream()`
  procura); o `oscap`/OpenSCAP em si pode precisar de correr como root (`sudo`) para o eval live.
- **`kb sha256` diferente do esperado** → confirma que a DB veio do mesmo `data/ccss_canonical.sql`
  sem alterações manuais às tabelas de regras; o hash ignora o histórico de scans, por isso correr
  scans não o altera, mas editar uma regra ou restaurar um dump diferente sim.
- **`ModuleNotFoundError: yaml`** → `pip install pyyaml` (via nativa) ou reconstrói a imagem (a
  linha pip dos Dockerfiles já o inclui).
- **`pdftotext: not found`** → `sudo apt-get install poppler-utils`.
- **`caspar` usa imagens antigas depois de reconstruíres (§2.5)** → confirma `docker images` e
  refaz o tagging; lembra: `latest` primeiro, `full` depois.
