# CASPAR — Docker

Distribuição em contentor do **CASPAR** (*Configuration Assessment and Security
Posture Automated Review*). Duas imagens, conforme o caso de uso:

| Imagem | Tamanho | Base | Inclui | Uso recomendado |
|--------|--------:|------|--------|-----------------|
| `caspar:latest` | **~430 MB** | `python:3.12-slim` | `scan` (ficheiro / directório / `docker://`), `targets`, `fetch-exploits`, relatórios; `build` / `plugin add` **com Ollama externo** | Produção, análise completa, *scan* de imagens Docker |
| `caspar:slim` | **~125 MB** | `python:3.12-alpine` | apenas `scan` de ficheiros / directórios e `targets` | CI/CD, *pipelines*, ambientes restringidos |

Ambas restauram a base de dados canónica (`ccss.db`) a partir de
`data/ccss_canonical.sql` **durante o build** — o `.db` nunca é copiado para a
imagem. Ambas correm como utilizador **não-root** (`caspar`, uid 1000).

> O contexto de build é a **raiz do repositório**. Os Dockerfiles são passados
> com `-f`; não corras `docker build` de dentro de `docker/caspar/`.

---

## Build

```bash
# A partir da raiz do repositório:
docker build -t caspar:latest -f docker/caspar/Dockerfile .
docker build -t caspar:slim   -f docker/caspar/Dockerfile.slim .

docker images | grep caspar
```

A `caspar:full` e a `caspar:demo` partem ambas da `caspar:latest` (`FROM
caspar:latest`), por isso a `latest` tem de ser reconstruída **primeiro** —
senão as alterações ao código não chegam a nenhuma das duas.

---

## A imagem da demonstração (`caspar:demo`)

A imagem do vídeo-anexo. Traz o Apache 2.4.49 instalado e já em configuração
deliberadamente vulnerável, de modo a que o scan ao vivo reproduza, sem nenhum
passo manual, os números que a dissertação publica.

```bash
docker build -t caspar:latest -f docker/caspar/Dockerfile      .
docker build -t caspar:demo   -f docker/caspar/Dockerfile.demo .

docker run --rm -it caspar:demo scan apache2 --live
```

Para o relatório HTML — e **é aqui que se perde um relatório**. Sem `-v`, o
`/reports` do contentor não é o teu disco: a escrita funciona, o caminho sai em
ciano, e o `--rm` apaga o ficheiro. O scan avisa quando isso acontece
(`nothing is mounted at '/reports'`), mas o certo é montar:

```bash
mkdir -p reports
docker run --rm -v "$PWD/reports:/reports" \
  caspar:demo scan apache2 --live --report -f dashboard
# → reports/ccss_apache2_<data>_dashboard.html, no host
```

Sem `-o`, o relatório vai para `/reports` (é o que a imagem põe em
`CASPAR_REPORTS_DIR`). Um `-o` para outro sítio qualquer dentro do contentor
tem o mesmo destino, e é avisado da mesma forma.

Esperado: `apache-httpd 2.4.49` · `8.5 / 10 HIGH` · 23 achados (0/2/19/2) ·
`Chains triggered 8` · pior chain 10.0 · `kb sha256:83b3ee01f415`. O *build*
**falha** se não for isto: a última camada do `Dockerfile.demo` corre o scan e
confere o score, a contagem de chains, a versão detectada e a digest da base de
conhecimento. Vale mais falhar no *build* do que descobrir o desvio com a câmara
a andar.

A digest está lá por uma razão concreta: é o número que aparece no rodapé
`reproducible:` em ecrã e no cartão final do vídeo, e a semente da imagem
(`data/ccss_canonical.sql`) já esteve uma versão atrás da base de trabalho —
514 regras · 32 chains · 12 alvos contra 488 · 27 · 11. A imagem dava então
`37087229989b`, e contradizia o roteiro sem avisar. Agora não compila se isso
voltar a acontecer.

O Apache vem da `httpd:2.4.49` oficial, que é a mesma build de origem que o
[`instalar-2.4.49.sh`](../../assets/demo-apache/instalar-2.4.49.sh) compila na
VM, com o mesmo prefixo (`/usr/local/apache2`) — poupa a compilação. A
configuração de partida é o `conf/original/httpd.conf` dessa imagem, a saída
intacta do `make install`, porque é esse o ponto de partida que foi medido.

**A 2.4.49 tem um RCE conhecido** (`CVE-2021-41773`). A imagem nunca arranca o
httpd — o scan lê a árvore de configuração em disco — e não expõe porta
nenhuma. Não lhe faças `-p` nem a publiques num registo público.

### Transportar a imagem para outra máquina

```bash
docker save caspar:demo | gzip > caspar-demo.tar.gz     # na máquina que constrói
docker load < caspar-demo.tar.gz                        # na máquina que grava
```

Evita ter de instalar o CASPAR, compilar o Apache e aplicar a configuração na
máquina da gravação: a imagem já traz tudo, e o estado é o mesmo em qualquer
máquina. Também dispensa o `restaurar-249.sh` — o contentor é descartável.

---

## Uso rápido

### Ver alvos suportados
```bash
docker run --rm caspar:latest targets
```

### Scan de ficheiro / directório local
```bash
# Directório (monta em /scan)
docker run --rm -v /etc/apache2:/scan caspar:latest scan /scan

# Ficheiro único
docker run --rm -v "$(pwd)/httpd.conf:/scan/httpd.conf" \
  caspar:latest scan /scan/httpd.conf
```

A versão do serviço é **auto-detectada** (tag → binário → texto da config) e
usada para cruzar CVEs/exploits e amplificar os *scores* (F1):

- **Versão na base canónica** → cruzamento offline e determinístico (×1.0–×1.5
  conforme CVEs/KEV).
- **Versão fora da base** → o runtime tenta o NVD ao vivo (*online-first*, com
  cache de 24 h). Com rede, pode amplificar; **sem rede ou sem versão, degrada
  graciosamente para ×1.0** e o relatório assinala o estado («exploit check
  unavailable» vs «checked clean»). Para um *scan* 100 % offline e reprodutível,
  garante que a versão está na base (`caspar fetch-exploits`) ou não passes
  versão.

### Scan com relatório persistente
```bash
docker run --rm \
  -v /etc/apache2:/scan \
  -v "$(pwd)/reports:/home/caspar/reports" \
  caspar:latest scan /scan --report --format dashboard --output /home/caspar/reports
```

> ⚠️ **O `--output` tem de apontar para um path montado.** O CASPAR escreve o
> relatório *dentro* do contentor; se esse path não tiver um volume do host
> montado, o ficheiro fica no contentor e perde-se quando ele é removido
> (`--rm`). A regra é simples: **o argumento de `--output` e o destino do `-v`
> têm de ser o mesmo path** (acima, ambos `/home/caspar/reports`).

### Scan de imagem Docker (`docker://`) — só `caspar:latest`
Requer o *socket* do Docker do host. Como a imagem corre como não-root, é
preciso conceder o grupo dono do *socket*. A versão é detectada a partir da tag
(`httpd:2.4.49` → `2.4.49`) e cruzada com a base canónica para amplificar os
*scores* (F1):

```bash
SOCK_GID=$(stat -c '%g' /var/run/docker.sock)

docker run --rm \
  --group-add "$SOCK_GID" \
  -v /var/run/docker.sock:/var/run/docker.sock \
  caspar:latest scan docker://nginx:latest
```

`docker://` **com relatório persistente** — junta o *socket*, o `--group-add` e
o volume de relatórios montado no mesmo path do `--output`:

```bash
docker run --rm \
  -v /var/run/docker.sock:/var/run/docker.sock \
  --group-add "$(stat -c '%g' /var/run/docker.sock)" \
  -v "$(pwd)/reports:/home/caspar/reports" \
  caspar:latest scan docker://httpd:2.4.49 \
  --report --format dashboard --output /home/caspar/reports
```

### Com docker-compose (inclui Ollama para *build-time*)
```bash
cd docker/caspar

# Runtime apenas (Ollama fica em baixo):
docker compose run --rm caspar targets
docker compose run --rm caspar scan /scan

# Build-time (sobe o Ollama sob o profile "full"):
docker compose --profile full up -d ollama
docker compose --profile full exec ollama ollama pull qwen2.5:14b
docker compose --profile full run --rm caspar plugin add \
  --source /home/caspar/app/sources/benchmarks/CIS_PostgreSQL_13.pdf
```

---

## Variáveis de ambiente

| Variável | Predefinição | Descrição |
|----------|--------------|-----------|
| `OLLAMA_HOST` | `http://ollama:11434` | Endereço do Ollama para os comandos *build-time* (`build`, `plugin add`). Ignorado em *runtime*. |
| `SEARCHSPLOIT_BIN` | (não definida) | Caminho do binário `searchsploit` (Exploit-DB) para enriquecimento de exploits, se disponível. Sem ele, o cruzamento usa apenas os dados já persistidos na base canónica. |

A flag `--db` (predefinição `ccss.db`) permite apontar para outra base; com o
volume `caspar_db` do compose, a base persiste entre execuções.

---

## Comparação de imagens

```
caspar:latest    430MB
caspar:slim      125MB
```

A `slim` exclui o cliente Docker, `git`, `curl` e a *toolchain* de build. O
maior ganho vem da exclusão dos PDFs de benchmark (CIS/STIG), que só são usados
em *build-time* (~85 MB, sendo o CIS SSH 78 MB) — não são lidos pelo *scan*.

---

## Performance

*Scan* do mesmo directório Apache (1 ficheiro `httpd.conf`, 7 *issues*),
3 execuções, *wall time* total incluindo arranque do contentor:

| Imagem | run 1 | run 2 | run 3 | Resultado |
|--------|------:|------:|------:|-----------|
| `caspar:latest` | 0.44 s | 0.40 s | 0.45 s | 9.8/10 Critical |
| `caspar:slim`   | 0.48 s | 0.44 s | 0.46 s | 9.8/10 Critical |

A análise de configuração é determinística e offline; o tempo é dominado pelo
arranque do processo, não pela análise. (A única excepção é o passo F1 quando a
versão não está na base — aí pode haver uma consulta ao NVD; ver a nota em
«Scan de ficheiro / directório local».) As duas imagens produzem **resultado
idêntico** — a vantagem da `slim` é o **tamanho** (≈3,4× menor), não a
velocidade.

*(Medições em WSL2, Docker 29.x; valores ilustrativos para a secção de
Performance da dissertação — reproduzíveis com o bloco abaixo.)*

```bash
for img in caspar:latest caspar:slim; do
  echo "--- $img ---"
  for i in 1 2 3; do
    /usr/bin/time -f "run $i: %e s" \
      docker run --rm -v /tmp/apache2_test:/scan $img scan /scan >/dev/null
  done
done
```

---

## Limitações

| Funcionalidade | Requisito | Sem ele |
|----------------|-----------|---------|
| `caspar build` / `caspar plugin add` | **Ollama** acessível em `OLLAMA_HOST` | Degrada graciosamente: o comando avisa que não há LLM e não corre. O *scan* continua a funcionar com a base canónica já incluída. |
| `caspar scan docker://<img>` | *socket* Docker montado **+** `--group-add <gid>` | Erro claro «Docker não está disponível». Disponível só na `caspar:latest` (a `slim` não traz cliente Docker). |
| Enriquecimento de exploits ao vivo | `searchsploit` (`SEARCHSPLOIT_BIN`) | Usa apenas os CVEs/exploits já persistidos na base canónica (offline). |
| F1 para versão **fora da base** | Rede + (opcional) `NVD_API_KEY` | Consulta o NVD ao vivo (*online-first*, cache 24 h). Sem rede, a amplificação degrada para ×1.0 e o relatório assinala «exploit check unavailable». Para versões na base, é tudo offline. |

A imagem **não inclui o Ollama** — é orquestrado à parte (ver
`docker-compose.yml`, profile `full`). Esta separação mantém a imagem de
*runtime* leve e o trabalho pesado de *build-time* (LLM + RAG + CVE) isolado.
