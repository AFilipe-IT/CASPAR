# AEGIS — Testar Todos os Comandos

> **Papel deste documento:** checklist sequencial que percorre **todos os
> subcomandos do CLI (`sca` / `python -m cli.main`)**, um a um, com um exemplo
> real contra os fixtures em [`test_target/`](../test_target/) e o output
> esperado. Serve para confirmar rapidamente, numa máquina nova ou depois de
> uma alteração ao código, que a ferramenta continua operacional de ponta a
> ponta.
>
> Complementa o [GUIA_TESTE_MAQUINA.md](GUIA_TESTE_MAQUINA.md) (que cobre
> setup/instalação e o roteiro de avaliação funcional Ubuntu) — aqui o foco é
> só "correr o comando X, confirmar que dá isto".

Pré-requisito: ambiente ativo e a partir da raiz do repositório.

```bash
source .venv/bin/activate     # ou: usa o wrapper `sca` se instalado via install.sh/-native.sh
```

Todos os exemplos abaixo usam `python -m cli.main`; se tiveres o wrapper
instalado, troca por `sca`.

---

## 1. Descoberta / estado geral

```bash
sca --help
sca targets
```
Confirma: lista os 12 plugins (`apache-httpd`, `azure-iac`, `docker`,
`dockerfile`, `dummy`, `kubernetes`, `mysql`, `nginx`, `redis`, `ssh`,
`tomcat`, `ubuntu`) com a versão e o benchmark de origem de cada um.

```bash
sca doctor
```
Confirma: `✓ Database is healthy — no issues found.` (exit 0). Com
`--strict` audita também narrativas com claims de impacto (RCE, privilege
escalation) sem linguagem condicional.

---

## 2. Scan (o comando principal, 4 modos)

**Modo 1 — ficheiro único:**
```bash
sca scan test_target/test_httpd.conf
sca scan test_target/nginx.conf
```
Confirma: score, findings individuais e attack chains (ex. `webdav-rce-chain`,
`directory-traversal-chain` no Apache), secção `UNCOVERED DIRECTIVES`, e a
linha `reproducible: sca 0.1.0 · kb sha256:... · N rules (<target>)`.

**Modo 2 — diretório completo:**
```bash
sca scan test_target/ --report -f html -o /tmp/aegis-test
```
Confirma: percorre todos os ficheiros reconhecíveis no diretório e escreve
`/tmp/aegis-test/ccss_test_target_<timestamp>.html`.

**Modo 3 — serviço live (requer o serviço instalado):**
```bash
sca scan --live nginx
```

**Modo 4 — imagem Docker (requer Docker):**
```bash
sca scan docker://httpd:2.4
```

**Opções úteis para testar em conjunto:**
```bash
sca scan test_target/nginx_hardened.conf         # 0.0/10 — No issues detected (fixture já endurecido)
sca scan test_target/nginx.conf --show-uncovered  # lista TODAS as diretivas fora da base
sca scan test_target/nginx.conf --profile internal # AV:Adjacent em vez de Network
sca scan test_target/nginx.conf -f json --report   # gera JSON (usado por diff/report/badge)
sca scan test_target/nginx.conf --threshold 7.0    # exit 1 se score > 7 (uso em CI)
sca scan test_target/nginx.conf --assess-unknown   # LLM avalia diretivas desconhecidas (requer Ollama)
```

---

## 3. Explicar uma regra sem correr scan

```bash
sca explain keepalive_timeout --target nginx
```
Confirma: mostra bad→good value, vetor CCSS completo, score base/temporal,
benchmark de origem, narrativa e justificação por submétrica (AC/C/I/A/GEL/GRL).

---

## 4. Correção automática

```bash
sca fix test_target/nginx.conf --dry-run
```
Confirma: mostra um diff `@@ line N (directiva, score)` com o valor inseguro
riscado e o valor seguro proposto, sem escrever nada em disco.

```bash
sca fix test_target/nginx.conf          # escreve nginx.conf.fixed
sca fix test_target/nginx.conf --in-place   # reescreve o próprio ficheiro (cuidado)
```

---

## 5. Histórico, tendência e comparação

Cada `scan` fica automaticamente registado na DB — por isso estes comandos já
têm dados reais depois de correres a secção 2.

```bash
sca history --last 5
```
Confirma: tabela `WHEN | SCORE | SEV | INPUT` dos scans mais recentes.

```bash
sca trend
```
Confirma: uma sparkline por input com score inicial → final e direção
(`▲` piorou, `▼` melhorou, `=` estável).

```bash
sca diff reports/scan_antigo.json reports/scan_novo.json
```
Confirma: `Resolved: N   New: M   Unchanged: K` e o delta de score. (Usa dois
JSONs gerados por `scan -f json --report`.)

```bash
sca report reports/*.json
```
Confirma: resumo executivo combinado — score médio, pior alvo, totais de
issues/chains, uma linha por scan.

```bash
sca badge reports/scan.json
```
Confirma: imprime markdown pronto para README, ex.
`![AEGIS Score](https://img.shields.io/badge/AEGIS-5.7%2F10-yellow)`.

---

## 6. Risco aceite (suppressions)

```bash
sca suppress --list                                            # "No suppressions." se vazio
sca suppress keepalive_timeout -r "Aprovado pela arquitetura"
sca suppress --list                                             # agora lista a entrada
sca suppress --remove keepalive_timeout
```

---

## 7. Monitorização contínua

```bash
sca watch test_target/nginx.conf
```
Confirma: fica a correr, imprime uma linha por alteração detetada no
ficheiro (score novo + o que mudou). `Ctrl+C` para parar.

```bash
sca watch test_target/nginx.conf --log /tmp/watch.log &   # background
# edita test_target/nginx.conf noutro terminal, depois:
cat /tmp/watch.log
kill %1                                                    # para o watch em background
```

---

## 8. Build-time — construção/manutenção da base de conhecimento

Estes comandos falam com um LLM local (Ollama) e/ou a rede (NVD/KEV) — não
fazem parte do runtime determinístico, só da fase de construção.

```bash
ollama list                       # confirma que o modelo (ex. qwen2.5:14b) está disponível
curl -s http://localhost:11434/api/tags   # confirma que o serviço Ollama responde
```

```bash
sca build --benchmark <caminho-para-um-Benchmark-CIS.pdf> --target apache-httpd --dry-run
```
> **Atenção:** `--benchmark` espera um **PDF de benchmark CIS/STIG real**
> (extraído via `pdftotext`), não um ficheiro de configuração de teste — não
> corras isto contra os fixtures de `test_target/*.conf`, fica pendurado à
> espera de texto de benchmark que não existe nesse ficheiro. Testa apenas
> com um PDF real, se tiveres um à mão; caso contrário confirma apenas que o
> comando aparece em `sca --help build` e que `ollama list`/`curl` acima
> respondem, o que já garante que o build teria com quem falar.

```bash
sca fetch-exploits -p nginx                # pré-busca NVD/Exploit-DB (rede)
sca refresh -t nginx --dry-run             # atualiza GEL/GRL com NVD+KEV, sem escrever
sca promote --stats                        # scoreboard do learning loop (0% é normal se nunca promoveste nada)
sca promote test_target/nginx.conf --dry-run 2>/dev/null || sca promote --stats  # ver nota abaixo
```
`promote` sem `--stats` só faz sentido depois de um `scan --assess-unknown`
que tenha sinalizado candidatos; sem isso não há nada para promover.

---

## 9. Plugins novos

```bash
sca plugin --help
sca plugin add --benchmark <PDF>            # instala plugin a partir de um benchmark CIS
sca plugin fetch <fonte>                    # descarrega benchmark público conhecido
sca plugin manual <target> <manual.pdf>     # acrescenta manual de serviço ao RAG de um plugin já instalado
```

---

## Checklist rápida (copiar/colar, sem LLM/rede)

Sequência mínima para confirmar que o núcleo determinístico está operacional,
sem depender de Ollama, Docker ou rede:

```bash
source .venv/bin/activate
sca targets
sca doctor
sca scan test_target/test_httpd.conf
sca scan test_target/test_nginx.conf
sca scan test_target/nginx_hardened.conf
sca explain keepalive_timeout --target nginx
sca fix test_target/nginx.conf --dry-run
sca history --last 5
sca trend
sca suppress --list
```

Se todos correrem sem traceback e o `scan` do fixture hardened devolver
`0.0/10 — No issues detected`, o núcleo está saudável.
