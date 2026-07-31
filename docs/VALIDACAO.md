# CASPAR — Plano de Validação Completo

> **Propósito:** catálogo sistemático de **todas as formas de validar o CASPAR**
> (metodologia AMiSA): validação científica, funcional, fiabilidade, desempenho
> (tempo, CPU, memória, energia), escalabilidade, comparação com baselines,
> **tradeoffs explícitos** e métricas estatísticas. Cada dimensão indica: a
> pergunta a que responde, o protocolo, a métrica, o comando, e o estado
> (✅ medido / 🔲 por medir).
>
> Complementa [AVALIACAO_FUNCIONAL.md](AVALIACAO_FUNCIONAL.md) (roteiro passo a
> passo no Ubuntu 22.04) e [DISSERTACAO_REFERENCIA.md](tese-docs/DISSERTACAO_REFERENCIA.md)
> (resultados consolidados para a tese).

---

## 0. Mapa de validação

| # | Dimensão | Pergunta | Métrica principal | Ferramenta | Estado |
|---|---|---|---|---|---|
| 0 | Científica — motor de scoring | O motor CCSS replica a especificação? | 18/18 exemplos oficiais do NISTIR 7502 §4 | `tests/test_nistir7502_examples.py` | ✅ 18/18 |
| 1 | Científica — correção | Os scores estão certos? | MAE / taxa de mismatch vs CCE | `scripts/evaluate.py` | ✅ 0% |
| 1b | Científica — submétricas | Cada submétrica CCSS está certa? | Concordância exata + Cohen's κ por submétrica | protocolo §1.2 | 🔲 |
| 2 | Funcional — deteção | Encontra as misconfigurations? | Recall + precision + F1 | `scripts/evaluate.py` | ✅ 100% recall · 100% precision/F1 |
| 3 | Funcional — integração | Tudo funciona de ponta a ponta? | Checks pass/fail | `scripts/functional_check.py` + pytest | ✅ 13/13 · ~646 |
| 4 | Fiabilidade | Dá sempre o mesmo resultado? | Determinismo, robustez, estabilidade do build LLM | §3 | ✅/🔲 |
| 5 | Desempenho — scan | Quanto custa identificar misconfigurations? | Latência, CPU, RAM, energia | §4.1 | 🔲 |
| 6 | Desempenho — extensão | Quanto custa adicionar um target novo? | Wall time, tokens/custo LLM, esforço humano | §4.2 | 🔲 |
| 7 | Desempenho — ingestão | Qual o overhead de inserir conhecimento? | Tempo de ingestão RAG, crescimento da BD | §4.3 | 🔲 |
| 8 | Escalabilidade | Aguenta configs/KB maiores que as atuais? | Curva latência × tamanho | §5 | 🔲 |
| 9 | Baselines | Como se posiciona vs Trivy/OpenSCAP? | Overlap, blind spots, custo por finding | `scripts/baseline_compare.py` | ✅ qualit. / 🔲 desempenho |
| 10 | Tradeoffs | O que se ganha e o que se paga? | Tabela §7 | análise | ✅ |

---

## 1. Validação científica (correção dos scores)

### 1.0 Replicação dos exemplos oficiais do NISTIR 7502 — ✅ 18/18

A própria especificação CCSS (NISTIR 7502, §4) publica **12 exemplos
resolvidos** (18 vetores base, 6 CCEs com dois casos), com impact subscore,
exploitability subscore e base score calculados com a calculadora oficial do
NVD. Replicá-los é a validação mais direta possível do motor de scoring: se o
`ccss.py` reproduz os números da especificação, a matemática está certa **por
construção**, independentemente da qualidade das submétricas extraídas.

```bash
python -m pytest tests/test_nistir7502_examples.py -v   # 21 passed
```

| O que se replica | Resultado |
|---|---|
| 18 vetores base (CCE-4675-5 … CCE-2776-3): impact + exploitability + base score | **18/18 exatos** |
| Exemplo temporal §4.12 (GEL:L/GRL:M → 1.9 / 3.7), via equação oficial §3.2.2 | ✅ reproduz |
| Defaults ND neutros (não alteram o score) em ambos os modelos | ✅ |

**Desvio documentado (achado desta replicação):** o `temporal_score()` do
CASPAR usa um modelo temporal **simplificado** — `BaseScore × GEL × GRL` com
valores GRL `U/W/H/ND` (linhagem CVSS v2) e multiplicadores combinados em
[0.81, 1.0] — enquanto a equação oficial usa GRL `N/L/M/H`, re-escala apenas o
termo de exploitability e permite multiplicadores até 0.6×0.4=0.24. O modelo
do CASPAR desconta portanto **no máximo ~19%** do score, contra reduções muito
maiores permitidas pela norma quando há remediação forte — um desvio
**conservador** (nunca subestima risco face à norma) mas que impede a
replicação direta do exemplo temporal com a API do CASPAR. Isto separa duas
coisas na dissertação: o **base score segue a norma exatamente** (18/18); o
ajuste temporal é uma **variação declarada e justificada**. Ver tradeoff em §7.

### 1.1 MAE vs ground truth CCE (Apache) — ✅ medido

O único target com dataset oficial anotado (CCE + faixas de severidade DISA).
Compara o score CCSS do CASPAR com a faixa DISA de cada controlo.

```bash
python -m scripts.evaluate          # secção "Correctness"
```

| Métrica | Resultado (Ubuntu 22.04, 2026-07-09) |
|---|---|
| Controlos CCE pontuados | 20 |
| Matched (dentro da faixa DISA) | **20/20** |
| Taxa de mismatch (≈ MAE categórico) | **0.0%** |
| Gate de aceitação (≤20%) | **PASS** |

*Limitação declarada:* azure-iac, kubernetes, dockerfile e ubuntu **não têm
dataset CCE oficial** — validam-se por recall + baselines (§2, §6), não por MAE.

### 1.2 Concordância **por submétrica** CCSS — 🔲 protocolo

O score final pode estar certo com submétricas erradas (erros que se cancelam).
Validar **cada submétrica individualmente** contra anotação de referência:

**Submétricas (NISTIR 7502 §3.2, implementadas em
[ccss.py](config_assessment/core/ccss.py)):**

| Submétrica | Valores | Peso no score |
|---|---|---|
| AV — Access Vector | Local / Adjacent / Network | 0.395 / 0.646 / 1.000 |
| Au — Authentication | Multiple / Single / None | 0.450 / 0.560 / 0.704 |
| AC — Access Complexity | High / Medium / Low | 0.350 / 0.610 / 0.710 |
| C, I, A — Impacto | None / Partial / Complete | 0.000 / 0.275 / 0.660 |
| GEL — General Exploit Level | N / L / M / H / ND | 0.900–1.000 |
| GRL — General Remediation Level | U / W / H / ND | 0.900–1.000 |

**Protocolo:**
1. Construir o *ground truth*: para uma amostra de N≥30 regras (estratificada
   por target), um anotador com o benchmark CIS/STIG à frente atribui as 8
   submétricas manualmente (sem ver os valores do CASPAR). Idealmente 2
   anotadores → mede-se também concordância inter-anotador (κ de Cohen) para
   estabelecer o teto humano.
2. Extrair os valores do CASPAR da BD:
   ```bash
   sqlite3 ccss.db "SELECT directive, av, au, ac, c, i, a, gel, grl
                    FROM misconfigurations WHERE target='apache-httpd';"
   ```
3. **Comparar por submétrica**, não só o score agregado:

| Submétrica | Concordância exata | κ de Cohen | Matriz de confusão | Erro médio em pontos de score* |
|---|---|---|---|---|
| AV | 🔲 | 🔲 | 🔲 | 🔲 |
| Au | 🔲 | 🔲 | 🔲 | 🔲 |
| AC | 🔲 | 🔲 | 🔲 | 🔲 |
| C / I / A | 🔲 | 🔲 | 🔲 | 🔲 |
| GEL / GRL | 🔲 | 🔲 | 🔲 | 🔲 |

\* recalcular o score com a submétrica corrigida e medir |Δscore| — traduz o
erro categórico em impacto real no resultado (sensibilidade).

**Interpretação de κ:** <0.40 fraco · 0.40–0.60 moderado · 0.60–0.80
substancial · >0.80 quase perfeito (Landis & Koch). Reportar também o intervalo
de confiança (bootstrap, 1000 reamostragens).

### 1.3 Correlação de ordenação — 🔲

Mesmo sem valores absolutos comparáveis, a **ordem** de severidade deve
concordar com a referência: correlação de **Spearman (ρ)** e **Kendall (τ)**
entre o ranking CASPAR e o ranking DISA/CIS das mesmas regras. ρ>0.8 indica
que a ferramenta prioriza como um perito.

### 1.4 Fator de amplificação das chains — declarado como trabalho futuro

O fator por-chain (declarado em `chains.json` com justificação) é uma
**heurística de calibração curada por perito** — a validação empírica da gama
[1.0–1.5] fica explicitamente como trabalho futuro na dissertação. Honestidade
metodológica > número inventado.

---

## 2. Validação funcional

### 2.1 Deteção — recall nas fixtures vulneráveis — ✅ 100% (96/96)

Fixtures deliberadamente inseguras em [test_target/](test_target/), cada uma
com a lista de misconfigurations que um scan correto **tem** de encontrar.
Cobre agora os 10 targets com fixtures dedicadas (docker fica de fora: as
suas regras são maioritariamente estado do host/CLI, não chaves de
`daemon.json`, pelo que uma fixture de config não as exercitaria de forma
honesta):

```bash
python -m scripts.evaluate          # secção "Detection"
```

| Fixture | Target | Recall |
|---|---|---|
| nginx.conf | nginx | 100% |
| azure_storage_vulnerable.tf | azure-iac | 100% |
| pod_vulnerable.yaml | kubernetes | 100% |
| Dockerfile.vulnerable | dockerfile | 100% |
| httpd.conf | apache-httpd | 100% |
| ubuntu_demo/sysctl.conf | ubuntu | 100% |
| ssh_demo/sshd_config | ssh | 100% |
| mysql_demo/my.cnf | mysql | 100% |
| redis_demo/redis.conf | redis | 100% |
| tomcat_demo/tomcat.conf | tomcat | 100% |

### 2.2 Precision e F1 — ✅ 100% (96 TP / 0 FP), corpus limpo fechado

Recall sozinho é enganador (uma ferramenta que grita sempre tem recall 100%).
**Protocolo:** para cada target acima, uma fixture **endurecida** com as
mesmas diretivas cobertas pela fixture vulnerável, todas em valor
conforme/seguro (incluindo as diretivas de *absence rule*, que têm de estar
**presentes** com um valor aceitável, não apenas ausentes). Qualquer finding
num ficheiro endurecido é um **falso positivo**.

```
precision = TP / (TP + FP)      F1 = 2·P·R / (P + R)
```

```bash
python -m scripts.evaluate          # secção "Precision & F1"
```

| Target | Fixture limpa | TP | FP | Precision | Recall | F1 |
|---|---|---|---|---|---|---|
| nginx | `nginx_hardened.conf` | 2 | 0 | 100% | 100% | 100% |
| azure-iac | `azure_storage_hardened.tf` | 5 | 0 | 100% | 100% | 100% |
| kubernetes | `pod_hardened.yaml` | 4 | 0 | 100% | 100% | 100% |
| dockerfile | `Dockerfile.hardened` | 3 | 0 | 100% | 100% | 100% |
| apache-httpd | `httpd_hardened.conf` | 21 | 0 | 100% | 100% | 100% |
| ubuntu | `ubuntu_hardened_demo/sysctl.conf` | 9 | 0 | 100% | 100% | 100% |
| ssh | `ssh_demo/sshd_config_hardened` | 13 | 0 | 100% | 100% | 100% |
| mysql | `mysql_hardened_demo/my.cnf` | 16 | 0 | 100% | 100% | 100% |
| redis | `redis_hardened_demo/redis.conf` | 11 | 0 | 100% | 100% | 100% |
| tomcat | `tomcat_hardened_demo/tomcat.conf` | 12 | 0 | 100% | 100% | 100% |

Reportar recall/precision com **intervalo de confiança de Wilson a 95%** —
com 96 casos o IC é mais estreito do que com as 14 fixtures originais, mas
ainda deve ser reportado explicitamente na tese (não assumir que 100%
empírico implica 100% populacional). O corpus é sintético e propositadamente
worst-case/best-case — não substitui um corpus de configs reais "em estado
selvagem", uma limitação a declarar explicitamente (ver Revisor 1, ponto 6).

### 2.3 Integração ponta a ponta — ✅

```bash
python -m pytest tests/ -q            # ~646 passed
python -m scripts.functional_check    # 13/13 capacidades integradas
```

### 2.4 Deteção de diretivas desconhecidas (3 camadas) — parcial

A Camada 1/2 (determinística) é coberta pelos testes; a **Camada 3 (LLM+RAG,
opt-in)** valida-se com um conjunto de diretivas reais *removidas de propósito*
da KB: mede-se quantas a L3 sinaliza e quão útil é a avaliação (revisão manual,
escala 1–5). 🔲

---

## 3. Fiabilidade

### 3.1 Determinismo do scan — ✅

Dois scans do mesmo input com a mesma KB → scores **idênticos**. Garantido por
desenho (sem LLM no caminho de scoring) e verificado no smoke test
(`determinism` check) + manifesto com `kb sha256` no rodapé do relatório.

```bash
python -m cli.main scan test_nginx.conf > /tmp/a.txt
python -m cli.main scan test_nginx.conf > /tmp/b.txt
diff /tmp/a.txt /tmp/b.txt && echo "DETERMINÍSTICO"
```

### 3.2 Estabilidade do build LLM — 🔲 protocolo

O caminho **não determinístico** é o `plugin add` (extração LLM). Medir a
variância entre N=5 builds independentes do mesmo benchmark:

| Métrica | Definição | Alvo |
|---|---|---|
| Jaccard das regras extraídas | \|A∩B\| / \|A∪B\| entre pares de builds | >0.9 |
| Concordância de submétricas | % de regras comuns com AV/Au/AC/C/I/A iguais | >95% |
| Desvio-padrão do nº de regras | σ(#regras) entre builds | pequeno vs média |

Mitigações já existentes a referir: `--dry-run` (revisão antes de inserir),
validações estruturais, gate MAE, e a via **curada** (kubernetes/dockerfile)
que elimina o LLM por completo.

### 3.3 Robustez a inputs degenerados — 🔲

O scan não pode crashar com lixo. Corpus de teste:

```bash
# ficheiro vazio, binário, encoding errado, 100k linhas, diretivas truncadas
for f in vazio.conf binario.bin latin1.conf gigante.conf; do
  python -m cli.main scan "$f"; echo "exit=$?"
done
```

Critério: **degradação graciosa** — mensagem clara, exit code coerente, nunca
stack trace. (Precedente já corrigido: crash do oscap com stderr não-UTF-8.)

### 3.4 Reprodutibilidade entre máquinas — ✅ parcial

Mesmo input + mesma KB (`kb sha256` igual) → mesmo score em WSL, Docker e
Ubuntu 22.04 nativo. Já observado informalmente; formalizar com uma tabela de
3 ambientes × 3 fixtures. 🔲 tabela

---

## 4. Desempenho e custo de recursos

> **Método comum:** cada medição corre **N≥10 vezes** (1 warm-up descartado),
> reporta **mediana, média ± desvio-padrão e p95**. Máquina documentada (CPU,
> RAM, SO). Usar `hyperfine` para latência e `/usr/bin/time -v` para memória.

### 4.1 Identificar misconfigurations (o caminho quente) — 🔲

**Latência:**
```bash
hyperfine --warmup 1 --runs 10 \
  'python -m cli.main scan test_nginx.conf' \
  'python -m cli.main scan test_target/pod_vulnerable.yaml'
```

**CPU e memória:**
```bash
/usr/bin/time -v python -m cli.main scan test_nginx.conf 2>&1 \
  | grep -E "Maximum resident|User time|System time|Percent of CPU"
```

**Energia** (Intel RAPL; requer acesso a `/sys/class/powercap` ou `perf`):
```bash
sudo perf stat -e power/energy-pkg/ python -m cli.main scan test_nginx.conf
# alternativa sem perf: ler /sys/class/powercap/intel-rapl:0/energy_uj antes/depois
# alternativa por estimativa: energia ≈ tempo_cpu × TDP_médio (declarar como estimativa)
```

**Tabela a preencher (por fixture):**

| Input | Latência mediana | p95 | CPU (user+sys) | RAM pico (RSS) | Energia (J) |
|---|---|---|---|---|---|
| nginx.conf (pequeno) | 🔲 | 🔲 | 🔲 | 🔲 | 🔲 |
| sysctl.conf real | 🔲 | 🔲 | 🔲 | 🔲 | 🔲 |
| pod_vulnerable.yaml | 🔲 | 🔲 | 🔲 | 🔲 | 🔲 |
| config grande (§5) | 🔲 | 🔲 | 🔲 | 🔲 | 🔲 |

Separar **arranque** (import Python + abrir BD) de **scan puro**: correr também
o scan via API interna num processo já quente para isolar o custo fixo do
interpretador — importa para o modo `watch`, onde o processo é persistente.

### 4.2 Adicionar um target/feature novo (extensibilidade) — 🔲

O argumento central da AMiSA é que estender a ferramenta é barato. Medir as
**três vias** de extensão:

| Via | O que medir | Comando |
|---|---|---|
| **LLM build** (`plugin add`) | wall time total, tempo LLM vs parsing, tokens in/out, custo €, nº regras obtidas | `time python -m cli.main plugin add <benchmark.pdf> --target <t>` |
| **Fetch público** (`plugin fetch --then-install`) | idem + tempo de download | `time python -m cli.main plugin fetch ...` |
| **Curada** (kubernetes/dockerfile) | horas-pessoa para escrever as regras à mão | diário de esforço |

**Métricas derivadas (as que interessam na comparação):**
- **custo por regra** = wall time (ou €) / nº de regras inseridas;
- **tempo-até-primeiro-scan**: do benchmark em mão ao primeiro scan a funcionar;
- contraste com o baseline: quanto custa adicionar um benchmark novo ao
  OpenSCAP (escrever OVAL à mão — ordem de dias/semanas, citar literatura) vs
  CASPAR (ordem de minutos + revisão).

| Target | Via | Wall time | Tokens (in/out) | Custo | Regras | Custo/regra |
|---|---|---|---|---|---|---|
| exemplo novo | LLM | 🔲 | 🔲 | 🔲 | 🔲 | 🔲 |
| kubernetes | curada | (horas-pessoa) | — | — | ✓ | 🔲 |

### 4.3 Overhead de inserção de conhecimento — 🔲

Custos de escrita na KB e de ingestão RAG (build-time, uma vez):

```bash
# tamanho da BD antes/depois de um plugin add
ls -l ccss.db; time python -m cli.main plugin add ...; ls -l ccss.db

# ingestão do manual (chunking + índice TF-IDF)
time python -m cli.main plugin manual nginx <manual.pdf>
```

| Operação | Tempo | Δ tamanho em disco | Frequência |
|---|---|---|---|
| Insert de regras (BD) | 🔲 | 🔲 KB | uma vez por target |
| Ingestão manual RAG | 🔲 | 🔲 (chunks + índice) | uma vez por documento |
| Abertura da KB no scan | 🔲 ms | — | todos os scans |

Ponto-chave a demonstrar: o modelo **"ingerir uma vez, consultar sempre"**
empurra o custo para build-time — o overhead **por scan** da RAG é ~0 quando a
Camada 3 está desligada (default), e limitado à consulta TF-IDF quando ligada.
Medir scan com e sem L3 para quantificar exatamente essa diferença.

### 4.4 Modo `watch` (daemon) — 🔲

RSS e CPU em idle vs em rajada de eventos; latência evento→relatório.
```bash
pidstat -r -u -p <pid_do_watch> 5 60   # 5 min de amostragem
```

---

## 5. Escalabilidade — para além das configurações atuais

As fixtures atuais são pequenas. Validar o comportamento com **inputs e KB
maiores do que os que existem no repo**:

### 5.1 Configs sintéticas crescentes — 🔲

Gerar configs válidas com nº crescente de diretivas (misto seguro/inseguro):

```bash
# gerar nginx.conf com N server blocks (script trivial de 20 linhas)
for N in 10 100 1000 5000; do
  python gen_config.py --target nginx --directives $N > /tmp/nginx_$N.conf
  hyperfine --runs 5 "python -m cli.main scan /tmp/nginx_$N.conf"
done
```

| Diretivas | Latência | RAM pico | Findings |
|---|---|---|---|
| 10 / 100 / 1000 / 5000 | 🔲 | 🔲 | 🔲 |

**Análise:** ajustar a curva (esperado ~linear no nº de diretivas; o lookup na
KB é indexado). Reportar o expoente do fit e o ponto onde a latência deixa de
ser interativa (>2 s).

### 5.2 KB crescente — 🔲

O scan degrada com mais targets/regras na BD? Duplicar sinteticamente as
regras (targets fantasma) até 10× e repetir o scan da mesma fixture:

| Regras na KB | 488 (atual) | ~1000 | ~5000 |
|---|---|---|---|
| Latência do mesmo scan | 🔲 | 🔲 | 🔲 |

### 5.3 Diversidade real — 🔲

Correr sobre configs reais públicas (nginx/apache de projetos open-source,
manifests K8s de repositórios populares) e reportar: % de ficheiros parseados
sem erro, findings por ficheiro, diretivas desconhecidas sinalizadas. Mede
**generalização** para fora das fixtures construídas por nós.

---

## 6. Comparação com baselines (mesmo input, métricas lado a lado)

```bash
python -m scripts.baseline_compare --oscap
```

### 6.1 Capacidades e resultados — ✅ (qualitativo + contagens)

| Métrica | CASPAR | Trivy | OpenSCAP |
|---|---|---|---|
| Findings em `azure_storage_vulnerable.tf` | 9 · score 8.5/10 | 13 · labels | n/a |
| Findings em `Dockerfile.vulnerable` | 4 · score 9.0/10 | 5 · labels | n/a |
| Ubuntu OS (controlos sobreponíveis) | 18 regras, score+narrativa | n/a | 24 fail/1 pass (binário) |
| Tipo de veredicto | **score CCSS 0–10 reproduzível + narrativa** | severidade fixa | pass/fail |
| Avalia | ficheiro de config | ficheiro | estado do sistema vivo |
| Extensível a benchmark novo | minutos (LLM) | requer código Go/rego | escrever OVAL à mão |

*Blind spots são bidirecionais:* o Trivy apanhou `https_traffic_only_enabled`
que o build LLM mapeou pelo sinónimo `secure_transfer_required`; o CASPAR dá
score e narrativa onde os outros dão um label fixo.

### 6.2 Desempenho lado a lado — 🔲

Mesma máquina, mesmo input, mesmo protocolo do §4.1:

| Métrica | CASPAR | Trivy | OpenSCAP |
|---|---|---|---|
| Latência mediana (mesmo .tf) | 🔲 | 🔲 | — |
| RAM pico | 🔲 | 🔲 | 🔲 |
| CPU total | 🔲 | 🔲 | 🔲 |
| Energia (J) | 🔲 | 🔲 | 🔲 |

> Nota de equidade: o Trivy é um binário Go, o CASPAR é Python — declarar que
> a comparação de recursos mede as *implementações*, não as *metodologias*.

---

## 7. Tradeoffs (o que se ganha ↔ o que se paga)

| Decisão de desenho | Ganho | Custo | Evidência |
|---|---|---|---|
| LLM só no **build-time**, nunca no scan | scan determinístico, offline, rápido, auditável | extração pode falhar sinónimos (caso `https_traffic_only_enabled`); cobertura congelada até rebuild | §3.1, §6.1 |
| Score CCSS + narrativa vs pass/fail | priorização fina, explicabilidade, reprodutível por manifesto | exige submétricas corretas → precisa da validação §1.2; mais caro de construir que um label | §1.1–1.2 |
| Avaliar **ficheiro** e não sistema vivo | reproduzível, funciona em CI/CD e pré-deploy, sem agente | não vê estado runtime (permissões, módulos carregados) — domínio do OpenSCAP, fora de scope **por design** | §6.1 |
| Extração LLM vs regras curadas | minutos vs dias para um target novo | não-determinístico, custo de tokens, exige gate MAE + revisão | §3.2, §4.2 |
| RAG "ingerir uma vez, consultar sempre" | overhead por scan ≈ 0 com L3 off | custo de disco por manual; conhecimento desatualiza até re-ingestão | §4.3 |
| Camada 3 (LLM) **opt-in** | default 100% determinístico | diretivas desconhecidas ficam sem avaliação por omissão | §2.4 |
| Fator de amplificação por-chain curado | captura risco composto que scanners atómicos ignoram | heurística sem validação empírica da gama (declarado) | §1.4 |
| Modelo temporal simplificado (GEL/GRL × BaseScore) | nunca desconta mais de ~19% — não subestima risco; API simples | desvia da equação oficial §3.2.2 (que desconta até ~50%+ com remediação forte); exemplo temporal do NISTIR não replica via API | §1.0 |
| Python + SQLite | extensível, legível, zero infra | mais lento e pesado que um binário Go (Trivy) | §6.2 |

Cada linha desta tabela deve aparecer na dissertação com o número que a
sustenta — um tradeoff sem medição é uma opinião.

---

## 8. Métricas estatísticas — referência rápida

| Métrica | Fórmula / método | Onde se usa |
|---|---|---|
| Taxa de mismatch (MAE categórico) | mismatched / scored | §1.1 |
| MAE numérico | mean(\|score − referência\|) | §1.2 (sensibilidade) |
| Recall | TP / (TP+FN) | §2.1 |
| Precision · F1 | TP/(TP+FP) · 2PR/(P+R) | §2.2 |
| IC de proporções | Wilson 95% (não normal — amostras pequenas) | §1.1, §2 |
| κ de Cohen | concordância corrigida pelo acaso | §1.2 (submétricas, inter-anotador) |
| Spearman ρ / Kendall τ | correlação de rankings | §1.3 |
| Jaccard | \|A∩B\|/\|A∪B\| | §3.2 (builds LLM) |
| Mediana · p95 · média±σ | sobre N≥10 corridas, warm-up descartado | §4 |
| Bootstrap (1000×) | IC de κ e de médias | §1.2, §4 |
| Fit da curva de escala | regressão latência vs tamanho (reportar R²) | §5.1 |
| Teste de Mann-Whitney U | comparar distribuições de latência CASPAR vs Trivy | §6.2 |

**Regras de reporte:** nunca uma média sem dispersão; nunca uma proporção sem
N e IC; nunca uma comparação de tempos sem a máquina e o nº de corridas.

---

## 9. Ordem de execução sugerida

```bash
# já implementado (correr primeiro — são os números-âncora)
python -m pytest tests/ -q                    # ~646 passed
python -m scripts.functional_check            # 13/13
python -m scripts.evaluate                    # KB · MAE 0% · recall 100% · precision/F1 100%
python -m scripts.baseline_compare --oscap    # Trivy + OpenSCAP

# por implementar/medir (por ordem de valor para a tese)
# 1. §4.1  latência/CPU/RAM/energia do scan      (hyperfine + time -v + RAPL)
# 2. §6.2  o mesmo para Trivy/OpenSCAP           (comparação de desempenho)
# 3. §4.2  custo de adicionar um target novo     (o argumento central da AMiSA)
# 4. §1.2  concordância por submétrica + κ       (rigor científico do scoring)
# 5. §5    escalabilidade sintética              (limites da abordagem)
# 6. §3.2  estabilidade do build LLM (5 builds)  (fiabilidade da via LLM)
```

---

*Documento de apoio à secção de avaliação da dissertação (metodologia AMiSA /
ferramenta CASPAR). Resultados ✅ obtidos em Ubuntu 22.04 real, 2026-07-09.*
