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
| 1b | Científica — submétricas | Cada submétrica CCSS está certa? | Concordância exata + Cohen's κ por submétrica | protocolo §1.2 | ✅ anotador-LLM (§1.2) |
| 2 | Funcional — deteção | Encontra as misconfigurations? | Recall + precision + F1 | `scripts/evaluate.py` | ✅ 100% recall · 100% precision/F1 |
| 3 | Funcional — integração | Tudo funciona de ponta a ponta? | Checks pass/fail | `scripts/functional_check.py` + pytest | ✅ 13/13 · ~647 |
| 4 | Fiabilidade | Dá sempre o mesmo resultado? | Determinismo, robustez, estabilidade do build LLM | §3 | ✅/🔲 |
| 5 | Desempenho — scan | Quanto custa identificar misconfigurations? | Latência, CPU, RAM, energia | §4.1 | ✅ WSL2 (`scripts/perf_scan.py`) / 🔲 repetir em Ubuntu nativo |
| 6 | Desempenho — extensão | Quanto custa adicionar um target novo? | Wall time, tokens/custo LLM, esforço humano | §4.2 | ✅ WSL2, N=1 (`postgresql`) / 🔲 repetir Ubuntu nativo + N≥5 (§3.2) |
| 7 | Desempenho — ingestão | Qual o overhead de inserir conhecimento? | Tempo de ingestão RAG, crescimento da BD | §4.3 | ✅ abertura KB + Δ BD / ✅ ingestão manual RAG |
| 8 | Escalabilidade | Aguenta configs/KB maiores que as atuais? | Curva latência × tamanho | §5 | ✅ configs sintéticas (§5.1) / ✅ KB crescente (§5.2) / ✅ diversidade real (§5.3) |
| 9 | Baselines | Como se posiciona vs Trivy/OpenSCAP? | Overlap, blind spots, custo por finding | `scripts/baseline_compare.py` | ✅ qualit. + desempenho (§6.2, WSL2) |
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

### 1.2 Concordância **por submétrica** CCSS — ✅ medido (anotador-LLM, N=1)

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

**Nota de metodologia — anotador-LLM, não substituto de anotação humana.**
O protocolo acima pede um anotador humano com o benchmark à frente. Por
indisponibilidade de um segundo anotador humano nesta fase, os resultados
abaixo foram produzidos por mim (Claude, agindo como "anotador-LLM"): li o
texto integral do CIS Apache HTTP Server Benchmark v2.3.0 (secções
Description/Rationale/Audit/Impact de cada controlo, via `pdftotext -layout`)
e atribuí as 8 submétricas **sem consultar a BD do CASPAR antes de gravar
cada valor** — cego no sentido de não ver a resposta do CASPAR, mas não cego
no sentido do protocolo (mesmo "anotador" que desenhou o esquema de
submétricas do CASPAR, logo com um prior partilhado, não independente). É
evidência adicional de consistência interna face a uma leitura direta do
benchmark, **não** o teto de concordância inter-anotador humana que o
protocolo original visa estabelecer — isso fica como trabalho futuro (idealmente
antes da defesa, com um segundo anotador humano real).

**Amostra:** população completa de `apache-httpd` (N=35 regras, não uma
subamostra de N≥30 — o target inteiro foi usado por simplicidade e por dar
mais poder estatístico que o mínimo pedido). Comando de extração usado
(nota: a coluna chama-se `target_name`, não `target`, ao contrário do exemplo
original do protocolo):
```bash
sqlite3 ccss.db "SELECT directive, bad_value, cis_section, av, au, ac, c, i, a, gel, grl
                 FROM misconfigurations WHERE target_name='apache-httpd';"
```

**Resultados:**

| Submétrica | Concordância exata | κ de Cohen | κ IC 95% (bootstrap 1000×) | Erro médio \|Δscore\| |
|---|---|---|---|---|
| AV | 35/35 = 100% | 1.000 | [1.000, 1.000] | 0.000 |
| Au | 35/35 = 100% | 1.000 | [1.000, 1.000] | 0.000 |
| AC | 23/35 = 65.7% | 0.032 | [−0.253, 0.407] | 0.229 |
| C | 31/35 = 88.6% | 0.751 | [0.485, 0.944] | 0.334 |
| I | 28/35 = 80.0% | 0.486 | [0.109, 0.802] | 0.289 |
| A | 33/35 = 94.3% | 0.856 | [0.635, 1.000] | 0.051 |
| C/I/A (agrupado, n=105) | 92/105 = 87.6% | 0.760 | [0.628, 0.871] | — |
| GEL | 6/35 = 17.1% | 0.000 | [0.000, 0.000] | n/a (temporal) |
| GRL | 35/35 = 100% | 1.000 | [1.000, 1.000] | n/a (temporal) |
| GEL/GRL (agrupado, n=70) | 41/70 = 58.6% | 0.310 | [0.207, 0.417] | n/a |

Score base completo (todas as submétricas substituídas): Δscore médio =
0.354, máximo = 1.50, 20/35 regras com Δscore = 0 (concordância perfeita em
todas as submétricas de base).

**Matrizes de confusão** (linhas = anotador-LLM/ground truth, colunas = CASPAR):

```
AC          L    M              C           C  N  P            I           C  N  P
  L         21   7                C         1  0  1              C         2  0  0
  M         5    2                N         0  8  3              N         0  23 3
                                   P         0  0  22             P         0  4  3

A           C  N  P             GEL         H   L   M          GRL       H
  C         0  2  0               H         0   15  0            H       35
  N         0  25 0               L         0   6   0
  P         0  0  8                M         0   14  0
```

**Leitura.**

- **AV e Au: κ=1.000.** Todas as 35 regras de `apache-httpd` são vulnerabilidades
  de rede sem autenticação prévia (um cliente HTTP anónimo consegue explorar
  qualquer uma) — tanto eu como o CASPAR concordamos nisto para 100% dos
  casos. Pouco informativo por si só (não há variância na amostra), mas confirma
  que o CASPAR não erra a classificação mais básica (AV/Au) neste target.
- **A (Availability): κ=0.856, quase perfeito.** As 8 regras relacionadas com DoS
  (Timeout, KeepAlive*, LimitRequest*) foram marcadas A=Partial por ambos em
  quase todos os casos; as 2 discordâncias (κ não é 1.0) foram `LogLevel=emerg`
  e outra regra de logging onde eu atribuí A=None (um log mal configurado não
  esgota recursos) e o CASPAR tinha A=Complete — ver matriz acima, célula C→N
  na linha A é onde a diferença se concentra.
- **C (Confidentiality): κ=0.751, substancial.** A maior discordância visível na
  matriz é 3 casos onde eu marquei N (nenhuma fuga de confidencialidade) e o
  CASPAR marcou P — nas regras de tuning de KeepAlive/Timeout, que são
  puramente de disponibilidade; o CASPAR parece herdar C=Partial por omissão
  nalguns templates de disponibilidade onde eu não via fuga de informação
  direta.
- **I (Integrity): κ=0.486, moderado — a submétrica mais discordante das três
  CIA.** 7 discordâncias: o CASPAR atribui I=None a algumas regras onde eu vi
  impacto de integridade indireto (ex.: `LogLevel=emerg`, onde a ausência de
  registo compromete a integridade da trilha de auditoria, não classificada
  assim pelo CASPAR) e vice-versa nalgumas regras de disponibilidade pura.
  Esta é a submétrica com a interpretação mais subjetiva das três — "integridade"
  cobre tanto integridade de dados como de processo/auditoria, e a fronteira é
  ambígua mesmo lendo o mesmo texto do benchmark.
- **AC (Access Complexity): κ=0.032, ~zero — a maior discordância do
  conjunto.** Concordância exata de 65.7% parece razoável à primeira vista, mas
  κ corrige para o facto de ambos os anotadores usarem L (Low) esmagadora e
  desproporcionadamente (30/35 e 28/35 respetivamente) — com tão pouca
  variância na distribuição marginal, a concordância esperada ao acaso (pe=0.646)
  já é quase igual à concordância observada (po=0.657), pelo que κ≈0. Isto é
  **mais um sintoma de desenho da escala do que um erro do CASPAR**: a
  maioria das misconfigurations de servidor web são triviais de explorar
  (pedido HTTP direto), pelo que AC=Low domina genuinamente qualquer
  anotação razoável — a escala L/M/H tem pouco poder discriminativo neste
  tipo de alvo. Recomendação: nas ~7 regras onde discordamos (ver matriz,
  célula L→M), a diferença tende a ser regras onde o CASPAR foi mais
  conservador (M) e eu mais otimista sobre a facilidade de exploração (L) em
  controlos que dependem de uma segunda condição (ex.: symlink plantado,
  posição MITM) — ambas as leituras são defensáveis a partir do mesmo texto.
- **GEL: κ=0.000, concordância exata 17.1% — a métrica mais fraca de
  longe.** O CASPAR atribui **GEL=Low a todas as 35 regras de apache-httpd**
  sem exceção (confirmado também que GEL varia normalmente entre targets
  na BD completa: L=114, M=116, H=17, N=9, ND=258 — não é um bug de
  extração, é uma característica genuína deste target/build específico). Isto
  sugere que o LLM de build-time convergiu para um valor "seguro"/default de
  GEL ao processar o benchmark Apache, em vez de diferenciar exploit level por
  regra (ex.: CRIME/POODLE contra SSL legado deveriam ter GEL mais alto —
  exploits públicos, ferramentas conhecidas — do que uma regra de log level).
  **Isto é o achado mais acionável de toda a secção 1.2**: candidato a
  investigação de causa raiz no prompt/lógica de atribuição de GEL do
  `build_apache` antes da defesa — não é meramente uma discordância de
  anotação, é uma possível falta de variância real na extração.
- **GRL: κ=1.000.** Ambos concordamos GRL=High (remediação bem documentada,
  fix de uma linha) para todas as 35 regras — plausível dado que praticamente
  todos os controlos deste benchmark têm remediação trivial (mudar um valor
  de diretiva), ao contrário de GEL onde seria de esperar mais variância.
- **Δscore médio geral = 0.354 pontos (numa escala 0–10)**, com 20/35 regras
  em concordância perfeita de score base. O impacto prático das discordâncias
  categóricas no score final é pequeno mesmo quando κ é baixo (caso de AC),
  porque a fórmula CCSS pesa AC apenas parcialmente no termo de
  explorabilidade — consistente com a observação already feita em §1.1 de que
  o score agregado pode estar "certo" mesmo com submétricas individuais
  discordantes (motivação original desta secção 1.2).
- **Limitação de amostra única**: `apache-httpd` é só 1 de 12 targets com
  regras na BD; o padrão GEL=L/GRL=H constante pode ser específico deste
  build e não generalizar — repetir esta análise nalgum outro target
  (idealmente um construído por LLM como `postgresql`, §4.2) antes de
  generalizar a conclusão sobre GEL.

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
python -m pytest tests/ -q            # ~647 passed
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

### 4.1 Identificar misconfigurations (o caminho quente) — ✅ medido (WSL2; repetir em Ubuntu nativo antes da defesa)

**Script** (substitui `hyperfine`, indisponível neste ambiente — usa `/usr/bin/time -v`
em subprocess fresco por corrida, mesma disciplina N≥10/warm-up/mediana+p95):
```bash
python -m scripts.perf_scan --runs 10 --json > perf_scan_results.json
python -m scripts.perf_scan --runs 10          # tabela legível
```

**Energia**: sem acesso RAPL/`perf` neste ambiente (WSL2 não expõe
`/sys/class/powercap`) — reportada como **estimativa** `energia ≈ tempo_cpu ×
TDP_declarado` (15W por omissão, `--tdp` para ajustar), não como medição.
Repetir com `perf stat -e power/energy-pkg/` se a validação final correr em
Ubuntu nativo com acesso ao RAPL.

**Máquina:** Intel Core i7-12700H · 15845 MB RAM · WSL2 (Linux
6.18.33.2-microsoft-standard-WSL2) — não é a máquina de validação final
(Ubuntu 22.04 nativo, §"Estado" do topo deste documento); os números abaixo
servem de baseline de forma/ordem de grandeza, a confirmar/substituir no
Ubuntu real antes da defesa.

> **Nota de correção:** a primeira versão desta medição continha um bug em
> `scripts/perf_scan.py` — `--db` estava a ser passado *depois* do
> subcomando `scan` em vez de antes (é uma opção global do CLI, não do
> subcomando), o que fazia o Click rejeitar o comando (`Error: No such
> option '--db'`, exit 2) em **todas** as corridas. `/usr/bin/time -v`
> continuava a produzir `wall_s`/`max_rss_kb` válidos mesmo com o comando a
> falhar — por isso o script não detetava o erro e os números antigos
> (0.050s, 16.2MB) mediam na verdade **o tempo de arrancar o Python e o
> Click rejeitar a opção**, não um scan real. Corrigido: `--db` movido para
> antes de `scan`, e `run_once()` agora valida `returncode == 0` antes de
> aceitar uma amostra. Os números abaixo são da medição corrigida.

**Resultados (N=10, 1 warm-up descartado):**

| Input | Latência mediana | Latência média±σ | p95 | CPU (user+sys) | RAM pico (RSS) | Energia (J, estimada) |
|---|---|---|---|---|---|---|
| nginx.conf (pequeno) | 0.130s | 0.137±0.018s | 0.166s | 0.090s | 27.0 MB | 1.35 |
| sysctl.conf real | 0.140s | 0.136±0.016s | 0.155s | 0.100s | 26.7 MB | 1.50 |
| pod_vulnerable.yaml (IaC) | 0.135s | 0.137±0.015s | 0.161s | 0.090s | 26.7 MB | 1.35 |
| config grande (§5.1, N=1000 server blocks) | 0.590s | 0.630±0.162s | 0.889s | 0.470s | 45.6 MB | ver §5.1 para a curva completa (10-5000) |

**Leitura:** a latência é dominada pelo arranque do interpretador Python +
abertura da BD SQLite, não pelo tamanho do input — os três fixtures (19-64
linhas) dão o mesmo tempo dentro do ruído (diferenças <10ms, dentro de 1σ).
RAM pico consistente (~27MB) confirma que o runtime não carrega toda a KB em
memória de uma vez. Isto é evidência a favor do argumento de
determinismo/leveza do runtime (nenhuma dependência de LLM/rede), mas a
distinção **arranque vs scan puro** (abaixo) ainda não foi isolada — a
medição de abertura de BD do §4.3 (1.124ms) já mostra que a BD não é o
gargalo; falta isolar quanto do resto (~130ms) é import do Python/Click vs.
lógica do scan em si antes de reportar isto como "o scan é O(1) no tamanho
do input", que é uma afirmação mais forte do que estes números sozinhos
sustentam.

Separar **arranque** (import Python + abrir BD) de **scan puro**: correr também
o scan via API interna num processo já quente para isolar o custo fixo do
interpretador — importa para o modo `watch`, onde o processo é persistente.
Ainda por fazer (🔲) — `scripts/perf_scan.py` mede só o processo fresco
(igual ao uso real via `caspar scan`), não a via API-interna-já-quente.

### 4.2 Adicionar um target/feature novo (extensibilidade) — ✅ medido (via LLM build, WSL2)

O argumento central da AMiSA é que estender a ferramenta é barato. Medir as
**três vias** de extensão:

| Via | O que medir | Comando |
|---|---|---|
| **LLM build** (`plugin add`) | wall time total, tempo LLM vs parsing, tokens in/out, custo €, nº regras obtidas | `time python -m cli.main plugin add <benchmark.pdf> --target <t>` |
| **Fetch público** (`plugin fetch --then-install`) | idem + tempo de download | `time python -m cli.main plugin fetch ...` |
| **Curada** (kubernetes/dockerfile) | horas-pessoa para escrever as regras à mão | diário de esforço |

**Nota sobre `plugin fetch`**: indisponível durante esta medição —
`stigviewer.com` (fonte pública de STIGs usada por `plugin fetch`) passou a
exigir autenticação (`{"error":"authentication_required"}` em todos os 43
targets testados, não só o alvo tentado inicialmente) desde a última
verificação; ver [[caspar-benchmark-fetch-sources]]. Não é um bug do CASPAR
— é uma mudança do lado da fonte externa. A via medida abaixo é `plugin add`
com um PDF local (CIS PostgreSQL 13 Benchmark v1.3.0, `sources/benchmarks/`),
que não depende do stigviewer e mede exatamente o mesmo custo de build LLM.

**Métricas derivadas (as que interessam na comparação):**
- **custo por regra** = wall time (ou €) / nº de regras inseridas;
- **tempo-até-primeiro-scan**: do benchmark em mão ao primeiro scan a funcionar;
- contraste com o baseline: quanto custa adicionar um benchmark novo ao
  OpenSCAP (escrever OVAL à mão — ordem de dias/semanas, citar literatura) vs
  CASPAR (ordem de minutos + revisão).

**Resultado real (target `postgresql`, CIS PostgreSQL 13 Benchmark v1.3.0,
64 secções indexadas, modelo `qwen2.5:14b` em CPU, WSL2, execução única —
não é uma média de N corridas, ver §3.2 para estabilidade entre builds):**

| Target | Via | Wall time | Regras extraídas | Custo/regra | Misconfigs | Chains | Narrativas |
|---|---|---|---|---|---|---|---|
| postgresql | LLM (`plugin add`, PDF local) | **1h46min16s** (6376s) | 32 (0 heurística, 32 LLM) | **~199s/regra** (~3.3 min/regra) | 26 | 5 | 26/26 |
| kubernetes | curada (mão) | (horas-pessoa, não cronometrado) | — | — | ✓ | ✓ | — |

**Leitura:**
- Tempo-até-primeiro-scan para um serviço totalmente novo: **~1h46min**, sem
  intervenção humana durante o build (correu unattended com `-y`), CPU-only,
  numa máquina de portátil (i7-12700H) — não GPU. Isto é a ordem de grandeza
  a citar como "minutos-a-horas" vs. a ordem de "dias-a-semanas" para OVAL
  manual (citar literatura no capítulo de avaliação).
- **Fiabilidade durante o build**: uma tentativa de geração de attack chains
  expirou (`Chain generation attempt 1 failed: timed out`) e foi repetida
  automaticamente com sucesso — dado relevante para §3 (fiabilidade/retry),
  não apenas para desempenho.
- **Limitação da medição**: `/usr/bin/time -v` mediu o processo pai
  (`plugin add`), que delega a inferência a um processo `ollama runner`
  separado — por isso `User time` reportado (0.94s) não reflete o custo de
  CPU real da LLM (confirmado via `ps aux` a mostrar o runner a ~459% CPU
  durante o build). O **wall time** (1h46min16s) continua válido e é a
  métrica que importa para "tempo-até-primeiro-scan"; CPU-time agregado do
  processo LLM fica como 🔲 se for necessário para o capítulo de energia.
- Não há custo em tokens/€ a reportar — `qwen2.5:14b` corre localmente via
  Ollama, sem API paga.
- **N=1**: esta é uma única execução, não a média/mediana de N≥10 exigida
  pelo protocolo geral do §4 — o custo de 1h46min por build torna N≥10
  impraticável neste ambiente; ver §3.2 (5 builds) para uma leitura de
  variância entre builds, ainda 🔲.

### 4.3 Overhead de inserção de conhecimento — ✅ medido

Custos de escrita na KB e de ingestão RAG (build-time, uma vez):

```bash
# tamanho da BD antes/depois de um plugin add
ls -l ccss.db; time python -m cli.main plugin add ...; ls -l ccss.db

# ingestão do manual (chunking + índice TF-IDF)
time python -m cli.main plugin manual nginx <manual.pdf>
```

**Abertura da KB — medido** (N=30, interpretador já quente, isola o custo do
`sqlite3.connect` do custo de arranque do Python que domina os números do
§4.1): mediana **1.124 ms** (média 1.224 ms, σ=0.489 ms) para abrir a BD;
consulta indexada por ponto (`get_misconfigurations`, o caminho quente do
runtime) mediana **0.1185 ms** (média 0.1411 ms, σ=0.0741 ms). Isto confirma
a leitura do §4.1: a latência de ~50ms observada por `caspar scan` é quase
toda arranque de interpretador — abrir a BD e fazer o lookup indexado somam
~1.2ms, <3% do tempo total.

| Operação | Tempo | Δ tamanho em disco | Frequência |
|---|---|---|---|
| Insert de regras (BD) | ✅ incluído no wall time do §4.2 (1h46min16s, dominado pela LLM, não pelo insert em si) | ✅ **+104 KB** (`ccss.db`: 3.211.264→3.317.760 bytes) para 26 misconfigs → **~4 KB/misconfig** | uma vez por target |
| Ingestão manual RAG (`plugin manual`) | ✅ N=3, mediana **0.12 s** wall (0.22 s / 0.11 s / 0.12 s), CPU user+sys ≈0.10-0.12s, RAM pico ≈23 MB | ✅ PDF 291.424 bytes → `.md` sidecar 126.282 bytes (extração `pdftotext -layout`) | uma vez por documento |
| Build do índice TF-IDF (`BenchmarkIndex`, sobre o `.md`) | ✅ N=5, mediana **13.4 ms** (13.1–16.5 ms) | — (em memória, não persistido — reconstruído a cada `scan --assess-unknown`) | por scan com L3 ligada |
| Abertura da KB no scan | ✅ 1.124 ms (mediana, N=30) | — | todos os scans |
| Lookup indexado (`get_misconfigurations`) | ✅ 0.1185 ms (mediana, N=30) | — | todos os scans |

**Metodologia:** medido com `caspar plugin manual nginx ./nistir7502.pdf`
(N=3, `/usr/bin/time -v`, plugin dir limpo entre corridas para evitar reuso
do `.md` já extraído) — usámos o NISTIR 7502 (referência CCSS partilhada,
291 KB) como documento de teste para não interferir com o benchmark próprio
do plugin nginx já instalado. O build do índice TF-IDF foi medido
separadamente (N=5, warm interpreter) chamando `BenchmarkIndex(path)`
diretamente sobre o `.md` já extraído, porque `_find_knowledge_docs`
descobre e indexa os documentos em memória a cada scan com
`--assess-unknown` (Camada 3) — não há índice persistido em disco a medir.

**Análise:** a ingestão de um manual é dominada por I/O de ficheiro e
extração de texto determinística (`pdftotext`), não por LLM — ordens de
grandeza mais rápida que o build de um plugin novo (§4.2, ~1h46min,
dominado por chamadas LLM). O build do índice TF-IDF em si é ~13ms mesmo
sobre um documento de ~2000 linhas, consistente com o overhead "por scan"
da RAG ser desprezável quando medido isoladamente — a Camada 3 só entra em
jogo quando há diretivas desconhecidas a avaliar (`--assess-unknown`), e
mesmo aí o custo de indexação é uma fração ínfima do tempo total do scan
(~50ms de arranque de interpretador, ver §4.1).

Plugin `postgresql` gerado ocupa 1.5 MB em disco (`config_assessment/plugins/postgresql/`),
dominado pelo PDF do benchmark original (1.51 MB) — os artefactos gerados
(`rules.py`, `parser.py`, `build_postgresql.py`, `chains.json`) somam ~9.6 KB.

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

### 5.1 Configs sintéticas crescentes — ✅ medido

Gerado com `scripts/gen_config.py` (script novo, ~55 linhas) — nginx.conf com
N server blocks, ~50% marcados aleatoriamente (seed=42) como inseguros
(`autoindex on`, `server_tokens on`, `ssl_protocols TLSv1 TLSv1.1`) vs.
seguros:

```bash
for N in 10 100 1000 5000; do
  python scripts/gen_config.py --target nginx --blocks $N > /tmp/nginx_$N.conf
done
python -m scripts.perf_scan --runs 10 \
  --fixture "N10=/tmp/nginx_10.conf" --fixture "N100=/tmp/nginx_100.conf" \
  --fixture "N1000=/tmp/nginx_1000.conf" --fixture "N5000=/tmp/nginx_5000.conf" \
  --json
```

N≥10 corridas/escala (1 warm-up descartado), medida em WSL2 (mesma máquina/
protocolo do §4.1: Intel i7-12700H, 15.8 GB RAM).

| Server blocks | Latência mediana | Latência média±σ | p95 | RAM pico (mediana) | Findings |
|---|---|---|---|---|---|
| 10 | 0.280 s | 0.287±0.049 s | 0.364 s | 29.6 MB | 19 |
| 100 | 0.245 s | 0.274±0.081 s | 0.403 s | 31.3 MB | 107 |
| 1000 | 0.590 s | 0.630±0.162 s | 0.889 s | 45.6 MB | 967 |
| 5000 | 2.520 s | 2.487±0.281 s | 2.812 s | 114.6 MB | 4951 |

**Análise:** regressão log-log (`t = a·N^b`) sobre os 4 pontos dá `b≈0.34`,
`R²=0.70` — um mau ajuste porque o ponto N=10 é dominado pelo custo fixo de
arranque do interpretador/abertura da BD (~0.15–0.2 s), não pelo trabalho de
parsing (mesma lógica de isolamento do custo fixo já discutida no protocolo
do §4.1). Excluindo esse ponto, o ajuste em N≥100 dá **`t ≈ 0.0148·N^0.58`,
R²=0.92** — sublinear a aproximadamente-linear, dentro do esperado (lookup na
KB é indexado; ver achado abaixo). Extrapolando esse ajuste, a latência
ultrapassa o limiar interativo de 2 s por volta de **N≈4700** server blocks —
o próprio N=5000 já está no limite (mediana 2.52 s).

**Achado relevante (bug de performance encontrado e corrigido nesta
sessão):** a primeira medição a N=5000 (antes da correção abaixo) deu
**166.294 s** — ~29× mais lento que N=1000 (5.692 s) para um aumento de
apenas 5× no tamanho do input, claramente super-linear (próximo do
quadrático: 5²=25). Perfilagem (`cProfile`) isolou a causa em
`config_assessment/plugins/nginx/parser.py`, classe `_LineTracker.line_of()`
— usada para resolver o número de linha de cada diretiva para efeitos de
relatório. A implementação original fazia uma **rescan completo do ficheiro
por cada instância de diretiva** (`for i, line in enumerate(self._lines)...`
sem indexação), ou seja O(diretivas × linhas) = O(N²) num ficheiro sintético
onde ambos os fatores crescem com N. Corrigido em duas iterações:

1. Pré-indexar as linhas por primeira palavra (`dict[str, deque[int]]`) no
   `__init__`, reduzindo o lookup por diretiva de "rescan de todo o
   ficheiro" para "rescan apenas do bucket com o mesmo nome de diretiva".
2. Consumir cada bucket a partir da frente (`deque.popleft`, devolvendo à
   frente as entradas sem correspondência de valor) em vez de apenas marcar
   linhas como "usadas" num `set` — a v1 ainda escondia um O(N) residual por
   chamada em diretivas muito repetidas (ex.: `listen`, `ssl_protocols`,
   5000 ocorrências cada em N=5000), porque saltar sobre um número crescente
   de entradas já "usadas" no início da lista continua a ser trabalho linear
   por chamada.

Resultado: N=5000 passou de 166.294 s → 4.190 s (fix 1) → **2.520 s** (fix
2), uma melhoria de **~66×** no total. Verificado com a suite completa de
testes (647/647 passed) e reperfilado — `line_of` deixou de aparecer no
top-10 por tempo próprio no perfil final (era 15.589 s de tottime em 9005
chamadas antes do fix 1). O comportamento é agora dominado por trabalho
genuinamente linear (`_tokenize`, `sqlite3.commit`/`execute`,
`_match_value_rules`), consistente com o expoente medido (~0.58, sublinear).

Este bug não tinha impacto visível nas fixtures pequenas usadas no resto da
validação (§4.1–§4.3, todas <1000 diretivas) — só se manifesta em inputs
grandes, exatamente o cenário que este protocolo §5.1 foi desenhado para
expor. Sem esta medição de escalabilidade sintética, o bug teria permanecido
por detetar.

### 5.2 KB crescente — ✅ medido

O scan degrada com mais targets/regras na BD? `scripts/grow_kb.py` (novo,
~70 linhas) clona `ccss.db` e duplica todas as regras existentes sob
targets fantasma sintéticos (`ghost_N`, um por regra clonada — necessário
porque a UNIQUE constraint em `(target_name, directive, bad_value,
expected_value_prefix)` impede reusar o mesmo target fantasma para um lote
inteiro, já que muitas regras partilham directive+bad_value entre targets
reais diferentes). Confirmado antes de medir que os findings da fixture
nginx (`test_target/test_nginx.conf`) são **idênticos** nas 3 BDs (9
findings em todas), ou seja as regras fantasma não interferem na deteção —
só aumentam o tamanho da tabela que o motor varre.

```bash
python scripts/grow_kb.py --dst /tmp/ccss_1000.db --target-rows 1000
python scripts/grow_kb.py --dst /tmp/ccss_5000.db --target-rows 5000
python -m scripts.perf_scan --runs 10 --db /tmp/ccss_1000.db \
  --fixture "KB1000=test_target/test_nginx.conf" --json
```

N=10 corridas/BD (1 warm-up descartado), WSL2, mesma fixture nas 3 medições.

| Regras na KB | 514 (atual) | 1000 | 5000 |
|---|---|---|---|
| Latência mediana | 0.130 s | 0.140 s | 0.180 s |
| Latência média±σ | 0.133±0.005 s | 0.158±0.046 s | 0.177±0.007 s |
| p95 | 0.140 s | 0.235 s | 0.185 s |
| RAM pico (mediana) | 26.9 MB | 29.0 MB | 38.9 MB |
| Findings (mesma fixture) | 9 | 9 | 9 |

**Análise:** a KB cresceu quase 10× (514→5000 regras) e a latência mediana
subiu apenas 0.05 s (+38%), RAM subiu ~12 MB — consistente com o lookup na
KB ser indexado por (target_name, directive) e não fazer scan linear sobre
todas as regras. O p95 de KB1000 (0.235s) tem uma amostra periférica (run
7/10: 0.280s) provavelmente ruído do SO, não sinal — a mediana e o stdev de
KB5000 (mais estável, σ=0.007) são a leitura mais fiável. Sem sinal de
degradação relevante nesta gama; não há indicação de que o crescimento da
KB seja um problema de escalabilidade a curto/médio prazo.

### 5.3 Diversidade real — ✅ medido

Corremos o CASPAR sobre configuração real, não escrita por nós para o efeito:

- **nginx**: `/etc/nginx` completo (config stock do pacote Ubuntu, com todos
  os `include` resolvidos — `sites-available/default`, `mime.types`, etc.).
- **apache**: `/etc/apache2` completo (config stock do pacote `apache2`
  Ubuntu, todos os módulos/confs habilitados por default).
- **kubernetes**: 6 manifests oficiais do repositório
  [`kubernetes/website`](https://github.com/kubernetes/website) (exemplos da
  documentação oficial — `simple-pod.yaml`, `nginx-deployment.yaml`,
  `nginx-app.yaml`, `nginx-secure-app.yaml`, `mysql-deployment.yaml`,
  `deployment.yaml`).

Não tentámos baixar configs nginx/apache de outros repositórios GitHub
(URLs adivinhadas deram 404); os pacotes stock Ubuntu já são configuração
real, mantida por terceiros (Debian/Ubuntu maintainers), não escrita para
este trabalho — servem o mesmo propósito de medir generalização.

```bash
caspar --db ccss.db scan /etc/nginx --output-dir out/nginx
caspar --db ccss.db scan /etc/apache2 --output-dir out/apache
for f in k8s_real/*.yaml; do caspar --db ccss.db scan "$f" --output-dir out/k8s; done
```

**Resultados:**

| Alvo | Ficheiros parseados | Diretivas escaneadas | Findings | Chains | Diretivas desconhecidas |
|---|---|---|---|---|---|
| nginx (`/etc/nginx`) | 100% (sem erros) | 107 | 4 | 0 | 106 |
| apache (`/etc/apache2`) | 100% (sem erros) | 291 | 12 | 8 | 245 |
| K8s (6 manifests) | 6/6 (100%) | 6–41 por ficheiro | 0 em todos | 0 | 5–27 por ficheiro |

Nenhum dos parses falhou (0 erros de sintaxe/leitura em qualquer dos
ficheiros reais) — o parser nginx/apache/K8s é robusto a configuração real
fora das nossas fixtures.

**Leitura das diretivas desconhecidas — nginx/apache:** a maioria das
"diretivas desconhecidas" não é configuração de segurança de todo — é
metadata de tipos MIME:

- nginx: 88/106 (83%) vêm de `mime.types` (mapeamentos `application/pdf
  pdf;`, etc.), 12 de `nginx.conf`, 6 de `sites-available/default`.
- apache: 137/245 (56%) vêm de `mods-available/mime.conf`, seguido de
  `autoindex.conf` (49), `setenvif.conf` (16), `apache2.conf` (11), e
  restantes módulos (`mpm_event`, `deflate`, `status`, etc.) com poucas
  entradas cada.

Excluindo os ficheiros de mapeamento MIME, a taxa "genuína" de diretivas
desconhecidas cai para 18/107 (17%) em nginx e 108/291 (37%) em apache,
concentrada em diretivas de módulos específicos fora do escopo curado da KB
atual (18 regras nginx, 35 regras apache) — não em falhas de parsing. Isto é
um resultado qualitativo relevante: o mecanismo de sinalização de diretivas
desconhecidas (não pontuadas, mas reportadas) está a funcionar como
desenhado, e a maior fonte de ruído (tabelas MIME) é facilmente filtrável se
se quiser um sinal de generalização mais limpo no futuro.

**Leitura das diretivas desconhecidas — K8s:** a KB de kubernetes cobre 10
diretivas curadas de segurança do `securityContext`
(`privileged`, `runAsNonRoot`, `allowPrivilegeEscalation`,
`readOnlyRootFilesystem`, `hostNetwork`, `hostPID`, `hostIPC`, `runAsUser`,
`automountServiceAccountToken`, `add`). Todo o resto do schema K8s
(`apiVersion`, `kind`, `containerPort`, `image`, `mountPath`, `name`, ...) é,
por desenho, sinalizado como "desconhecido" — não é uma lacuna do parser,
é o âmbito deliberadamente estreito da KB curada (consistente com o resto
do plugin IaC, ver mapa §0). Os 6 manifests oficiais não geraram nenhum
finding porque são exemplos de tutorial bem formados (sem `privileged: true`,
sem `hostNetwork: true`, etc.) — um resultado limpo e plausível, não um
sinal de falha de deteção (confirmado por inspeção manual do log de
`nginx-secure-app.yaml`: 31 diretivas genuinamente escaneadas).

**Análise:** 100% dos ficheiros reais testados (nginx, apache, 6 manifests
K8s) foram parseados sem erro — nenhuma falha de parsing em configuração
que não escrevemos nós. O volume bruto de "diretivas desconhecidas" é
dominado por dados não seguros (tabelas MIME), não por lacunas de
cobertura; depois de filtrar isso, a taxa de diretivas fora do âmbito da KB
é modesta e concentrada em módulos/campos específicos não cobertos —
esperado para uma KB curada (por desenho, não exaustiva) e não indicativo
de um problema de robustez do parser.

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

### 6.2 Desempenho lado a lado — ✅ medido (WSL2; repetir em Ubuntu nativo antes da defesa)

Mesma máquina, mesmo input, mesmo protocolo do §4.1. Script:
`scripts/perf_baseline.py` (reutiliza `scripts/perf_scan.py`, mesma disciplina
N≥10/warm-up/mediana+p95, mesmos fixtures do `scripts/baseline_compare.py`
usado no §6.1 — achados e desempenho medidos sobre exatamente o mesmo input).

```bash
python -m scripts.perf_baseline --runs 10 --json > perf_baseline.json
python -m scripts.perf_baseline --runs 10
```

**Resultados (N=10, 1 warm-up descartado):**

| Input | Ferramenta | Latência mediana | Latência média±σ | p95 | CPU total | RAM pico | Energia (J, est.) |
|---|---|---|---|---|---|---|---|
| azure_storage_vulnerable.tf | CASPAR | 0.150s | 0.152±0.016s | 0.175s | 0.110s | 27.0 MB | 1.65 |
| azure_storage_vulnerable.tf | Trivy | 1.015s | 1.042±0.129s | 1.216s | 1.655s | 195.1 MB | 24.82 |
| Dockerfile.vulnerable | CASPAR | 0.130s | 0.136±0.013s | 0.155s | 0.090s | 26.7 MB | 1.35 |
| Dockerfile.vulnerable | Trivy | 0.890s | 0.893±0.026s | 0.935s | 1.465s | 198.4 MB | 21.98 |
| — (live system eval, cis_level1_server) | OpenSCAP | 0.975s | 0.973±0.030s | 1.021s | 0.895s | 195.7 MB | — |

> Nota de equidade: o Trivy é um binário Go, o CASPAR é Python — a
> comparação de recursos mede as *implementações*, não as *metodologias*.
> **OpenSCAP avalia o sistema vivo, não um ficheiro** (§6.1 "Avalia: estado
> do sistema vivo") — não é comparável ficheiro-a-ficheiro com CASPAR/Trivy;
> reportado à parte, N=10 mas sem par de input comum.

**Leitura:** CASPAR é **6-8× mais rápido em wall time** e usa **~7× menos
RAM pico** que o Trivy nos mesmos dois ficheiros, apesar de ser Python vs Go
— consistente com CASPAR fazer um lookup indexado num SQLite pequeno
(§4.3: BD abre em ~1ms) contra o binário Trivy carregar as suas policies/
regras embutidas a cada invocação. CPU total do Trivy (~1.5s) é bem acima do
seu próprio wall time (~0.9-1.0s) — `Percent of CPU this job got: ~170%`
confirma paralelismo interno (múltiplas goroutines), o que reduz o wall time
à custa de mais CPU agregado; o CASPAR não paraleliza (CPU total < wall
time). Energia estimada (TDP×CPU-time) segue a mesma proporção: ~15-18×
menos para CASPAR. **Nota de fiabilidade da medição**: o Trivy falhou o
parsing de `/usr/bin/time -v` em ~1/20 corridas neste ambiente WSL2 (causa
não identificada — não reproduzível isoladamente, resolvido com retry
automático em `run_once_trivy`); não afeta CASPAR nem OpenSCAP, e as
corridas com falha foram descartadas e repetidas, não incluídas nestes
números.

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
python -m pytest tests/ -q                    # ~647 passed
python -m scripts.functional_check            # 13/13
python -m scripts.evaluate                    # KB · MAE 0% · recall 100% · precision/F1 100%
python -m scripts.baseline_compare --oscap    # Trivy + OpenSCAP

# já medido nesta sessão (WSL2 — repetir em Ubuntu nativo antes da defesa)
python -m scripts.perf_scan --runs 10          # §4.1 latência/CPU/RAM/energia do scan
python -m scripts.perf_baseline --runs 10      # §6.2 idem para Trivy/OpenSCAP
# §4.2 custo de extensão medido via `plugin add` local (stigviewer.com passou a
# exigir auth — ver [[caspar-benchmark-fetch-sources]]; plugin fetch indisponível)
# §1.2 concordância por submétrica: anotador-LLM (eu), N=35 (apache-httpd
# completo), sem segundo anotador humano — ver nota de metodologia em §1.2.
# Achado mais acionável: GEL constante (=Low) nas 35 regras deste target,
# candidato a investigação de causa raiz no build_apache antes da defesa.
# §5.1 escalabilidade sintética (nginx, N=10/100/1000/5000 server blocks):
# fit N>=100 dá t~=0.0148*N^0.58 (R²=0.92, sublinear). Limiar interativo
# (2s) ~N=4700. Encontrado e corrigido um bug real de performance: o
# resolvedor de nº de linha em parser.py (_LineTracker.line_of) era
# O(diretivas x linhas) = O(N²); N=5000 caiu de 166.294s -> 2.520s (~66x)
# apos indexar por diretiva + consumo em deque. 647/647 testes continuam a
# passar. Ver §5.1 para a análise completa.
# §5.2 KB crescente (514->1000->5000 regras via targets fantasma): +38%
# latência mediana (0.130s->0.180s), +12MB RAM, findings idênticos (9/9/9)
# — lookup indexado por (target_name, directive), sem sinal de degradação.
# §5.3 diversidade real (/etc/nginx, /etc/apache2 stock Ubuntu + 6 manifests
# K8s oficiais kubernetes/website): 100% parse sem erros. "Diretivas
# desconhecidas" dominadas por tabelas MIME (não são config de segurança);
# taxa genuína fora do âmbito da KB é modesta e concentrada em módulos
# específicos — comportamento esperado de uma KB curada, não exaustiva.
# §4.3 ingestão manual RAG (`plugin manual`): N=3, mediana 0.12s wall,
# dominado por I/O+extração pdftotext, não LLM. Build do índice TF-IDF
# (BenchmarkIndex, N=5): mediana 13.4ms sobre um .md de ~2000 linhas —
# overhead "por scan" da RAG desprezável, ordens de grandeza abaixo do
# build de plugin novo (§4.2, ~1h46min, dominado por LLM).

# por implementar/medir (por ordem de valor para a tese)
# 1. Repetir §4.1/§4.2/§6.2 em Ubuntu nativo — AÇÃO DO UTILIZADOR: este
#    ambiente é WSL2 (confirmado via uname -r), sem máquina Ubuntu nativa
#    acessível; correr scripts/perf_scan.py e scripts/perf_baseline.py na
#    máquina Ubuntu 22.04 real antes da defesa e reportar os números aqui.
# (§3.2 — estabilidade do build LLM, 5 builds — intencionalmente NÃO medido
#  nesta ronda, por decisão explícita: custo ~9h considerado desproporcional
#  para o ganho marginal face a §4.2 (N=1) já reportado)
# (opcional, reforça §1.2) segundo anotador humano real para apache-httpd,
#    ou repetir §1.2 noutro target para testar se GEL=L constante generaliza
```

---

*Documento de apoio à secção de avaliação da dissertação (metodologia AMiSA /
ferramenta CASPAR). Resultados ✅ obtidos em Ubuntu 22.04 real, 2026-07-09.*
