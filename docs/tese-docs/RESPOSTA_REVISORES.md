# Resposta aos comentários dos revisores (INForum)

Este documento responde ponto a ponto às questões e sugestões levantadas pelo
Revisor 1 (score: weak accept). Cada resposta indica se o ponto ficou
**resolvido**, **parcialmente resolvido** ou **não resolvido** (limitação
declarada), com referências concretas ao código/documentação.

---

## 0. Estilo — parágrafos longos (Secção 2.3)

Nota de estilo sobre o texto do artigo submetido, não uma questão técnica.
Fica registada para a revisão de texto antes da versão final (quebrar
parágrafos longos na secção correspondente, sem alterar conteúdo técnico).

---

## 1. Risco do não-determinismo do LLM na classificação CCSS

> "Considerando a natureza probabilística dos LLMs, qual o risco de usá-los
> para inferir classificações do CCSS? Executar a fase de build múltiplas
> vezes produzirá classificações distintas? Como lidar com isso?"

**Estado: RESOLVIDO.**

Sim — o risco é real e foi medido e mitigado de forma concreta:

- **Medição do problema:** `scripts/determinism_experiment.py` executa a
  fase de build 5 vezes sobre as mesmas 30 entradas e mede: percentagem de
  vetores unânimes, concordância por métrica (AC/C/I/A/GEL/GRL), amplitude
  de score e taxa de fallback. Resultado reportado: 0/150 acionamentos do
  fallback conservador, mas variação residual não-nula em algumas métricas
  (ver `DISSERTACAO_REFERENCIA.md` §4.7).
- **Mitigação implementada (não apenas medida) — cinco camadas:**
  1. Temperatura baixa (`temperature=0.1`, quase *greedy decoding*).
  2. RAG como redutor de variabilidade contextual (ancora o prompt na secção
     exata do benchmark CIS).
  3. Retry interno com validação sintática (JSON bem formado, valores no
     domínio legal) antes de aceitar qualquer resposta.
  4. Fallback conservador determinístico, explicitamente marcado
     (`confidence=0.0`), se todas as tentativas falharem.
  5. **Separação estrutural build-time/runtime**: o não-determinismo fica
     confinado à construção única da base de conhecimento; o *scan* em si
     (o que corre por infraestrutura, repetidamente) é 100% determinístico
     — parsing + lookup exato + aritmética CCSS, sem LLM.
- **Resposta direta a "múltiplas execuções produzem classificações
  distintas? como lidar com isso":** implementámos **self-consistency**
  (Wang et al., 2022) diretamente no pipeline de build — cada directiva pode
  ser classificada a partir de *k* amostras independentes do LLM, agregadas
  por votação de maioria **por métrica** (não por vetor inteiro), com um
  score de `confidence` (a taxa de concordância da métrica menos
  consensual) persistido na base de conhecimento junto de cada regra. Os
  empates são resolvidos não por uma tabela de severidade inventada, mas
  computando qual candidato produz o `temporal_score` mais alto segundo a
  fórmula CCSS real — garantindo que o desempate nunca diverge do motor de
  scoring que o próprio sistema usa. Ver `DISSERTACAO_REFERENCIA.md` §4.7.3
  e `tese/Chapters/Chapter2_Background.tex` §2.6.5 para a descrição
  completa; implementação em
  `config_assessment/plugins/apache_httpd/llm_pipeline.py`
  (`_vote`, `_call_llm`, parâmetro `consensus_samples`).
- **Distinção honesta que se mantém:** concordância entre amostras mede
  *estabilidade*, não *correção* — um modelo sistematicamente enviesado
  pode votar unanimemente numa classificação errada. Por isso este
  mecanismo não substitui, mas complementa, a validação externa via MAE
  contra o ground truth CCE oficial (§4.3) e a revisão humana no comando
  `promote`.

---

## 2. Qual o LLM usado na metodologia de testes

> "É preciso incluir na metodologia de testes qual [LLM] foi utilizado."

**Estado: RESOLVIDO.**

Modelo, plataforma e hiperparâmetro de temperatura estão declarados
explicitamente e de forma consistente:

- **Modelo:** `qwen2.5:14b` (14 mil milhões de parâmetros), família Qwen2.5.
- **Plataforma:** Ollama (inferência local, sem dependência de API externa
  paga), classe `OllamaClient` em `config_assessment/build/llm_client.py`.
- **Temperatura:** `0.1` (baixa, para reduzir variância de amostragem —
  ver ponto 1).
- **Onde está declarado:** `DISSERTACAO_REFERENCIA.md` (secção da
  experiência de determinismo), `README.md` (secção de instalação do
  Ollama, com tabela de RAM vs. modelo recomendado, incluindo alternativa
  `qwen2.5:32b-instruct-q4_K_M` para máquinas com mais memória),
  `tese/Chapters/Chapter2_Background.tex` e
  `tese/Chapters/Chapter5_CASPAR.tex` (metodologia, com citação
  bibliográfica ao modelo e ao Ollama), e `tese/Chapters/Chapter6_Evaluation.tex`
  (discussão explícita do porquê deste tamanho de modelo face ao hardware
  disponível). Fica também declarado como escolha de "configuração de
  produção" usada na própria experiência de determinismo
  (`scripts/determinism_experiment.py`).

---

## 3. Inputs da fase de runtime (Figura 1)

> "Na fase de runtime, o que são, exatamente, os inputs da ferramenta?
> [...] quais os dados necessários sobre 'serviço em execução' e como a
> ferramenta relaciona essa informação com a base de conhecimento?"

**Estado: RESOLVIDO.**

A arquitetura de inputs está descrita em detalhe (com figura dedicada,
"Global Data Flow and Input Modes",
`tese/Chapters/Chapter5_CASPAR.tex`) e suporta **quatro modos de input**,
implementados em `config_assessment/core/input_resolver.py`:

1. **Ficheiro único** de configuração (ex.: um `httpd.conf` isolado).
2. **Diretório**, seguindo diretivas `Include` para reconstruir a
   configuração efetiva completa.
3. **Serviço instalado localmente**, via flag `--live` — a ferramenta
   localiza a configuração ativa do serviço no próprio sistema.
4. **Imagem Docker** (`docker://...`) — extrai a configuração de dentro da
   imagem sem a correr.

**Ligação "serviço em execução" → base de conhecimento:** no modo `--live`
(ou a partir de uma imagem Docker), a ferramenta tenta detetar a **versão**
do serviço instalado — via tag da imagem, via binário local no `PATH`
(`httpd -v`, `sshd -V`, etc.) ou, em último caso, via texto da própria
configuração. Essa versão detetada (`detected_version` em `ScanResult`) é
depois usada para consultar a tabela `version_exploits` (pré-preenchida em
build-time via NVD/Exploit-DB/KEV — ver ponto 5 abaixo) e aplicar
**amplificação de score sensível à versão** quando a versão detetada tem
exploits públicos conhecidos — este é o mecanismo F1 referido na Secção 3.4
do artigo. A ligação à base de conhecimento "estática" (as regras CCSS por
diretiva) é sempre por **lookup exato de diretiva + valor**, independente
do modo de input — o que muda entre os 4 modos é apenas *como o texto de
configuração e a versão são obtidos*, não como são pontuados depois.

---

## 4. Como são criados/executados os "probes" para serviços (SSH incluído)

> "Falta uma descrição sobre como os probes para serviços são criados e
> executados. Por exemplo, como é verificada a configuração das
> permissões de sessão do root via SSH?"

**Estado: RESOLVIDO — implementado sem probing ativo, porque o objetivo do
AEGIS é avaliar o ficheiro de configuração efetivo, não o estado de sessões
em runtime.**

O AEGIS não estabelece sessões SSH reais nem interroga o alvo pela rede para
responder "a pessoa autenticar-se-ia como root?" — essa pergunta está
inteiramente contida na configuração declarada (`sshd_config` efetivo, com
todos os `Include` e blocos `Match` resolvidos). Em vez de probing, foi
implementada avaliação **worst-case, estática** de blocos `Match`:

- `config_assessment/plugins/ssh/parser.py` (`_match_applies_worst_case`,
  `_address_token_is_private`) avalia agora as condições de cada bloco
  `Match <criteria>` contra um perfil de atacante remoto genérico:
  critérios `User`/`Group`/`Host` são tratados como satisfazíveis por
  construção (um atacante escolhe que utilizador tentar); critérios
  `Address`/`LocalAddress` só são considerados "não aplicáveis" quando
  **todos** os endereços listados caem numa gama privada/loopback
  (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `127.0.0.0/8`, `::1`) —
  qualquer endereço público ou wildcard (`*`) é tratado como
  atacante-alcançável, e um bloco com endereços mistos (um público, um
  privado) é worst-case aplicável se **qualquer um** for alcançável.
- Diretivas dentro de um bloco `Match` worst-case-aplicável (ex.:
  `PermitRootLogin yes` dentro de `Match User admin`) passam a ter
  `context="global"`, exatamente como uma diretiva de topo — o motor de
  scan (`runtime.py`) já trata todas as diretivas de forma idêntica
  independentemente do `context`, pelo que este passou a ser o único ponto
  de decisão necessário.
- **Descoberta relevante durante a implementação:** o docstring antigo do
  parser afirmava que diretivas de blocos `Match` eram "excluídas da
  avaliação em runtime" — mas essa filtragem nunca existiu de facto em
  `runtime.py` (o `context` era usado apenas para exibição em
  `cli/_output.py`/relatórios, nunca para decidir o que é avaliado). A
  lacuna real não era "falta de probing" nem sequer "falta de filtragem",
  mas sim que o parser atribuía a diretivas dentro de `Match` um contexto
  não-global mesmo quando o bloco era, na prática, satisfazível por um
  atacante — subestimando o risco por rotulagem, não por omissão de
  avaliação.
- **Testado:** `tests/test_ssh.py` — 4 testes novos/reescritos cobrem
  `Match User` (sempre worst-case), `Match Address` restrito a gama privada
  (não worst-case, mantido apenas para visibilidade), `Match Address`
  público/wildcard (worst-case) e `Match Address` misto
  público+privado (worst-case porque um dos endereços é alcançável).

Isto confirma a reclassificação já feita antes da implementação: o ponto do
revisor identificava corretamente uma lacuna real (blocos `Match` não
avaliados), e a solução correta era completar o parser estático — não
introduzir live-probing, que seria inconsistente com o desenho
determinístico/offline do AEGIS.

---

## 5. CTI feeds para vulnerabilidades sem CVE

> "Muitos eventos de segurança decorrentes de erros de configuração não
> possuem CVE associados. Na Sec. 3.4, a 'pontuação sensível ao contexto'
> considera apenas exploits para vulnerabilidades conhecidas. Não faria
> sentido incluir aqui feeds de CTI?"

**Estado: RESOLVIDO.**

O mecanismo F1 já ia além de "CVE puro" ao combinar NVD API v2, CISA KEV
(*Known Exploited Vulnerabilities*) e Exploit-DB — mas continuava
estruturalmente ancorado a vulnerabilidades **com CVE atribuído**;
`_compute_gel` forçava `GEL="L"` sempre que não havia CVE. Foi agora
adicionado um quarto sinal, especificamente para o caso sem CVE que o
revisor identificou:

- **`config_assessment/enrichment/ttp_enricher.py`** (novo módulo) — tabela
  curada e offline (`_TTP_TABLE`) que mapeia `(target, diretiva,
  bad_value)` → técnica MITRE ATT&CK (`TTPRecord`: id, nome, tática,
  racional), no mesmo padrão de `CPE_TEMPLATES` (curado, não gerado
  automaticamente, extensível). Cobre 7 entradas iniciais: `ssh`
  (`PermitRootLogin`→T1078.003, `PasswordAuthentication`→T1110,
  `PermitEmptyPasswords`→T1078), `apache-httpd` (`ServerTokens`
  Full→T1592.002, `Options Indexes`→T1083), `mysql`
  (`skip-grant-tables`→T1078), `redis` (`requirepass`→T1078).
- **Integração em `cve_enricher.py`:** `_compute_gel` ganhou parâmetros
  opcionais (`target_name`, `directive`, `bad_value`); quando não há CVEs,
  em vez de devolver sempre `GEL="L"`, consulta `lookup_ttp(...)` e, se
  houver mapeamento, devolve `GEL="M"` com nota a citar a técnica ATT&CK e
  o racional — evidência mais fraca que um CVE/KEV real (`GEL="H"`), mas
  mais forte que "sem qualquer sinal" (`GEL="L"`). Um CVE conhecido
  continua sempre a ter prioridade sobre o mapeamento TTP.
- **Retrocompatibilidade:** todas as chamadas existentes que não passam
  `target_name` continuam a devolver exatamente o comportamento antigo
  (`GEL="L"`), porque `lookup_ttp` sem `target_name` nunca encontra
  correspondência — mudança puramente aditiva.
- **Testado:** `tests/test_cve_enricher.py` — 10 testes novos (classes
  `TestTTPFallback`, `TestTTPEnricher`) cobrem o fallback sem CVE/sem TTP
  (continua `GEL="L"`), o fallback com TTP curado (`GEL="M"`, técnica na
  nota), a prioridade de um CVE conhecido sobre o mapeamento TTP, e o
  lookup exato/wildcard/sem-correspondência.

Isto não pretende ser uma cobertura exaustiva de CTI (não substitui um feed
MISP/OTX ao vivo, que introduziria uma dependência de rede inconsistente
com o desenho offline do AEGIS) — é, deliberadamente, um sinal adicional
curado, tal como o próprio mecanismo de CVE já era curado via
`CPE_TEMPLATES`. Extensão da tabela `_TTP_TABLE` fica registada como
trabalho futuro de cobertura, não de arquitetura.

---

## 6. Cenários de teste limitados

> "Os cenários de teste são limitados e carecem de uma descrição
> detalhada."

**Estado: RESOLVIDO.**

A suite formal de recall/precisão/F1 (`scripts/evaluate.py`,
`VALIDACAO.md` §2.1–2.2) foi alargada de 4 para **10 dos 11 plugins**
existentes — todos exceto `docker` (as suas regras são maioritariamente
estado do host/CLI — kernel, flags do daemon, permissões de ficheiro — não
chaves de `daemon.json`, pelo que uma fixture de configuração não as
exercitaria de forma honesta; fica declarado como fora de âmbito, não como
lacuna escondida):

- **Fixtures vulneráveis novas:** `test_target/ssh_demo/sshd_config`,
  `test_target/mysql_demo/my.cnf`, `test_target/redis_demo/redis.conf`,
  `test_target/tomcat_demo/tomcat.conf` — mais o registo formal de
  `httpd.conf` (apache-httpd) e `ubuntu_demo/sysctl.conf` (ubuntu), que já
  existiam mas não estavam na suite de `evaluate.py`. Cada fixture usa
  apenas diretivas com `bad_value` literal (não placeholders como
  `insecure_value`), para que o recall seja uma medição real, não
  cosmética.
- **Fixtures hardened novas (fecha a lacuna de precisão/F1 do ponto
  anterior):** contraparte "limpa" para os 10 alvos —
  `nginx_hardened.conf`, `pod_hardened.yaml`, `Dockerfile.hardened`,
  `azure_storage_hardened.tf`, `httpd_hardened.conf`,
  `ubuntu_hardened_demo/sysctl.conf`, `ssh_demo/sshd_config_hardened`,
  `mysql_hardened_demo/my.cnf`, `redis_hardened_demo/redis.conf`,
  `tomcat_hardened_demo/tomcat.conf` — cada uma cobre as mesmas diretivas
  da fixture vulnerável correspondente, incluindo as diretivas que só são
  avaliadas por *absence rule* (têm de estar **presentes** com valor
  aceitável, não apenas omitidas, ex.: `ClientAliveInterval`, `add_header
  X-Content-Type-Options` em nginx, `Header ... Strict-Transport-Security`
  em Apache).
- **Resultado medido (`python -m scripts.evaluate`):** recall 100%
  (96/96 findings esperados, nos 10 alvos), precisão 100% (96 TP / 0 FP),
  F1 100% — nenhuma fixture hardened produziu um único falso positivo.
- **`VALIDACAO.md` §2.1–2.2** atualizado com as tabelas por alvo e a nota
  honesta sobre o alcance do corpus: é sintético e deliberadamente
  worst-case/best-case, não substitui um corpus de configurações reais "em
  estado selvagem" — essa continua a ser uma limitação a declarar
  explicitamente na tese, não resolvida por este trabalho.
- **Testado:** `python -m pytest tests/ -q` — 646 passed (sem regressões
  face às 636 anteriores à sessão de correções).

Isto substitui a resposta anterior ("trabalho futuro concreto e
desbloqueado") pela implementação efetiva: os 6 plugins que faltavam
(`ssh, mysql, redis, tomcat, ubuntu` + registo formal de `apache-httpd`)
estão agora cobertos por fixtures vulneráveis e hardened, registados e
medidos.

---

## Resumo — Revisor 1

| # | Ponto do revisor | Estado | Referência |
|---|---|---|---|
| 0 | Parágrafos longos (estilo) | A corrigir na revisão de texto | — |
| 1 | Risco do não-determinismo do LLM na classificação CCSS | **Resolvido** | self-consistency, `llm_pipeline.py` |
| 2 | LLM usado na metodologia de testes | **Resolvido** | `qwen2.5:14b`, Ollama, temp. 0.1 |
| 3 | Inputs da fase de runtime / Figura 1 | **Resolvido** | `input_resolver.py`, 4 modos |
| 4 | Probes de serviço (SSH root session) | **Resolvido** | `ssh/parser.py` — `Match` worst-case |
| 5 | Feeds de CTI para vulnerabilidades sem CVE | **Resolvido** | `enrichment/ttp_enricher.py` |
| 6 | Cenários de teste limitados | **Resolvido** | 10/11 plugins, recall+precisão+F1 100% |

Todos os seis pontos levantados pelo Revisor 1 ficam respondidos com
trabalho efetivamente implementado e testado nesta sessão (não apenas
diagnosticado como viável):

- **Ponto 4 (probes SSH):** implementado sem probing ativo remoto —
  `_match_applies_worst_case` resolve estaticamente se um bloco `Match`
  seria satisfazível por um atacante remoto genérico, dobrando as suas
  diretivas para `context="global"` quando aplicável.
- **Ponto 5 (CTI):** `ttp_enricher.py` acrescenta um quarto sinal ao
  mecanismo F1 — mapeamento curado diretiva→MITRE ATT&CK, usado como
  fallback (`GEL="M"`) quando não há CVE associado, sem nunca substituir a
  prioridade de um CVE/KEV real.
- **Ponto 6 (cenários de teste):** os 6 plugins sem fixture formal (`ssh,
  mysql, redis, tomcat, ubuntu` + registo de `apache-httpd`) têm agora
  fixtures vulneráveis e hardened, com recall/precisão/F1 medidos a 100%
  em `scripts/evaluate.py` e documentados em `VALIDACAO.md`.

Todas as alterações são estritamente aditivas e retrocompatíveis (626 → 646
testes, zero regressões, `python -m pytest tests/ -q`). A limitação que
permanece, e que deve ser declarada com honestidade na tese, é a natureza
sintética do corpus de fixtures (worst-case/best-case deliberado) — não
substitui um corpus de configurações reais recolhidas "em estado
selvagem", o que fica registado como trabalho futuro de validação externa,
não como uma lacuna de implementação.

---

## Revisores 2 e 3 — nota de enquadramento

Os Revisores 2 (weak reject) e 3 (weak accept) levantam críticas de
**natureza diferente** das do Revisor 1: não são perguntas técnicas
pontuais respondíveis com referências a código, mas críticas estruturais
ao **artigo submetido** — falta de detalhe experimental, ausência de
comparação com alternativas, ausência de secção de limitações/threats to
validity, motivação insuficientemente demonstrada, e avaliação
"superficial". Por indicação explícita, estas críticas **não geram uma
segunda rodada de resposta ponto-a-ponto** como a do Revisor 1 — o artigo
já foi submetido e não há resubmissão prevista. Em vez disso, servem para
**orientar a escrita da tese**, onde há espaço (e é esperado) resolver de
forma muito mais completa o que o artigo, por limite de páginas, deixou
por explicar.

### O que cada crítica implica para a tese

**Revisor 2:**
- *"Não há detalhe suficiente sobre a extração LLM (modelo, prompts,
  validação, casos de falha, deteção de métricas CCSS incorretas ou
  ambíguas)."* — Já coberto em detalhe na dissertação de referência e nos
  capítulos da tese (modelo/temperatura no ponto 2 acima; prompts em
  `_SYSTEM_PROMPT`/`_FEW_SHOT`; validação sintática em
  `validate_metrics`; casos de falha no fallback conservador; e agora
  também o mecanismo de self-consistency/`confidence`, ponto 1). A tese
  deve garantir que este nível de detalhe, que já existe no repositório e
  na documentação técnica, está de facto refletido no capítulo de
  metodologia/implementação, não apenas mencionado de passagem.
- *"Falta comparação experimental com OpenSCAP, CIS-CAT, Trivy ou
  LLMSecConfig sobre as mesmas configurações."* — Parcialmente coberto:
  já existe `scripts/baseline_compare.py` (Trivy, OpenSCAP) referido na
  dissertação (ver memória "CASPAR evaluation & baselines"), e uma
  comparação *conceptual* (não experimental) com LLMSecConfig em §4.7.1. A
  tese deve deixar claro que a comparação experimental direta existe para
  Trivy/OpenSCAP (mesmo que não no artigo, por limite de páginas), e que a
  comparação com LLMSecConfig é necessariamente conceptual (arquiteturas
  não comparáveis por rodar sobre tarefas diferentes — reparação vs.
  scoring), explicando isso explicitamente em vez de deixar a ausência
  sem justificação.
- *"Não há secção de threats to validity / limitações."* — A tese já tem
  isto de forma extensa (§4.8 Limitações, §4.7.2 contraponto sobre
  fiabilidade da base de conhecimento). Garantir que este nível de
  autocrítica, que falta no artigo por espaço, está bem visível e
  destacado num capítulo próprio da tese.
- *Afirmações na introdução sem referências, introdução sem explicar como
  a metodologia será avaliada, Figura 2 duplicando a Tabela 2* — questões
  de escrita/edição do artigo, não aplicáveis à tese (que já tem estrutura
  diferente); ficam como nota de estilo a rever no artigo, se houver
  oportunidade de nova versão, mas não implicam trabalho técnico.

**Revisor 3:**
- *"O modo como o artigo endereça as fraquezas do estado da arte não é
  convincente; risco de ser 'mais uma ferramenta' de avaliação de
  configurações."* — Isto é uma crítica de posicionamento/narrativa, não
  de implementação. A tese tem mais espaço para argumentar a contribuição
  distintiva (a combinação específica de CCSS quantitativo + LLM
  build-time/runtime determinístico + AMiSA como metodologia, não só
  CASPAR como ferramenta) de forma mais desenvolvida do que um artigo de
  conferência permite. Deve informar como o capítulo de introdução/related
  work da tese posiciona a contribuição, mais do que qualquer mudança de
  código.
- *"Confiar a classificação CCSS ao LLM requer validação extensiva."* —
  Diretamente endereçado pelo trabalho já feito (self-consistency, MAE
  contra CCE, ponto 1 acima) — mas o comentário serve de lembrete para a
  tese apresentar essa validação de forma exaustiva e sem ambiguidade,
  precisamente porque um revisor externo achou que não estava
  suficientemente demonstrado no artigo.
- *"Não descreve como implementa a automação das verificações, nem quão
  flexível é dado que as regras são extraídas."* — A tese deve detalhar
  com mais profundidade o mecanismo de lookup exato diretiva+valor em
  runtime e o processo de extensão via `promote`/plugins novos (já
  ilustrado no cenário de "criação automática de plugin Redis a partir de
  um DISA STIG" mencionado pelo Revisor 2), garantindo que fica claro que a
  ferramenta é extensível por desenho, não rígida.
- *"Avaliação superficial, incapaz de demonstrar a capacidade total da
  abordagem de forma convincente."* — Reforça, tal como o Revisor 2, a
  necessidade de a tese apresentar a validação de forma mais completa e
  quantificada do que o artigo — o que já está em grande parte feito
  (MAE, recall, baselines, determinismo) mas deve estar bem organizado e
  destacado, não disperso.

### Conclusão sobre Revisores 2 e 3

Nenhuma das críticas destes dois revisores aponta para uma lacuna técnica
nova que não esteja já a ser tratada pelo trabalho em curso — são,
sobretudo, sintomas de **limite de espaço do formato artigo** (8-10
páginas) versus o detalhe que uma tese permite. A ação concreta é
**editorial/estrutural na tese**: garantir que os capítulos de metodologia,
avaliação e limitações tornam explícito e bem organizado tudo o que estas
críticas assumem estar em falta — não é preciso nova implementação além do
que já foi identificado nos pontos 4–6 da secção do Revisor 1.
