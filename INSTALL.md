# INSTALL — do clone ao primeiro scan

Este documento leva uma máquina Linux acabada de instalar até um scan CVM
reproduzível. É o percurso mínimo: **clone → instalar → semear → scan**.

Todos os comandos abaixo foram executados exactamente como estão escritos. Onde
há um resultado esperado, ele está transcrito da execução real, não parafraseado.

> **Nomenclatura.** CVM (*Configuration Vulnerability Meter*) é a metodologia;
> CASPAR é a implementação de referência. Por isso o comando chama-se `caspar` e
> a base de dados `ccss.db` — os nomes do programa não mudam, mesmo quando a
> documentação fala de CVM.

**Ambientes validados:** Ubuntu 22.04 LTS, Ubuntu 24.04 LTS, Debian 12.
Ver [docs/06_VALIDACAO.md](docs/06_VALIDACAO.md) para a matriz de resultados.

---

## 0. Pré-requisitos

```bash
sudo apt-get update
sudo apt-get install -y python3 python3-venv python3-pip git sqlite3
```

| Pacote | Porquê | Obrigatório |
|---|---|---|
| `python3` ≥ 3.10 | O `pyproject.toml` exige `>=3.10`. Ubuntu 22.04 traz 3.10, Ubuntu 24.04 traz 3.12 — ambos servem. | sim |
| `python3-venv` | Instalação isolada, sem tocar no Python do sistema. | sim |
| `git` | Clonar o repositório. | sim |
| `sqlite3` | Aplicar a base de conhecimento canónica (passo 3). | sim |
| `poppler-utils` | Só para `caspar build --benchmark <pdf>` (extrair texto de PDFs). Não é preciso para fazer scans. | não |
| Docker | Só para `caspar scan docker://...`. Ver [secção 6](#6-caminho-alternativo-docker). | não |

Confirmar a versão do Python:

```bash
python3 --version    # tem de ser 3.10 ou superior
```

---

## 1. Clonar o repositório

```bash
git clone https://github.com/AFilipe-IT/CASPAR.git caspar
cd caspar
```

---

## 2. Instalar

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -e .
```

**Esperado:** termina em poucos segundos com `Successfully installed ... caspar-0.1.0 ...`.
As dependências base são apenas três (`pydantic`, `click`, `pyyaml`), por isso a
instalação é rápida.

Confirmar:

```bash
caspar --help
```

**Esperado:** o texto de ajuda. Após a linha `Usage:`, a descrição é
`CASPAR — Configuration Vulnerability Meter (CVM) reference implementation.`,
seguida da lista de comandos (`scan`, `build`, `plugin`, `watch`, …).

> Se em vez disso aparecer `CASPAR — Configuration Analysis, Security Posture
> Assessment and Reporting`, o clone é anterior à uniformização de nomenclatura
> para CVM (anterior a `66f1159`). Confirma com `git log --oneline -1`: uma
> versão antiga não tem a correcção de determinismo e pode falhar a verificação
> da secção 4.

> ⚠️ **O `pip install --upgrade pip` acima não é decorativo.** Com o pip que
> vem de origem no Ubuntu 22.04, `pip install -e ".[dev]"` falha com
> `ResolutionTooDeep`. Com o pip actualizado resolve em segundos. Se
> encontrares esse erro, actualiza o pip antes de tentar outra coisa.

---

## 3. Semear a base de conhecimento

**Este passo é obrigatório.** Sem ele, qualquer scan falha com:

```
DB 'ccss.db' not found.
Run: caspar build --benchmark <pdf>
```

Essa mensagem aponta para `caspar build`, que reconstrói a base de conhecimento
com um LLM local e demora cerca de **1h46min** (medido). Não é preciso: o
repositório já inclui a base de conhecimento canónica, e aplicá-la demora
menos de um segundo.

```bash
sqlite3 ccss.db < data/ccss_canonical.sql
```

Confirmar:

```bash
caspar doctor      # integridade da base de dados
caspar targets     # tecnologias suportadas
```

**Esperado:** `doctor` termina com `✓ Database is healthy — no issues found.` e
`targets` lista 13 plugins:

```
  apache-httpd  azure-iac  docker    dockerfile  dummy   kubernetes  mysql
  nginx         postgresql redis     ssh         tomcat  ubuntu
```

> A base de conhecimento fica em `ccss.db` **na pasta onde correres o comando**.
> Para a usar a partir de qualquer sítio, define `export CASPAR_DB=$PWD/ccss.db`
> ou passa `--db /caminho/para/ccss.db` (nota: as opções globais vêm *antes* do
> subcomando — `caspar --db X scan f.conf`, nunca `caspar scan f.conf --db X`).

---

## 4. Primeiro scan

Criar uma configuração Apache deliberadamente vulnerável:

```bash
cat > apache.conf <<'EOF'
ServerTokens Full
ServerSignature On
TraceEnable On
EOF

caspar scan apache.conf
```

> **Para um teste mais realista**, `caspar demo` escreve quatro configurações
> de exemplo — Apache e NGINX, cada uma em versão vulnerável e endurecida — sem
> precisares de clonar nada:
>
> ```bash
> caspar demo
> caspar scan caspar-demo/apache-vulnerable.conf   # 8.7 HIGH,   4 cadeias
> caspar scan caspar-demo/apache-hardened.conf     # 4.7 MEDIUM, 0 cadeias
> ```
>
> O par vulnerável/endurecido mostra o score a mover-se por uma razão
> conhecida, que é mais informativo do que um número isolado. As três linhas
> acima servem para o percurso mínimo; o `demo` serve para perceber o que a
> ferramenta faz.

**Esperado** — a identidade CASPAR, o painel de score, e depois:

```
  Highest finding 6.0   Highest chain 6.1   Chains triggered 1   → score from findings; chains not scored

  TOP FINDINGS

  #  Severity  Directive      Score  CCSS Vector                   File / Location
  ──────────────────────────────────────────────────────────────────────────────────
  1  MEDIUM    Header           6.0  AV:N AC:L Au:N C:P I:P A:N    -
  2  MEDIUM    ServerTokens     4.7  AV:N AC:L Au:N C:P I:N A:N    apache.conf:1
  3  MEDIUM    ServerSign...    4.7  AV:N AC:L Au:N C:P I:N A:N    apache.conf:2
  4  MEDIUM    TraceEnable      4.0  AV:N AC:M Au:N C:P I:N A:N    apache.conf:3

  ATTACK CHAINS TRIGGERED

  [MEDIUM] info-disclosure-chain: ServerTokens -> ServerSignature   Score: 6.1

  RECOMMENDATION

  !  This configuration scores 6.0 — MEDIUM overall vulnerability.
     Highest-value fix: Header (6.0)
     → Add 'Header always append Content-Security-Policy …'

     Note: these findings compose into info-disclosure-chain, rated 6.1 —
     higher than any single finding.
     Chain: ServerTokens + ServerSignature

  COVERAGE

  3 of 3 directives read from the configuration were matched against the
  knowledge base

  reproducible: caspar 0.1.0 · kb sha256:37087229989b · 35 rules (apache-httpd)
```

> Os números exactos dependem dos factores temporais na tua base de
> conhecimento; o `kb sha256:` no rodapé identifica-a. A saída acima é o resumo
> operacional — `--verbose` mostra cada finding em detalhe, `--show-chains` a
> análise completa das cadeias.

**O código de saída é 0.** Por omissão `caspar scan` não falha por encontrar
problemas — para o usar como gate de CI, passa `--exit-code` (devolve 2 num
achado Critical) ou `--threshold N` (devolve 1 acima de N).

Repara no resultado central da metodologia. O score global (6.0) vem do **pior
finding individual**, e continua a ser sempre atribuível a uma directiva
concreta que podes corrigir. Mas a cadeia `info-disclosure-chain` está cotada a
**6.1** — acima de qualquer finding que a compõe (4.7 + 4.7). `ServerTokens` e
`ServerSignature` isoladamente são divulgação de informação; combinadas dão ao
atacante versão exacta *e* confirmação do software.

Essa composição é o que um scanner de conformidade pass/fail não captura, e é a
contribuição central do CVM. As cadeias são **reportadas mas não somadas ao
score**: um número que não se consegue rastrear até uma directiva corrigível é
um número sobre o qual não se consegue agir. A cadeia aparece como aviso
explícito na recomendação, precisamente para que quem corrige apenas a primeira
linha da tabela saiba que fica com o problema maior por resolver.

> **Os scores dependem dos factores temporais** (`GEL`/`GRL`, visíveis com
> `--verbose`). Logo após o seed reflectem a base canónica; `caspar refresh`
> (NVD + CISA KEV) e `caspar fetch-exploits` incorporam dados de exploração
> pública e fazem os mesmos findings subir. **Não corras esses comandos se
> quiseres comparar com o output acima**: precisam de rede e mudam os valores.
> O percurso base é deliberadamente offline e determinístico.

### Verificar a reprodutibilidade

O mesmo input tem de dar exactamente o mesmo output. Para o confirmar:

```bash
for i in 1 2 3 4 5; do
  caspar scan apache.conf --report -f json -o out$i >/dev/null 2>&1
done

python3 - <<'EOF'
import json, hashlib, glob
VOLATILE = {"scan_date", "timestamp", "target_path", "scan_id",
            "duration_seconds", "file_path", "date", "generated_at", "path"}
def clean(o):
    if isinstance(o, dict):
        return {k: clean(v) for k, v in o.items() if k not in VOLATILE}
    if isinstance(o, list):
        return [clean(x) for x in o]
    return o
for i in range(1, 6):
    d = json.load(open(glob.glob(f"out{i}/*.json")[0]))
    h = hashlib.sha256(json.dumps(clean(d), sort_keys=True, default=str).encode())
    print(f'run {i}: score={d["global_temporal_score"]}  sha={h.hexdigest()[:16]}')
EOF
```

**Esperado:** as cinco linhas com o mesmo score e o **mesmo hash**. Os campos
voláteis (data, caminho, id) são excluídos do hash por variarem por construção;
tudo o resto — scores, findings, cadeias, justificações — tem de ser idêntico.

```
run 1: score=6.1  sha=c6ec56b851fc812d
run 2: score=6.1  sha=c6ec56b851fc812d
run 3: score=6.1  sha=c6ec56b851fc812d
run 4: score=6.1  sha=c6ec56b851fc812d
run 5: score=6.1  sha=c6ec56b851fc812d
```

Se os hashes divergirem, **não continues** — é um problema de reprodutibilidade
e deve ser registado, não contornado.

> O hash acima corresponde à base canónica acabada de semear
> (`kb sha256:37087229989b`), sem enriquecimento por rede. Se tiveres corrido
> `refresh` ou `fetch-exploits`, os scores sobem e o hash muda — é esperado. O
> critério que tem sempre de se verificar é que as cinco linhas sejam **iguais
> entre si**; o valor absoluto só é comparável entre bases idênticas, e a linha
> `reproducible:` de cada scan identifica qual foi usada. Este teste não
> é decorativo: foi ele que expôs uma fonte real de não-determinismo (a ordem
> das directivas numa cadeia de ataque variava com o `PYTHONHASHSEED` do
> processo), corrigida em `config_assessment/core/engines/attack_chain.py` e
> agora coberta por `tests/test_chain_determinism.py`.

---

## 5. (Opcional) Correr a suite de testes

```bash
pip install -e ".[dev]"
python3 -m pytest tests/ -q
```

**Esperado:** `755 passed, 22 skipped`, sem falhas nem erros de colecção.

Os skips são esperados e não indicam problema. A suite adapta-se ao que o
ambiente tem:

| Cenário | Resultado | Porquê |
|---|---|---|
| Clone limpo + `[dev]` | `755 passed, 22 skipped` | os skips dependem de ficheiros-fonte que o repositório não redistribui (PDFs dos CIS Benchmarks em `sources/benchmarks/`) |
| Só `pytest`, sem `[dev]` | `692 passed, 4 skipped` | os 4 módulos da API REST precisam do FastAPI |
| Com todos os ficheiros-fonte presentes | `777 passed` | nada por exercitar |

Para ver o motivo de cada skip no teu ambiente:

```bash
python3 -m pytest tests/ -q -rs 2>&1 | grep SKIPPED | sort | uniq -c
```

O critério de aceitação é **zero falhas e zero erros**, não um número exacto
de testes. Um `passed` acompanhado de `skipped` é um resultado válido; um
`failed` ou `error` não é.

Se isto falhar com `ResolutionTooDeep`, o pip está desactualizado — corre
`pip install --upgrade pip` e repete (ver secção 2).

---

## 6. Caminho alternativo: Docker

Não precisa de Python, nem de clonar o repositório, nem do passo do seed — a
imagem já traz a base de conhecimento e semeia-a na primeira utilização.

**Antes de começar**, confirma que o teu utilizador consegue falar com o Docker:

```bash
docker info >/dev/null 2>&1 && echo "OK" || echo "sem acesso ao Docker"
```

Se não tiveres acesso, acrescenta-te ao grupo `docker` — instalar o Docker não
o faz automaticamente:

```bash
sudo usermod -aG docker $USER
getent group docker      # confirma que o teu utilizador aparece na lista
sudo reboot
```

Depois de reiniciar, confirma:

```bash
id -nG                   # 'docker' tem de aparecer
docker ps                # tem de correr sem erro de permissões
```

> **Porque reiniciar e não apenas voltar a entrar.** Os grupos são fixados no
> arranque da sessão. Num ambiente gráfico, um terminal novo herda os grupos da
> sessão X/Wayland que o lançou, que é anterior ao `usermod` — por isso pode
> continuar sem acesso mesmo depois de "abrir outro terminal". O `newgrp
> docker` dá acesso imediato, mas só ao sub-shell que abre, e não sobrevive a
> essa sessão. Reiniciar é o único caminho que se aplica a tudo de uma vez.

> `sudo curl … | sh` **não** resolve este problema: o `sudo` aplica-se ao
> `curl`, não ao shell que executa o script, por isso a instalação continua a
> correr sem privilégios.

```bash
curl -fsSL https://raw.githubusercontent.com/AFilipe-IT/CASPAR/master/install.sh | sh
export PATH="$HOME/.local/bin:$PATH"

caspar targets
caspar scan apache.conf
```

O percurso completo em Docker, incluindo a instalação do Docker Engine e a
comparação contra Trivy e OpenSCAP, está em
[docs/03_GUIA_VM_UBUNTU22.md](docs/03_GUIA_VM_UBUNTU22.md).

---

## 7. A seguir

| Quero… | Ver |
|---|---|
| Perceber o que os scores significam | [docs/02_GUIA_CASPAR.md](docs/02_GUIA_CASPAR.md) |
| Reproduzir os resultados da dissertação | [docs/04_AVALIACAO_FUNCIONAL.md](docs/04_AVALIACAO_FUNCIONAL.md) |
| Protocolo de medições e validação | [docs/06_VALIDACAO.md](docs/06_VALIDACAO.md) |
| Arquitectura interna | [docs/05_GUIA_TECNICO.md](docs/05_GUIA_TECNICO.md) |
| Consola web (React) | `caspar serve`, depois `http://127.0.0.1:2027/app` |

---

## Resolução de problemas

| Sintoma | Causa | Solução |
|---|---|---|
| `DB 'ccss.db' not found` | O seed (passo 3) não foi aplicado, ou estás noutra pasta. | `sqlite3 ccss.db < data/ccss_canonical.sql`, ou define `CASPAR_DB` com o caminho absoluto. |
| `ResolutionTooDeep` no `pip install` | O pip de origem do Ubuntu 22.04 é demasiado antigo para resolver o extra `[dev]`. | `pip install --upgrade pip` e repete. |
| `caspar: command not found` | A venv não está activa. | `source .venv/bin/activate` |
| O scan devolve 1 | Comportamento normal — encontrou problemas. | Nada a fazer; usa `--threshold` para definir o teu próprio gate. |
| `--db` parece ignorado | As opções globais vêm antes do subcomando. | `caspar --db X scan f.conf` |
| `caspar build` demora horas | É esperado — reconstrói a base com um LLM local. | Usa o seed (passo 3) em vez de `build`. |
