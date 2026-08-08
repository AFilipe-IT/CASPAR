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

**Esperado:** o texto de ajuda, começando por
`CASPAR — Configuration Vulnerability Meter (CVM) reference implementation.`

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

**Esperado** — o cabeçalho CASPAR, seguido de:

```
  Total Score (worst-case): 8.9/10 (HIGH)   Total Findings: 4
  Highest issue 7.1   Highest chain 8.9   (overall driven by attack chain)
  Attack Chains Triggered: 1   Directives Scanned: 3

  [HIGH]     8.1    ServerTokens         : ServerTokens Full expõe a versão…
  [MEDIUM]   5.16   Header               : sem Content-Security-Policy…
  [MEDIUM]   8.2    ServerSignature      : ServerSignature On revela a versão…
  [MEDIUM]   5.8    TraceEnable          : HTTP TRACE permite Cross-Site Tracing…

  [HIGH] info-disclosure-chain: ServerTokens -> ServerSignature   Score: 8.9
```

**O código de saída é 1, e isso está correcto.** Não é um erro: `caspar scan`
devolve 1 quando encontra problemas, para poder ser usado como gate de CI. Um
scan de uma configuração limpa devolve 0.

Repara no resultado central da metodologia: o score global (8.9) é **superior ao
pior finding individual** (7.1). Isso é a cadeia de ataque — `ServerTokens` e
`ServerSignature` isoladamente são divulgação de informação; combinadas dão ao
atacante versão exacta *e* confirmação do software. É precisamente o que um
scanner de conformidade pass/fail não captura.

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
run 1: score=8.9  sha=a9621ace0f0fe8e4
run 2: score=8.9  sha=a9621ace0f0fe8e4
run 3: score=8.9  sha=a9621ace0f0fe8e4
run 4: score=8.9  sha=a9621ace0f0fe8e4
run 5: score=8.9  sha=a9621ace0f0fe8e4
```

Se os hashes divergirem, **não continues** — é um problema de reprodutibilidade
e deve ser registado, não contornado.

> O valor exacto do hash depende da versão da base de conhecimento; o que tem
> de se verificar é que as cinco linhas são **iguais entre si**. Este teste não
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

**Esperado:** `774 passed`.

Se isto falhar com `ResolutionTooDeep`, o pip está desactualizado — corre
`pip install --upgrade pip` e repete (ver secção 2). Em alternativa,
`pip install pytest pytest-cov` instala o mesmo sem passar pelo resolvedor
do extra.

---

## 6. Caminho alternativo: Docker

Não precisa de Python, nem de clonar o repositório, nem do passo do seed — a
imagem já traz a base de conhecimento e semeia-a na primeira utilização.

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
| Consola web (React) | `caspar serve`, depois `http://127.0.0.1:8000/app` |

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
