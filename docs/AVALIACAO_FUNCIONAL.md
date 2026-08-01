# CASPAR — Avaliação Funcional (Ubuntu 22.04)

> **Propósito:** roteiro reproduzível para avaliar o CASPAR de ponta a ponta
> numa máquina Ubuntu 22.04 real (nativo, git clone + venv), e recolher os
> resultados para a secção de avaliação da dissertação. Cada passo diz o que
> correr, o que esperar, e o que **capturar** para a tese.
>
> Complementa [GUIA_VM_UBUNTU22.md](GUIA_VM_UBUNTU22.md) (preparar a VM do zero),
> [GUIA_TESTE_MAQUINA.md](GUIA_TESTE_MAQUINA.md) (setup) e
> [scripts/evaluate.py](scripts/evaluate.py) / [scripts/baseline_compare.py](scripts/baseline_compare.py).

---

## 0. Porque Ubuntu 22.04 (e não o WSL de dev)

O Ubuntu 22.04 real é o ambiente onde:
- o **OpenSCAP dá pass/fail reais** (no WSL dava `notapplicable` — os probes
  OVAL precisam de um sistema com systemd/kernel real e config aplicada);
- o SSG tem datastream para 22.04 (não há para 24.04 — daí a escolha da versão);
- a validação end-to-end reflecte o que um utilizador real faria.

---

## 1. Setup (uma vez)

```bash
# dependências de sistema
sudo apt-get update && sudo apt-get install -y \
  python3-venv poppler-utils sqlite3 openscap-scanner ssg-debderived trivy
# (trivy: se não estiver no apt, ver https://trivy.dev/latest/getting-started/installation/)

# clonar + ambiente
git clone https://github.com/AFilipe-IT/CASPAR.git caspar && cd caspar
python3 -m venv .venv && source .venv/bin/activate

# IMPORTANTE: atualizar o pip primeiro. O pip antigo do python3.10-venv (Ubuntu
# 22.04) tem um resolver que entra em backtracking infinito num `-e ".[dev]"`
# (ResolutionTooDeep). Atualizar + instalar deps directamente evita isso:
pip install --upgrade pip
pip install "pydantic>=2.0" "click>=8.1" "pyyaml>=6.0" pytest pytest-cov \
            openpyxl requests pypdf
pip install -e . --no-deps          # instala o pacote CASPAR sem re-resolver

# sanidade dos imports
python -c "import click, pydantic, yaml, cli.main; print('imports OK')"

# restaurar a base de conhecimento
sqlite3 ccss.db < data/ccss_canonical.sql
```

**Nota:** os PDFs de benchmark (material licenciado) não vêm no clone — 13
testes RAG do Apache fazem *skip*, o que é normal. Nada do que segue precisa deles.

---

## 2. Verificação de sanidade (unit + smoke)

```bash
python -m pytest tests/ -q                    # ~647 passed (uns skips)
python -m scripts.functional_check            # 13/13 checks (end-to-end)
```

✓ **Capturar:** o output do `functional_check` (13/13 PASS) — prova que todas
as capacidades funcionam integradas na máquina de teste.

---

## 3. Avaliação da metodologia (os números-âncora)

```bash
python -m scripts.evaluate
```

✓ **Capturar** (para a tese):
- **Composição da KB:** 12 targets, 514 regras, 32 chains, com proveniência.
- **Correção:** MAE vs CCE (Apache) — esperado **20/20, 0% mismatch, gate PASS**.
- **Deteção:** recall nas fixtures — esperado **100% (14/14)**.

---

## 4. Comparação com baselines

### 4.1 Trivy (IaC + Docker) — funciona em qualquer máquina

```bash
python -m scripts.baseline_compare
```

✓ **Capturar:** a tabela CASPAR vs Trivy (`.tf` 9-vs-13, Dockerfile 4-vs-5) e a
observação dos *blind spots* (o Trivy apanha `https_traffic_only_enabled` que o
build LLM mapeou como sinónimo `secure_transfer_required`).

### 4.2 OpenSCAP (Ubuntu OS) — **aqui é que o 22.04 real conta**

Primeiro, o CASPAR sobre o `sysctl.conf` **real** da máquina. O `/etc/sysctl.conf`
é legível sem privilégios, por isso **não precisas de sudo** aqui:

```bash
python -m cli.main scan /etc/sysctl.conf
# (o comando curto 'caspar' só existe após 'pip install -e .'; e com sudo o
#  venv não é visto — usa 'sudo .venv/bin/python -m cli.main …' se precisares)
```

Depois o OpenSCAP no mesmo sistema, e a comparação automática:

```bash
python -m scripts.baseline_compare --oscap
```

✓ **Capturar:** agora o OpenSCAP deve dar **pass/fail reais** (não
`notapplicable`) no subconjunto config-based sobreponível. Compara:
- nº de controlos que ambos avaliam (subconjunto sobreponível);
- OpenSCAP: pass/fail binário · CASPAR: score CCSS + narrativa por finding.

Para um relatório OpenSCAP navegável (opcional, boa figura para a tese):

```bash
DS=/usr/share/xml/scap/ssg/content/ssg-ubuntu2204-ds.xml
sudo oscap xccdf eval \
  --profile xccdf_org.ssgproject.content_profile_cis_level1_server \
  --results oscap-results.xml --report oscap-report.html "$DS"
# abre oscap-report.html no browser
```

---

## 5. Demonstração qualitativa (estudo de caso)

Mostra o ciclo detect → remediar → re-scan (bom para narrativa na tese). O
`fix` reescreve os valores inseguros para os do CIS (ASLR, syncookies, redirects…).

```bash
# usar uma cópia com o NOME CANÓNICO (o target 'ubuntu' deteta 'sysctl.conf')
mkdir -p /tmp/case && cp test_target/ubuntu_demo/sysctl.conf /tmp/case/sysctl.conf

# 1. scan da config insegura → score alto
caspar scan /tmp/case/sysctl.conf --report -f json -o /tmp/r/

# 2. remediação assistida (gera .fixed, não toca no original)
caspar fix /tmp/case/sysctl.conf --dry-run    # ver o diff proposto
caspar fix /tmp/case/sysctl.conf              # escreve /tmp/case/sysctl.conf.fixed

# 3. re-scan da versão corrigida → score baixo/zero
#    (renomear p/ o nome canónico para o scan detetar de novo)
cp /tmp/case/sysctl.conf.fixed /tmp/fixed/sysctl.conf 2>/dev/null || \
  (mkdir -p /tmp/fixed && cp /tmp/case/sysctl.conf.fixed /tmp/fixed/sysctl.conf)
caspar scan /tmp/fixed/sysctl.conf --report -f json -o /tmp/r2/

# 4. diff entre os dois scans (delta quantificado)
caspar diff /tmp/r/ccss_*.json /tmp/r2/ccss_*.json
```

✓ **Capturar:** o antes/depois (score alto → baixo) e o `diff` — evidência de
que a metodologia não só deteta, mas quantifica a melhoria da postura.

---

## 6. Reprodutibilidade (a afirmação central)

```bash
# o mesmo scan em duas máquinas / dois momentos → manifesto e score idênticos
caspar scan test_target/nginx.conf | grep reproducible
```

✓ **Capturar:** a linha `reproducible: caspar 0.1.0 · kb sha256:… · N rules`.
Se o `kb sha256` for igual ao desta documentação (mesma DB canónica), os scores
são idênticos por construção — a afirmação de determinismo, verificável.

---

## 7. Checklist de recolha para a tese

| # | Artefacto | Comando | Estado |
|---|---|---|---|
| 1 | Unit tests verdes | `pytest tests/ -q` | ☐ |
| 2 | Smoke test 13/13 | `scripts.functional_check` | ☐ |
| 3 | MAE 0% + recall 100% | `scripts.evaluate` | ☐ |
| 4 | Trivy vs CASPAR | `scripts.baseline_compare` | ☐ |
| 5 | **OpenSCAP pass/fail reais** | `scripts.baseline_compare --oscap` | ☐ |
| 6 | Relatório OpenSCAP HTML | `oscap xccdf eval --report` | ☐ |
| 7 | Estudo de caso detect→fix→re-scan | §5 | ☐ |
| 8 | Manifesto de reprodutibilidade | §6 | ☐ |

## Troubleshooting

- **`caspar: command not found`** → usa `python -m cli.main …`, ou garante que
  `~/.local/bin` está no PATH (instalação nativa).
- **OpenSCAP ainda dá `notapplicable`** → confirma que corres com `sudo` (os
  probes precisam de ler estado do sistema) e num Ubuntu real (não WSL).
- **`trivy` não instala pelo apt** → segue o instalador oficial (repo aquasec).
