# AEGIS — Testar o framework numa máquina nova

> **Papel deste documento:** guia passo-a-passo para pôr o AEGIS a funcionar e validá-lo numa
> máquina limpa (Linux/WSL2), incluindo **como construir as imagens Docker a partir do código**.
> Complementa o [README.md](README.md) (referência) e o [GUIA_AEGIS.md](GUIA_AEGIS.md) (conceitos).

---

## 0. O que viaja no git e o que NÃO viaja

O clone traz o código, os testes, a DB canónica (`data/ccss_canonical.sql`) e o NISTIR 7502.
**Não traz** (gitignored, material licenciado/local):

| Não viaja | Consequência | Se precisares |
|---|---|---|
| PDFs dos benchmarks CIS (Apache, Azure, …) | 13 testes RAG fazem *skip*; builds LLM não correm | copia a pasta `CIS_Microsoft_Azure/` e os PDFs dos plugins manualmente (scp/pen) |
| `ccss.db` | restaura-se do dump em 1 comando (passo 2.3) | — |
| `.env` (NVD API key) | enrichment online fica limitado | copia o teu `.env` |

O **scan e a suite de testes funcionam sem nada disto** — o runtime é offline por design.

---

## 1. Clonar

```bash
git clone https://github.com/AFilipe-IT/AEGIS.git sca
cd sca
```

---

## 2. Via A — Nativa (venv), a mais rápida para validar

### 2.1 Dependências de sistema

```bash
sudo apt-get update && sudo apt-get install -y python3-venv poppler-utils sqlite3
# poppler-utils = pdftotext (extração de PDFs) · sqlite3 = restaurar a DB
```

### 2.2 Ambiente Python

```bash
python3 -m venv .venv
source .venv/bin/activate
# Atualiza o pip PRIMEIRO — o pip antigo do python3.10 (Ubuntu 22.04) rebenta
# num `-e ".[dev]"` com ResolutionTooDeep. Instala as deps directamente:
pip install --upgrade pip
pip install "pydantic>=2.0" "click>=8.1" "pyyaml>=6.0" pytest pytest-cov \
            openpyxl requests pypdf
pip install -e . --no-deps
```

### 2.3 Restaurar a base de conhecimento

```bash
sqlite3 ccss.db < data/ccss_canonical.sql
```

### 2.4 Validar — suite completa (offline, ~20-40s)

```bash
python -m pytest tests/ -q
```

✓ **Esperado:** `~590 passed` (uns quantos *skips* se os PDFs licenciados não estiverem presentes —
normal). Nenhum teste precisa de rede nem de Ollama.

### 2.5 Smoke tests reais

```bash
python -m cli.main doctor                              # integridade da DB
python -m cli.main targets                             # ~11 plugins listados
python -m cli.main scan test_nginx.conf                # ≈5.7/10 [Medium]
python -m cli.main scan test_target/pod_vulnerable.yaml      # ≈10.0 [Critical] + attack chain
python -m cli.main scan test_target/Dockerfile.vulnerable    # ≈9.0  [Critical]
```

✓ **Esperado:** cada scan termina com a linha `reproducible: sca … · kb sha256:… · N rules (…)`.
O hash da kb deve ser **igual** ao da máquina original se a DB veio do mesmo dump — é o manifesto
de reprodutibilidade a fazer o seu trabalho.

---

## 3. Via B — Docker: **construir as imagens a partir do código**

### 3.1 Pré-requisito

Docker instalado e a correr (`docker version` responde). Em WSL2: Docker Desktop com a integração
WSL ligada para a tua distro (Settings → Resources → WSL integration).

### 3.2 Ordem de build — IMPORTANTE

A `aegis:full` é `FROM aegis:latest` → **constrói sempre a `latest` primeiro**, senão a `full`
fica com código antigo. O contexto de build é a **raiz do repo** (o `.dockerignore` trata das
exclusões; o NISTIR 7502 é incluído por exceção — é a base de conhecimento CCSS partilhada).

```bash
cd sca

# 1º — imagem runtime (leve: scan/report/watch/trend; sem Ollama)
docker build -t aegis:latest -f docker/aegis/Dockerfile .

# 2º — imagem build-time (com Ollama embutido: plugin add/fetch --then-install, build azure)
docker build -t aegis:full -f docker/aegis/Dockerfile.full .

# (opcional) slim — runtime mínimo
docker build -t aegis:slim -f docker/aegis/Dockerfile.slim .
```

### 3.3 Tagging para o wrapper

O wrapper `sca` usa os nomes `alfilipe/aegis:latest|full` — dá esses nomes às tuas imagens locais:

```bash
docker tag aegis:latest alfilipe/aegis:latest
docker tag aegis:full   alfilipe/aegis:full
```

### 3.4 Instalar o wrapper SEM sobrepor as imagens locais

⚠️ O `install.sh` normal faz `docker pull`, o que **substituiria as imagens que acabaste de
construir** pelas publicadas no Docker Hub. Para testar código local, instala o wrapper saltando
os pulls:

```bash
sed '/docker pull/d' install.sh | sh
export PATH="$HOME/.local/bin:$PATH"    # se ~/.local/bin não estiver no PATH
```

(Para testar as imagens **publicadas** em vez das locais, usa o `install.sh` normal.)

### 3.5 Smoke tests em Docker

```bash
sca doctor
sca targets
sca scan test_nginx.conf
sca scan test_target/pod_vulnerable.yaml
```

✓ **Esperado:** mesmos resultados da via nativa (2.5). Primeiro uso semeia a DB no volume
`aegis_data` a partir do dump embutido; plugins fetched/manuais e a DB **sobrevivem ao `--rm`**
graças a esse volume.

### 3.6 Verificações específicas de Docker

```bash
# O NISTIR viajou dentro da imagem? (base de conhecimento RAG partilhada)
docker run --rm --entrypoint ls alfilipe/aegis:latest /home/aegis/app/nistir7502.pdf

# O pyyaml está lá? (parsers IaC)
docker run --rm --entrypoint python alfilipe/aegis:latest -c "import yaml; print('ok')"
```

### 3.7 Publicar no Docker Hub (quando quiseres atualizar as imagens públicas)

```bash
docker login
docker push alfilipe/aegis:latest
docker push alfilipe/aegis:full
```

---

## 4. (Opcional) Build Azure IaC com LLM — precisa de Ollama e dos PDFs

Só necessário para **construir** a base de regras Azure; o scan de `.tf/.bicep/.json` funciona
assim que as regras existirem na DB (e a DB viaja no dump depois de fazeres o build + regenerares
o dump).

```bash
# 1. copia a pasta CIS_Microsoft_Azure/ para a máquina (não viaja no git)
# 2. Ollama nativo:                    ou via imagem :full (Ollama embutido)
ollama pull qwen2.5:14b

# 3. rever o mapeamento primeiro (dry-run), depois gravar
python -m config_assessment.plugins.azure_iac.build_azure \
  -b CIS_Microsoft_Azure/CIS_Microsoft_Azure_Storage_Services_Benchmark_v2.0.0.pdf \
  --model qwen2.5:14b --timeout 300 --dry-run
```

Notas: `--timeout 300` evita perder secções longas no 14b; `--model qwen2.5:7b` é ~3-4× mais
rápido com mapeamentos um pouco menos fiáveis; re-executar sem `--dry-run` é idempotente (upsert).

---

## 5. Checklist final

| # | Verificação | Como | Esperado |
|---|---|---|---|
| 1 | Suite de testes | `python -m pytest tests/ -q` | ~590 passed, offline |
| 2 | DB íntegra | `sca doctor` | ✓ healthy |
| 3 | Plugins registados | `sca targets` | ~11, incl. azure-iac/kubernetes/dockerfile |
| 4 | Scan clássico | `sca scan test_nginx.conf` | ≈5.7 [Medium] |
| 5 | Scan IaC | `sca scan test_target/pod_vulnerable.yaml` | ≈10.0 [Critical] + chain |
| 6 | Reprodutibilidade | rodapé `reproducible:` com o MESMO `kb sha256` da máquina original | manifesto igual ⇒ scores iguais |
| 7 | Persistência Docker | scan → `docker volume ls` → `aegis_data` existe | plugins/DB sobrevivem a `--rm` |

## Troubleshooting rápido

- **`ModuleNotFoundError: yaml`** → `pip install pyyaml` (via A) ou reconstrói a imagem (a linha
  pip dos Dockerfiles já o inclui).
- **`pdftotext: not found`** → `sudo apt-get install poppler-utils`.
- **Docker "command not found" no WSL** → liga a integração WSL no Docker Desktop.
- **Testes RAG do apache em skip** → normal sem o PDF licenciado do benchmark; não afeta o runtime.
- **`sca` usa imagens antigas** → confirma `docker images` e refaz o passo 3.3 (tagging);
  lembra: `latest` primeiro, `full` depois.
