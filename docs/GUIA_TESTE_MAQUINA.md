# CASPAR — Testar o framework numa máquina nova

> **Papel deste documento:** guia passo-a-passo para pôr o CASPAR a funcionar e validá-lo numa
> máquina limpa (Linux/WSL2), incluindo **como construir as imagens Docker a partir do código**.
> Complementa o [README.md](../README.md) (referência), o [GUIA_CASPAR.md](GUIA_CASPAR.md) (conceitos)
> e o [TESTAR_COMANDOS.md](TESTAR_COMANDOS.md) (checklist comando-a-comando de todo o CLI, uma vez
> já instalado). Este guia foca-se em **pôr a ferramenta de pé pela primeira vez**; o
> TESTAR_COMANDOS.md foca-se em **validar cada subcomando** depois disso.

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
git clone https://github.com/AFilipe-IT/CASPAR.git caspar
cd caspar
```

---

## 2. Via A — Nativa (venv), a mais rápida para validar

### 2.1 O caminho de um comando

```bash
bash install-native.sh
source .venv/bin/activate
```

`install-native.sh` faz exatamente os passos 2.1.1–2.1.3 abaixo (deps do sistema por conta do SO,
venv, pip, restauro da DB). Usa-o quando só queres a ferramenta a funcionar depressa. As secções
seguintes explicam o que ele faz por baixo — útil se algo falhar a meio ou quiseres correr os
passos manualmente.

> Build-time (`plugin add`, `build`) precisa ainda de Ollama nativo (`ollama pull qwen2.5:14b`,
> ~9GB) — a via nativa não o instala automaticamente. Se quiseres esse passo também automatizado,
> usa a Via B (Docker), cujo `install.sh` trata de tudo, Ollama incluído.

### 2.1.1 Dependências de sistema

```bash
sudo apt-get update && sudo apt-get install -y python3-venv poppler-utils sqlite3
# poppler-utils = pdftotext (extração de PDFs) · sqlite3 = restaurar a DB
```

### 2.1.2 Ambiente Python

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

### 2.1.3 Restaurar a base de conhecimento

```bash
sqlite3 ccss.db < data/ccss_canonical.sql
```

### 2.2 Validar — suite completa (offline, ~20-40s)

```bash
python -m pytest tests/ -q
```

✓ **Esperado:** `646 passed` (uns quantos *skips* se os PDFs licenciados não estiverem presentes —
normal). Nenhum teste precisa de rede nem de Ollama.

### 2.3 Smoke tests reais

```bash
python -m cli.main doctor                                    # integridade da DB
python -m cli.main targets                                   # 12 plugins listados
python -m cli.main scan test_target/test_nginx.conf           # ≈5.7/10 [Medium]
python -m cli.main scan test_target/pod_vulnerable.yaml       # ≈10.0 [Critical] + attack chain
python -m cli.main scan test_target/Dockerfile.vulnerable     # ≈9.0  [Critical]
```

✓ **Esperado:** cada scan termina com a linha `reproducible: caspar … · kb sha256:… · N rules (…)`.
O `kb sha256` é um fingerprint só do **conteúdo** da base de conhecimento (regras, chains,
enrichment de CVEs) — não do ficheiro `ccss.db` inteiro, que também guarda o histórico de scans e
cresce a cada execução. Por isso o hash **mantém-se igual entre execuções sucessivas na mesma
máquina** (podes confirmar repetindo o comando `scan` acima) e **deve ser igual ao de outra
máquina** desde que a DB tenha vindo do mesmo dump (`data/ccss_canonical.sql`) sem alterações às
regras — é o manifesto de reprodutibilidade a fazer o seu trabalho.

---

## 3. Via B — Docker: **construir as imagens a partir do código**

### 3.1 Pré-requisito

Docker instalado e a correr (`docker version` responde). Em WSL2: Docker Desktop com a integração
WSL ligada para a tua distro (Settings → Resources → WSL integration).

### 3.2 Ordem de build — IMPORTANTE

A `caspar:full` é `FROM caspar:latest` → **constrói sempre a `latest` primeiro**, senão a `full`
fica com código antigo. O contexto de build é a **raiz do repo** (o `.dockerignore` trata das
exclusões; o NISTIR 7502 é incluído por exceção — é a base de conhecimento CCSS partilhada).

```bash
cd caspar

# 1º — imagem runtime (leve: scan/report/watch/trend; sem Ollama)
docker build -t caspar:latest -f docker/caspar/Dockerfile .

# 2º — imagem build-time (com Ollama embutido: plugin add/fetch --then-install, build azure)
docker build -t caspar:full -f docker/caspar/Dockerfile.full .

# (opcional) slim — runtime mínimo
docker build -t caspar:slim -f docker/caspar/Dockerfile.slim .
```

### 3.3 Tagging para o wrapper

O wrapper `caspar` usa os nomes `alfilipe/caspar:latest|full` — dá esses nomes às tuas imagens locais:

```bash
docker tag caspar:latest alfilipe/caspar:latest
docker tag caspar:full   alfilipe/caspar:full
```

### 3.4 Instalar o wrapper SEM sobrepor as imagens locais

⚠️ O `install.sh` normal faz `docker pull`, o que **substituiria as imagens que acabaste de
construir** pelas publicadas no Docker Hub. Para testar código local, instala o wrapper saltando
os pulls:

```bash
sed '/docker pull/d' install.sh | sh
export PATH="$HOME/.local/bin:$PATH"    # se ~/.local/bin não estiver no PATH
```

(Para testar as imagens **publicadas** em vez das locais — o caso normal de um utilizador novo —
corre `install.sh` sem alterações: `curl -fsSL .../install.sh | sh`. Esse é o "um comando, tudo
configurado": o wrapper instalado escolhe sozinho a imagem `:full` quando o comando precisa de
Ollama, e o `entrypoint_full.sh` arranca o Ollama, descarrega `qwen2.5:14b` na primeira utilização
e confirma que o modelo respondeu antes de correr o `caspar` — sem passos manuais.)

### 3.5 Smoke tests em Docker

```bash
caspar doctor
caspar targets
caspar scan test_target/test_nginx.conf
caspar scan test_target/pod_vulnerable.yaml
```

✓ **Esperado:** mesmos resultados da via nativa (2.3). Primeiro uso semeia a DB no volume
`caspar_data` a partir do dump embutido; plugins fetched/manuais e a DB **sobrevivem ao `--rm`**
graças a esse volume.

### 3.6 Verificações específicas de Docker

```bash
# O NISTIR viajou dentro da imagem? (base de conhecimento RAG partilhada)
docker run --rm --entrypoint ls alfilipe/caspar:latest /home/caspar/app/nistir7502.pdf

# O pyyaml está lá? (parsers IaC)
docker run --rm --entrypoint python alfilipe/caspar:latest -c "import yaml; print('ok')"
```

### 3.7 Publicar no Docker Hub (quando quiseres atualizar as imagens públicas)

```bash
docker login
docker push alfilipe/caspar:latest
docker push alfilipe/caspar:full
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
| 1 | Suite de testes | `python -m pytest tests/ -q` | 646 passed, offline |
| 2 | DB íntegra | `caspar doctor` | ✓ healthy |
| 3 | Plugins registados | `caspar targets` | 12, incl. azure-iac/kubernetes/dockerfile |
| 4 | Scan clássico | `caspar scan test_target/test_nginx.conf` | ≈5.7 [Medium] |
| 5 | Scan IaC | `caspar scan test_target/pod_vulnerable.yaml` | ≈10.0 [Critical] + chain |
| 6 | Reprodutibilidade | rodapé `reproducible:` com o MESMO `kb sha256` entre execuções sucessivas e face à máquina original | manifesto igual ⇒ scores iguais |
| 7 | Persistência Docker | scan → `docker volume ls` → `caspar_data` existe | plugins/DB sobrevivem a `--rm` |

Depois deste checklist, usa o [TESTAR_COMANDOS.md](TESTAR_COMANDOS.md) para percorrer cada
subcomando do CLI individualmente.

## Troubleshooting rápido

- **`ModuleNotFoundError: yaml`** → `pip install pyyaml` (via A) ou reconstrói a imagem (a linha
  pip dos Dockerfiles já o inclui).
- **`pdftotext: not found`** → `sudo apt-get install poppler-utils`.
- **Docker "command not found" no WSL** → liga a integração WSL no Docker Desktop.
- **Testes RAG do apache em skip** → normal sem o PDF licenciado do benchmark; não afeta o runtime.
- **`caspar` usa imagens antigas** → confirma `docker images` e refaz o passo 3.3 (tagging);
  lembra: `latest` primeiro, `full` depois.
- **`kb sha256` diferente do esperado** → confirma que a DB veio do mesmo `data/ccss_canonical.sql`
  sem alterações manuais às tabelas de regras (`targets`/`misconfigurations`/`attack_chains`/
  `version_exploits`); o hash ignora o histórico de scans (`scan_results`), por isso correr scans
  não o altera, mas editar uma regra ou restaurar um dump diferente sim.
