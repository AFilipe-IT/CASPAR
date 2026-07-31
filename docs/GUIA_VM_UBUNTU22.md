# AEGIS — Preparar uma VM Ubuntu 22.04 limpa para testes

> **Papel deste documento:** guia do zero absoluto — VM acabada de instalar, sem Docker, sem
> Python configurado, sem nada do projeto. Cobre **Docker (via principal)** e **nativa venv/pip**
> (via de comparação), na mesma máquina. Depois de a VM estar pronta, segue para o
> [GUIA_TESTE_MAQUINA.md](GUIA_TESTE_MAQUINA.md) (validação) e o
> [TESTAR_COMANDOS.md](TESTAR_COMANDOS.md) (checklist comando-a-comando).

Assume-se acesso à internet normal (`apt`, `curl`, `docker pull`, `ollama pull` — sem proxy nem
rede isolada).

---

## 0. Atualizar o sistema

```bash
sudo apt-get update && sudo apt-get upgrade -y
```

---

## 1. Via principal — Docker (1 comando, tudo automático)

### 1.1 Instalar o Docker Engine

O Ubuntu 22.04 traz um `docker.io` desatualizado nos repositórios padrão; usa o repositório oficial
da Docker para uma versão atual:

```bash
# Dependências do repositório
sudo apt-get install -y ca-certificates curl gnupg

# Chave GPG oficial da Docker
sudo install -m 0755 -d /etc/apt/keyrings
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/docker.gpg
sudo chmod a+r /etc/apt/keyrings/docker.gpg

# Repositório
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] https://download.docker.com/linux/ubuntu \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null

sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
```

### 1.2 Correr o Docker sem `sudo` (recomendado)

```bash
sudo usermod -aG docker "$USER"
```

⚠️ Esta alteração só é aplicada numa **sessão nova** — faz logout/login (ou `newgrp docker` para a
sessão atual) e depois confirma:

```bash
docker version   # deve responder sem sudo e sem erro de permissão
```

### 1.3 Instalar o AEGIS — um comando

```bash
curl -fsSL https://raw.githubusercontent.com/AFilipe-IT/CASPAR/master/install.sh | sh
export PATH="$HOME/.local/bin:$PATH"   # só se o script avisar que não está no PATH ainda
```

Isto:
- confirma que o Docker existe,
- faz `docker pull` das duas imagens públicas (`alfilipe/aegis:latest` leve, `alfilipe/aegis:full`
  com Ollama embutido),
- instala o wrapper `sca` em `~/.local/bin`.

### 1.4 Validar

```bash
sca doctor       # integridade da DB
sca targets      # 12 plugins listados
sca scan /etc/nginx/nginx.conf 2>/dev/null || echo "(sem nginx instalado na VM — normal)"
```

Para um alvo garantido sem precisares de instalar nginx/apache na VM, usa os ficheiros de teste do
próprio repositório — mas nota que **estes só existem se clonares o repo** (ver §3); a instalação
via `curl | sh` sozinha não traz o código-fonte, só o wrapper `sca` que fala com as imagens Docker.
Para scans reais nesta VM, aponta o `sca scan` a configurações que já existam nela (ex.:
`/etc/ssh/sshd_config`, `/etc/nginx/nginx.conf` se tiveres esses serviços instalados) ou clona o
repo (§3) para teres os fixtures de exemplo em `test_target/`.

### 1.5 (Opcional) Build-time — testar o download automático do Ollama/modelo

```bash
sca plugin add --source /caminho/para/um/benchmark.pdf
```

Na primeira utilização de um comando de build-time (`plugin add`, `build`, `fetch --then-install`),
o container `:full` arranca sozinho o Ollama, descarrega `qwen2.5:14b` (~9GB, demora — depende da
tua ligação) e só depois corre o comando. Não precisas de instalar Ollama na VM para isto — vive
dentro do container, com o modelo guardado no volume Docker `caspar_ollama_models` (sobrevive a
`--rm`, não precisa de novo download da próxima vez).

---

## 2. Via de comparação — nativa (venv + pip, sem Docker)

Útil para comparar comportamento/desempenho com a via Docker, ou se quiseres depurar código
diretamente sem camada de container.

### 2.1 Clonar o repositório

```bash
git clone https://github.com/AFilipe-IT/CASPAR.git sca
cd sca
```

### 2.2 Instalar — um comando

```bash
bash install-native.sh
source .venv/bin/activate
```

Isto instala as dependências de sistema (`python3-venv`, `poppler-utils`, `sqlite3`), cria o venv,
instala os pacotes Python e restaura a base de conhecimento a partir de `data/ccss_canonical.sql`.

### 2.3 Validar

```bash
python -m pytest tests/ -q                                   # 646 passed
sca doctor
sca targets                                                   # 12 plugins
sca scan test_target/test_nginx.conf                          # ≈5.7/10 [Medium]
sca scan test_target/pod_vulnerable.yaml                      # ≈10.0 [Critical] + chain
```

### 2.4 (Opcional) Build-time nativo — precisa de Ollama à parte

Ao contrário da via Docker, aqui o Ollama **não** é automático:

```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama pull qwen2.5:14b     # ~9GB
```

---

## 3. Se quiseres o código-fonte também na via Docker (fixtures de teste, docs)

A via Docker (§1) instala só o wrapper `sca` — não traz o repositório. Se quiseres os mesmos
fixtures de `test_target/` para testar via Docker, clona o repo à parte (não interfere com o
wrapper já instalado):

```bash
git clone https://github.com/AFilipe-IT/CASPAR.git sca-src
cd sca-src
sca scan test_target/test_nginx.conf     # usa o wrapper Docker já instalado, com o repo só como fonte de fixtures
```

---

## 4. Checklist final da VM

| # | Verificação | Como | Esperado |
|---|---|---|---|
| 1 | Docker sem sudo | `docker version` | responde sem erro de permissão |
| 2 | AEGIS instalado (Docker) | `sca doctor` | ✓ healthy |
| 3 | Plugins (Docker) | `sca targets` | 12 |
| 4 | Nativa instalada | `python -m pytest tests/ -q` (dentro do venv) | 646 passed |
| 5 | Persistência Docker | `docker volume ls` | `aegis_data`, `caspar_ollama_models` existem |

---

## Troubleshooting rápido

- **`permission denied` ao correr `docker`** → falta logout/login (ou `newgrp docker`) depois do
  `usermod -aG docker`.
- **`docker: command not found`** após instalar → confirma que os pacotes `docker-ce*` instalaram
  sem erro (`dpkg -l | grep docker-ce`); em VMs sem virtualização aninhada ativa, o `containerd`
  pode falhar a arrancar — confirma `sudo systemctl status docker`.
- **`curl: (6) Could not resolve host`** → a VM não tem rede — confirma o adaptador de rede da VM
  (NAT/bridged) nas definições do hipervisor.
- **Download do modelo lento/interrompido** → o `caspar_ollama_models` é um volume persistente;
  repetir o comando retoma sem re-descarregar as camadas já obtidas pelo `ollama pull`.
- Para problemas depois de instalado (imagens antigas, DB, etc.), ver a secção de troubleshooting
  do [GUIA_TESTE_MAQUINA.md](GUIA_TESTE_MAQUINA.md#troubleshooting-rápido).
