#!/usr/bin/env bash
# CASPAR — Configuration Vulnerability Meter (CVM) reference implementation
# Instalação via Docker (um único comando):
#   curl -fsSL https://raw.githubusercontent.com/AFilipe-IT/CASPAR/master/install.sh | sh
#
# Para uma instalação nativa (venv + pip, sem Docker), usa install-native.sh.

set -e

INSTALL_DIR="$HOME/.local/bin"
WRAPPER="$INSTALL_DIR/caspar"

echo "🔍 Checking dependencies..."
command -v docker >/dev/null 2>&1 || { echo "❌ Docker not found. Install it from https://docs.docker.com/get-docker/"; exit 1; }

# O Docker pode estar instalado mas inacessível: o utilizador não pertence ao
# grupo 'docker'. Vale a pena diagnosticar aqui, com a solução, em vez de
# deixar o 'docker pull' falhar com uma mensagem sobre sockets.
if ! docker info >/dev/null 2>&1; then
    echo "❌ Docker is installed but this user cannot reach it."
    echo
    echo "   Usual cause: '$USER' is not in the 'docker' group. Fix it with:"
    echo
    echo "     sudo usermod -aG docker \$USER"
    echo "     getent group docker  # confirm you are listed"
    echo "     sudo reboot"
    echo
    echo "   Rebooting is not overkill: groups are fixed when a session starts,"
    echo "   and on a desktop a new terminal inherits them from the session"
    echo "   that launched it. After rebooting, 'id -nG' must show 'docker'."
    echo "   Then run this installer again."
    echo
    echo "   Note: 'sudo curl … | sh' does NOT help — sudo applies to curl,"
    echo "   not to the shell running the script."
    exit 1
fi

echo "📦 Pulling CASPAR images..."
docker pull alfilipe/caspar:latest || { echo "❌ Failed to pull alfilipe/caspar:latest."; exit 1; }
docker pull alfilipe/caspar:full   || { echo "❌ Failed to pull alfilipe/caspar:full."; exit 1; }

echo "📝 Installing wrapper..."
mkdir -p "$INSTALL_DIR"

cat > "$WRAPPER" << 'WRAPPER_EOF'
#!/usr/bin/env bash
# CASPAR wrapper — abstrai Docker transparentemente

# Detectar se o comando precisa de build-time (Ollama).
# 'plugin fetch --then-install' corre 'plugin add' internamente, por isso
# precisa igualmente da imagem :full (com Ollama) — mas só com --then-install;
# um fetch simples (só download) fica na imagem leve.
BUILDTIME_CMDS="plugin add|build"
IMAGE="alfilipe/caspar:latest"
if echo "$*" | grep -qE "$BUILDTIME_CMDS" \
   || { echo "$*" | grep -q "plugin fetch" && echo "$*" | grep -q "\-\-then-install"; }; then
    IMAGE="alfilipe/caspar:full"
fi

# Escolher a pasta de trabalho a montar em /workspace. Por omissão é a cwd, mas
# se o utilizador passar um CAMINHO existente (ficheiro/pasta) fora da cwd — ex.:
# 'caspar watch ~/demo/apache2.conf' corrido de outro sítio — montamos a pasta
# DESSE caminho e reescrevemos o argumento para o caminho equivalente dentro do
# container. Assim o comando funciona de qualquer diretório.
# Excepções (ficam na cwd): modo --live (o alvo é um nome de serviço, não um
# caminho) e caminhos sob /etc (já montado read-only mais abaixo).
WORKDIR_HOST="$(pwd)"
if ! echo "$*" | grep -q "\-\-live"; then
    for _arg in "$@"; do
        case "$_arg" in
            -*) continue ;;                    # é uma flag, não um caminho
            /etc/*) continue ;;                # já coberto pelo mount de /etc
        esac
        if [ -e "$_arg" ]; then
            # Monta a pasta que CONTÉM o alvo e reescreve o argumento para o
            # caminho equivalente sob /workspace. Um ficheiro → monta o dirname;
            # uma pasta → monta a própria pasta. Funciona de qualquer cwd.
            if [ -d "$_arg" ]; then
                WORKDIR_HOST=$(cd "$_arg" && pwd)
                _wsarg="/workspace"
            else
                WORKDIR_HOST=$(cd "$(dirname "$_arg")" && pwd)
                _wsarg="/workspace/$(basename "$_arg")"
            fi
            _new=(); for _a in "$@"; do
                if [ "$_a" = "$_arg" ]; then _new+=("$_wsarg"); else _new+=("$_a"); fi
            done
            set -- "${_new[@]}"
            break
        fi
    done
fi

# Reescrever o valor de --log para o interior de /workspace, para que um caminho
# absoluto (ex.: --log ~/demo/watch.log) funcione dentro do container. Se cair
# dentro da pasta montada, converte para /workspace/<relativo>; se for só um
# nome (sem barra), fica como está (já resolve para /workspace). Assim o
# utilizador pode dar o log no mesmo sítio da config sem pensar no mount.
_new=(); _take_log=0
for _a in "$@"; do
    if [ "$_take_log" = "1" ]; then
        _take_log=0
        case "$_a" in
            /*)  # absoluto: se estiver sob a pasta montada, torna-o relativo a /workspace
                case "$_a" in
                    "$WORKDIR_HOST"/*) _new+=("/workspace/${_a#$WORKDIR_HOST/}") ;;
                    *)                 _new+=("$_a") ;;   # fora: deixa (o CASPAR avisa)
                esac ;;
            */*) _new+=("/workspace/$_a") ;;             # relativo com subpasta
            *)   _new+=("$_a") ;;                          # nome simples: já vai p/ /workspace
        esac
        continue
    fi
    _new+=("$_a")
    [ "$_a" = "--log" ] && _take_log=1
done
set -- "${_new[@]}"

# Montar a pasta escolhida em /workspace (leitura apenas por omissão).
# Excepção: 'watch --log' precisa de ESCREVER o ficheiro de log, logo read-write.
if echo "$*" | grep -qE "(^| )watch( |$)" && echo "$*" | grep -q "\-\-log"; then
    MOUNT_ARGS="-v $WORKDIR_HOST:/workspace"    # read-write: para o log
else
    MOUNT_ARGS="-v $WORKDIR_HOST:/workspace:ro"
fi

# Em modo --live (e watch), montar /etc do host (leitura) para inspecionar a
# configuração do serviço em execução. O bind-mount é uma vista live do host,
# por isso o 'watch' deteta edições feitas no host em tempo real.
# NOTA: NÃO montar /usr do host — mascararia o binário caspar da imagem
# (/usr/local/bin/caspar) e o container deixaria de arrancar.
# A deteção de versão recorre, neste modo, ao texto da configuração.
if echo "$*" | grep -qE "(\-\-live|(^| )watch( |$))"; then
    MOUNT_ARGS="$MOUNT_ARGS -v /etc:/etc:ro"
fi

# --notify: para o 'wall' de dentro do container alcançar os terminais do HOST,
# partilha-se os pseudo-terminais do host e a lista de logins (utmp). Sem isto,
# a notificação ficaria presa no container. Só quando --notify é pedido.
if echo "$*" | grep -q "\-\-notify"; then
    MOUNT_ARGS="$MOUNT_ARGS -v /dev/pts:/dev/pts -v /run/utmp:/run/utmp:ro"
fi

# --- Injeção de versão no modo --live --------------------------------------
# O container está isolado e não tem o binário do serviço, por isso não pode
# correr 'httpd -v'. Corremo-lo AQUI (no host, onde o serviço está instalado) e
# passamos --service-version ao container, para o cross-reference de CVEs/
# exploits funcionar. Só se o utilizador não tiver já indicado a versão.
VERSION_ENV=""
if echo "$*" | grep -q "\-\-live" \
   && ! echo "$*" | grep -qE "\-\-service-version"; then
    _svc=$(echo "$*" | sed -n 's/.*--live[= ]*\([^ ]*\).*/\1/p')
    _ver=""
    case "$_svc" in
        apache2|httpd|apache-httpd)
            _ver=$( { apache2 -v 2>/dev/null || httpd -v 2>/dev/null; } \
                    | sed -n 's#.*Apache/\([0-9][0-9.]*\).*#\1#p' | head -n1 ) ;;
        nginx)
            _ver=$(nginx -v 2>&1 | sed -n 's#.*nginx/\([0-9][0-9.]*\).*#\1#p' | head -n1) ;;
        sshd|ssh|openssh)
            _ver=$(sshd -V 2>&1 | sed -n 's#.*OpenSSH_\([0-9][0-9.]*\).*#\1#p' | head -n1) ;;
        mysql|mysqld|mariadb)
            _ver=$( { mysqld --version 2>/dev/null || mysql --version 2>/dev/null; } \
                    | sed -n 's#.*Ver \([0-9][0-9.]*\).*#\1#p' | head -n1 ) ;;
    esac
    if [ -n "$_ver" ]; then
        set -- "$@" --service-version "$_ver"
        echo "🔎 Versão detetada no host: $_svc $_ver (passada ao scan)" >&2
    fi
fi

# Montar volume persistente para modelos Ollama
OLLAMA_VOL="-v caspar_ollama_models:/root/.ollama"

# Relatórios: quando o comando usa --report, montar uma pasta ./reports do host
# em /reports (escrevível), para os ficheiros aparecerem DIRETAMENTE na máquina
# do utilizador — sem precisar de os extrair de um volume Docker. Fora de
# --report, usa o volume persistente (não polui o cwd com uma pasta vazia).
if echo "$*" | grep -q "\-\-report"; then
    mkdir -p "$(pwd)/reports"
    REPORTS_VOL="-v $(pwd)/reports:/reports"
else
    REPORTS_VOL="-v caspar_reports:/reports"
fi

# Montar volume persistente para dados (DB + plugins instalados via
# 'plugin add'/'plugin fetch --then-install'), para que sobrevivam ao --rm.
DATA_VOL="-v caspar_data:/home/caspar/data"

# Passar a variável de modelo, se definida
MODEL_ENV=""
if [ -n "$CASPAR_MODEL" ]; then
    MODEL_ENV="-e CASPAR_MODEL=$CASPAR_MODEL"
fi

# 'watch' é um daemon (loop até Ctrl-C). Dá-lhe um nome previsível para o poderes
# parar com 'docker stop caspar-watch', e permite só uma instância de cada vez.
# --init garante que Ctrl-C/kill/docker-stop chegam ao processo dentro do
# container e o param de imediato (sem --init o loop fica órfão).
NAME_ARG=""
if echo "$*" | grep -qE "(^| )watch( |$)"; then
    NAME_ARG="--name caspar-watch"
    docker rm -f caspar-watch >/dev/null 2>&1 || true
fi

exec docker run --rm --init $NAME_ARG \
    $MOUNT_ARGS \
    $OLLAMA_VOL \
    $REPORTS_VOL \
    $DATA_VOL \
    $MODEL_ENV \
    -w /workspace \
    "$IMAGE" "$@"
WRAPPER_EOF

chmod +x "$WRAPPER"

# Adicionar ao PATH, se necessário
if ! echo "$PATH" | grep -q "$INSTALL_DIR"; then
    echo "" >> "$HOME/.bashrc"
    echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$HOME/.bashrc"
    echo "" >> "$HOME/.zshrc" 2>/dev/null || true
    echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$HOME/.zshrc" 2>/dev/null || true
    export PATH="$HOME/.local/bin:$PATH"
fi

echo ""
echo "✅ CASPAR installed."
echo ""
echo "Usage examples:"
echo "  caspar targets                              # supported technologies"
echo "  caspar scan ./apache.conf                   # a file in the current directory"
echo "  caspar scan /etc/apache2/apache2.conf       # an installed service's config"
echo "  caspar scan --live apache2                  # a running service"
echo "  caspar scan docker://httpd:2.4              # a container image"
echo ""
echo "Paths are resolved inside the container: the file must exist on the host,"
echo "and relative paths are taken from the directory you run the command in."
echo ""
echo "To use a different model for knowledge building:"
echo "  CASPAR_MODEL=qwen2.5:14b caspar plugin add --source benchmark.pdf"
