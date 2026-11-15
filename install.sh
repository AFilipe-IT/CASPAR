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

# --- Modo demonstração (CASPAR_DEMO=1) ------------------------------------
# Para gravar o vídeo-anexo (docs/08_ROTEIRO_VIDEO.md) numa máquina limpa:
#
#   curl -fsSL https://raw.githubusercontent.com/AFilipe-IT/CASPAR/master/install.sh \
#     | CASPAR_DEMO=1 sh
#
# O princípio: o Docker serve para trazer a aplicação, e mais nada. Depois da
# instalação não se volta a escrever 'docker' — há 'caspar', há 'apache2ctl', e
# há a configuração do Apache em ~/cvm/apache-conf, que é um directório normal
# do disco. Quem grava vê uma aplicação local.
#
# Isso consegue-se montando a árvore de configuração do anfitrião para dentro
# do container. O efeito que interessa é o estado: 'caspar fix --in-place'
# escreve nos ficheiros do anfitrião, por isso a correcção sobrevive ao --rm e
# o re-scan seguinte — noutro container — lê-a. Sem esta montagem seria preciso
# manter um container vivo entre comandos, e isso aparecia em câmara.
#
# O wrapper é deliberadamente SEPARADO do normal, porque três coisas que o
# normal faz bem destruiriam a demonstração em silêncio:
#
#   1. monta /etc do host em --live. O alvo da demonstração é o 2.4.49, não o
#      apache2 que a máquina por acaso tenha;
#   2. corre 'apache2 -v' no host e injecta --service-version. Numa máquina com
#      apache2 instalado, isso passaria a versão do host (2.4.52, por exemplo)
#      e o relatório contradiria o ecrã;
#   3. monta o volume caspar_data. Um volume de uma instalação anterior traz a
#      base antiga, e o refresh de arranque só repõe as regras e as chains dos
#      alvos nativos — não os alvos nem os exploits. A digest deixaria de ser
#      83b3ee01f415, que é o número que aparece em ecrã.
#
# Por isso não há volume de dados nenhum: cada execução semeia a base a partir
# da imagem. É mais lento por uma fracção de segundo e é sempre o mesmo
# resultado, que numa demonstração de reprodutibilidade é o ponto todo.
if [ -n "${CASPAR_DEMO:-}" ]; then
    CVM_HOME="$HOME/cvm"

    echo "📦 Pulling the demo image..."
    docker pull alfilipe/caspar:demo \
      || { echo "❌ Failed to pull alfilipe/caspar:demo."; exit 1; }

    mkdir -p "$CVM_HOME"
    rm -rf "$CVM_HOME/apache-conf"
    _cid=$(docker create alfilipe/caspar:demo) \
      || { echo "❌ Could not create a container to copy from."; exit 1; }
    docker cp "$_cid:/usr/local/apache2/conf" "$CVM_HOME/apache-conf" >/dev/null \
      || { docker rm "$_cid" >/dev/null 2>&1; echo "❌ Could not copy the config tree."; exit 1; }
    docker rm "$_cid" >/dev/null 2>&1

    echo "📝 Installing commands (demo mode)..."
    mkdir -p "$INSTALL_DIR"

    # ---- caspar ----------------------------------------------------------
    cat > "$WRAPPER" << 'DEMO_WRAPPER_EOF'
#!/usr/bin/env bash
# CASPAR — modo demonstração.
#
# A configuração do Apache vem de ~/cvm/apache-conf, no disco: é isso que faz
# com que 'fix --in-place' e o re-scan seguinte vejam o mesmo ficheiro, apesar
# de serem containers diferentes. ~/cvm é a pasta de trabalho, por isso um
# '-o reports' aterra em ~/cvm/reports.
IMAGE="alfilipe/caspar:demo"
CVM_HOME="$HOME/cvm"

# Avaliar uma imagem externa ('caspar scan docker://nginx:1.24.0') significa
# puxá-la e extrair-lhe a configuração, e para isso o CASPAR fala com o daemon
# do anfitrião. O socket só é montado nessas invocações: dá controlo total da
# máquina a quem está lá dentro, e não há razão para o entregar a um scan que
# lê um ficheiro. --group-add evita ter de correr como root.
SOCK_ARGS=""
SCAN_DOCKER=no
case "$*" in
    *docker://*) SCAN_DOCKER=yes ;;
esac
if [ "$SCAN_DOCKER" = yes ]; then
    if [ -S /var/run/docker.sock ]; then
        SOCK_ARGS="-v /var/run/docker.sock:/var/run/docker.sock"
        _gid=$(stat -c %g /var/run/docker.sock 2>/dev/null || echo "")
        if [ -n "$_gid" ]; then SOCK_ARGS="$SOCK_ARGS --group-add $_gid"; fi
    else
        echo "Aviso: /var/run/docker.sock não existe — não é possível puxar" >&2
        echo "a imagem a avaliar. Verifica com 'docker info'." >&2
    fi
fi

# Sem httpd.conf não há nada para avaliar, e o erro que o scan daria seria
# "Service 'apache2' not found" — enganador, porque sugere que falta instalar
# alguma coisa quando o que falta é a árvore extraída. A exigência vale só para
# os comandos que lêem essa árvore: 'about' e 'targets' não a tocam, e uma
# imagem externa traz a sua própria configuração.
case "${1:-}" in
    scan|fix) LE_CONF=sim ;;
    *)        LE_CONF=nao ;;
esac
if [ "$SCAN_DOCKER" = yes ]; then LE_CONF=nao; fi
if [ "$LE_CONF" = sim ] && [ ! -f "$CVM_HOME/apache-conf/httpd.conf" ]; then
    echo "A configuração do Apache não está em $CVM_HOME/apache-conf." >&2
    echo "Corre 'caspar-demo-reset' para a repor." >&2
    exit 1
fi

TTY_ARG=""
if [ -t 1 ]; then TTY_ARG="-t"; fi

mkdir -p "$CVM_HOME/reports"
exec docker run --rm --init $TTY_ARG $SOCK_ARGS \
    -v "$CVM_HOME/apache-conf:/usr/local/apache2/conf" \
    -v "$CVM_HOME:/workspace" \
    -v "$CVM_HOME/reports:/reports" \
    -w /workspace \
    "$IMAGE" "$@"
DEMO_WRAPPER_EOF
    chmod +x "$WRAPPER"

    # ---- apache2ctl ------------------------------------------------------
    cat > "$INSTALL_DIR/apache2ctl" << 'DEMO_APACHECTL_EOF'
#!/usr/bin/env bash
# apache2ctl do 2.4.49 da demonstração, a validar a configuração local.
IMAGE="alfilipe/caspar:demo"
CVM_HOME="$HOME/cvm"
TTY_ARG=""
if [ -t 1 ]; then TTY_ARG="-t"; fi
exec docker run --rm --init $TTY_ARG \
    -v "$CVM_HOME/apache-conf:/usr/local/apache2/conf" \
    --entrypoint apache2ctl \
    "$IMAGE" "$@"
DEMO_APACHECTL_EOF
    chmod +x "$INSTALL_DIR/apache2ctl"

    # ---- determinismo.py -------------------------------------------------
    # O script vive dentro da imagem e precisa da base semeada. Os symlinks
    # ccss.db / ccss_alt.db existem para que a linha escrita em câmara seja
    # exactamente '--db ccss.db --alt-db ccss_alt.db', como no roteiro.
    cat > "$INSTALL_DIR/determinismo.py" << 'DEMO_DET_EOF'
#!/usr/bin/env bash
IMAGE="alfilipe/caspar:demo"
CVM_HOME="$HOME/cvm"
TTY_ARG=""
if [ -t 1 ]; then TTY_ARG="-t"; fi
exec docker run --rm --init $TTY_ARG \
    -v "$CVM_HOME:/workspace" \
    --entrypoint bash \
    "$IMAGE" -lc '
cd /home/caspar/app
caspar targets >/dev/null 2>&1
cp -f /home/caspar/data/ccss.db /home/caspar/data/ccss_alt.db
ln -sf /home/caspar/data/ccss.db ccss.db
ln -sf /home/caspar/data/ccss_alt.db ccss_alt.db
exec python3 assets/reproducao/determinismo.py "$@"
' determinismo "$@"
DEMO_DET_EOF
    chmod +x "$INSTALL_DIR/determinismo.py"

    # ---- caspar-demo-reset ----------------------------------------------
    cat > "$INSTALL_DIR/caspar-demo-reset" << 'DEMO_RESET_EOF'
#!/usr/bin/env bash
# Sem argumentos: repõe a configuração vulnerável de origem, entre tomadas.
# Com --all: apaga tudo — imagem, ~/cvm e os comandos — para voltar a correr
# o processo inteiro desde o 'docker pull'.
set -e
IMAGE="alfilipe/caspar:demo"
CVM_HOME="$HOME/cvm"
BIN="$(cd "$(dirname "$0")" && pwd)"

if [ "${1:-}" = "--all" ]; then
    echo "Isto apaga a imagem ($IMAGE), $CVM_HOME e os comandos instalados."
    echo "A imagem volta a ser descarregada na próxima instalação (~635 MB)."
    printf "Continuar? [s/N] "
    read -r resposta < /dev/tty
    case "$resposta" in
        s|S|y|Y) ;;
        *) echo "Nada foi apagado."; exit 0 ;;
    esac

    # Containers parados que tenham ficado para trás (as execuções usam --rm,
    # mas uma que falhe a arrancar pode deixar um).
    restos=$(docker ps -aq --filter "ancestor=$IMAGE" 2>/dev/null || true)
    if [ -n "$restos" ]; then
        docker rm -f $restos >/dev/null 2>&1 || true
        echo "  removidos: containers parados desta imagem"
    fi

    docker rmi "$IMAGE" >/dev/null 2>&1 \
      && echo "  removida: a imagem $IMAGE" \
      || echo "  a imagem $IMAGE já não estava presente"

    rm -rf "$CVM_HOME"
    echo "  removido: $CVM_HOME (configuração e relatórios)"

    rm -f "$BIN/caspar" "$BIN/apache2ctl" "$BIN/determinismo.py"
    echo "  removidos: caspar, apache2ctl, determinismo.py"
    echo ""
    echo "Limpo. Para recomeçar do princípio:"
    echo "  curl -fsSL https://raw.githubusercontent.com/AFilipe-IT/CASPAR/master/install.sh | CASPAR_DEMO=1 sh"
    echo ""
    echo "(A linha do PATH em ~/.bashrc fica — é a pasta normal de binários"
    echo " do utilizador e outras coisas podem depender dela.)"
    rm -f "$0"
    exit 0
fi

mkdir -p "$CVM_HOME"
rm -rf "$CVM_HOME/apache-conf"
cid=$(docker create "$IMAGE")
docker cp "$cid:/usr/local/apache2/conf" "$CVM_HOME/apache-conf" >/dev/null
docker rm "$cid" >/dev/null
echo "Configuração reposta: $CVM_HOME/apache-conf"
echo "O próximo 'caspar scan apache2 --live' volta a dar 8.5 / 10 HIGH."
echo ""
echo "Para apagar tudo (imagem incluída) e recomeçar: caspar-demo-reset --all"
DEMO_RESET_EOF
    chmod +x "$INSTALL_DIR/caspar-demo-reset"

    if ! echo "$PATH" | grep -q "$INSTALL_DIR"; then
        echo "" >> "$HOME/.bashrc"
        echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$HOME/.bashrc"
        export PATH="$HOME/.local/bin:$PATH"
    fi

    echo ""
    echo "✅ CASPAR installed in demo mode."
    echo ""
    echo "Everything from here on is local — no further docker commands:"
    echo "  caspar about"
    echo "  caspar scan apache2 --live"
    echo "  caspar fix apache2 --live --in-place"
    echo "  apache2ctl configtest"
    echo "  determinismo.py --runs 10 --db ccss.db --alt-db ccss_alt.db"
    echo ""
    echo "The Apache config is a normal directory you can edit:"
    echo "  $CVM_HOME/apache-conf/"
    echo "Reports land in $CVM_HOME/reports/."
    echo "Between takes, 'caspar-demo-reset' restores the vulnerable config."
    echo ""
    echo "Expected: apache-httpd 2.4.49 · 8.5 / 10 HIGH · 23 findings ·"
    echo "          8 chains · worst chain 10.0 · kb sha256:83b3ee01f415"
    echo ""
    echo "The 2.4.49 has a known RCE (CVE-2021-41773). The image never starts"
    echo "httpd and publishes no port — the scan reads the config tree on disk."
    exit 0
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
# Excepções, ambas casos em que o container tem mesmo de escrever no cwd:
#   - 'watch --log' escreve o ficheiro de log;
#   - '--report' com '-o pasta' escreve os relatórios nessa pasta. O -o é
#     relativo ao cwd, logo resolve para /workspace/<pasta>: com o mount
#     read-only o scan corria até ao fim e só depois rebentava no mkdir, com
#     um traceback de 'Read-only file system'. Sem -o não havia problema (cai
#     no CASPAR_REPORTS_DIR=/reports, montado à parte e escrevível), o que
#     tornava a falha tanto mais confusa.
if { echo "$*" | grep -qE "(^| )watch( |$)" && echo "$*" | grep -q "\-\-log"; } \
   || echo "$*" | grep -q "\-\-report"; then
    MOUNT_ARGS="-v $WORKDIR_HOST:/workspace"    # read-write: log / relatórios
else
    MOUNT_ARGS="-v $WORKDIR_HOST:/workspace:ro"
fi

# Em modo --live (e watch), montar /etc do host (leitura) para inspecionar a
# configuração do serviço em execução. O bind-mount é uma vista live do host,
# por isso o 'watch' deteta edições feitas no host em tempo real.
# NOTA: NÃO montar /usr do host — mascararia o binário caspar da imagem
# (/usr/local/bin/caspar) e o container deixaria de arrancar.
# 'serve' entra na mesma lista: a consola web oferece scan --live e watch sobre
# os serviços instalados, mas quem os corre é o processo dentro do container.
# Sem /etc montado, o container só via o seu próprio sistema de ficheiros e a
# consola respondia "service not found" para serviços que existem mesmo no
# host — o pedido nunca chegava a sair do container.
#
# Junto com /etc vai a base de dados de pacotes do dpkg, em leitura: como não
# montamos /usr, o binário do serviço não existe dentro do container e
# `apache2 -v` não responde. Sem versão não há cruzamento com exploits, e o
# mesmo ServerTokens que a CLI pontua 7.1 no host era pontuado 6.0 pelo
# servidor — lia-se como se o watch não reagisse às alterações. O ficheiro do
# dpkg é texto e dá a versão sem executar nada.
if echo "$*" | grep -qE "(\-\-live|(^| )watch( |$)|(^| )serve( |$))"; then
    MOUNT_ARGS="$MOUNT_ARGS -v /etc:/etc:ro"
    if [ -f /var/lib/dpkg/status ]; then
        MOUNT_ARGS="$MOUNT_ARGS -v /var/lib/dpkg/status:/var/lib/dpkg/status:ro"
    fi
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
        # Em inglês: é output da CLI, e a CLI é toda em inglês. Os comentários
        # deste script ficam em português, mas o que o utilizador vê não.
        echo "🔎 Detected on host: $_svc $_ver (passed to the scan)" >&2
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

# 'serve' expõe a API REST e a consola web. Sem publicar a porta, o servidor
# arrancava dentro do container e o utilizador via os URLs impressos no ecrã
# sem conseguir abrir nenhum — o container está isolado. Além da porta, é
# preciso forçar --host 0.0.0.0: o default 127.0.0.1 só aceita ligações de
# dentro do container, portanto a publicação da porta não bastaria.
PORT_ARGS=""
if echo "$*" | grep -qE "(^| )serve( |$)"; then
    # Precedência: --port explícito > CASPAR_PORT > 2027. A porta publicada tem
    # de ser a mesma em que o servidor escuta, senão o browser bate numa porta
    # aberta sem ninguém do outro lado — falha silenciosa e difícil de ler.
    _port=$(echo "$*" | sed -n 's/.*--port[= ]*\([0-9]\{1,\}\).*/\1/p' | head -n1)
    if [ -z "$_port" ]; then
        _port="${CASPAR_PORT:-2027}"
        set -- "$@" --port "$_port"
    fi
    PORT_ARGS="-p $_port:$_port"
    if ! echo "$*" | grep -q "\-\-host"; then
        set -- "$@" --host 0.0.0.0
    fi
    echo "🌐 Console: http://localhost:$_port/app   API: http://localhost:$_port/docs" >&2
fi

# Sem TTY o Docker não dá terminal ao container, o Click conclui que o output
# não é um terminal e desliga as cores — a CLI aparecia monocromática a quem
# instalasse por Docker. Só com terminal: com -t o Docker injecta \r em cada
# linha, o que corromperia 'caspar scan ... > ficheiro.txt' e pipes.
TTY_ARG=""
if [ -t 1 ]; then
    TTY_ARG="-t"
fi

exec docker run --rm --init $NAME_ARG $TTY_ARG \
    $PORT_ARGS \
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
