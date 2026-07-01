#!/usr/bin/env bash
# CASPAR — Configuration Assessment and Security Posture Automated Review
# Instalação via Docker (um único comando):
#   curl -fsSL https://raw.githubusercontent.com/AFilipe-IT/CASPAR/master/install.sh | sh
#
# Para uma instalação nativa (venv + pip, sem Docker), usa install-native.sh.

set -e

INSTALL_DIR="$HOME/.local/bin"
WRAPPER="$INSTALL_DIR/caspar"

echo "🔍 A verificar dependências..."
command -v docker >/dev/null 2>&1 || { echo "❌ Docker não encontrado. Instala em https://docs.docker.com/get-docker/"; exit 1; }

echo "📦 A descarregar imagens CASPAR..."
docker pull alfilipe/caspar:latest
docker pull alfilipe/caspar:full

echo "📝 A instalar wrapper..."
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

# Montar o directório actual para scan de ficheiros locais
MOUNT_ARGS="-v $(pwd):/workspace:ro"

# Em modo --live, montar /etc do host (leitura) para inspecionar a configuração
# do serviço em execução. NOTA: NÃO montar /usr do host — mascararia o binário
# caspar da imagem (/usr/local/bin/caspar) e o container deixaria de arrancar.
# A deteção de versão recorre, neste modo, ao texto da configuração.
if echo "$*" | grep -q "\-\-live"; then
    MOUNT_ARGS="$MOUNT_ARGS -v /etc:/etc:ro"
fi

# Montar volume persistente para modelos Ollama
OLLAMA_VOL="-v caspar_ollama_models:/root/.ollama"

# Montar volume persistente para relatórios
REPORTS_VOL="-v caspar_reports:/reports"

# Passar a variável de modelo, se definida
MODEL_ENV=""
if [ -n "$CASPAR_MODEL" ]; then
    MODEL_ENV="-e CASPAR_MODEL=$CASPAR_MODEL"
fi

exec docker run --rm \
    $MOUNT_ARGS \
    $OLLAMA_VOL \
    $REPORTS_VOL \
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
echo "✅ CASPAR instalado com sucesso!"
echo ""
echo "Exemplos de utilização:"
echo "  caspar targets"
echo "  caspar scan /etc/apache2/apache2.conf"
echo "  caspar scan --live apache2"
echo "  caspar plugin add --source CIS_PostgreSQL.pdf"
echo ""
echo "Para usar um modelo diferente:"
echo "  CASPAR_MODEL=qwen2.5:14b caspar plugin add --source benchmark.pdf"
