#!/bin/bash
# Entrypoint da imagem caspar:full — arranca o Ollama, garante o modelo
# necessário para comandos de build-time, e delega no caspar.
set -e

MODEL="${CASPAR_MODEL:-mistral:7b}"

# Iniciar o Ollama em background
ollama serve &
OLLAMA_PID=$!

# Aguardar que o Ollama fique pronto
echo "⏳ A iniciar Ollama..."
for i in $(seq 1 30); do
    if curl -sf http://localhost:11434/api/tags >/dev/null 2>&1; then
        break
    fi
    sleep 1
done

# Para plugin add / build, garantir que o modelo está disponível
if echo "$*" | grep -qE "plugin add|build"; then
    if ! ollama list 2>/dev/null | grep -q "$MODEL"; then
        echo "📥 A descarregar o modelo $MODEL (primeira utilização, pode demorar)..."
        ollama pull "$MODEL"
    fi
fi

# Executar o caspar (sem abortar antes de terminar o Ollama)
set +e
caspar "$@"
EXIT_CODE=$?
set -e

# Terminar o Ollama
kill "$OLLAMA_PID" 2>/dev/null || true

exit $EXIT_CODE
