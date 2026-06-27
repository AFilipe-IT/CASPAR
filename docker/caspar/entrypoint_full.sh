#!/bin/bash
set -e

export OLLAMA_HOST=http://localhost:11434
MODEL="${CASPAR_MODEL:-mistral:7b}"

# Iniciar Ollama em background
ollama serve &
OLLAMA_PID=$!

# Aguardar Ollama estar pronto (até 30s)
for i in $(seq 1 30); do
    if curl -sf http://localhost:11434/api/tags > /dev/null 2>&1; then
        break
    fi
    sleep 1
done

# Para plugin add/build SEM --no-llm: garantir modelo disponível ANTES do caspar
if echo "$*" | grep -qE "plugin add|build" && \
   ! echo "$*" | grep -q -- "--no-llm"; then

    # Descarregar modelo se não existir
    if ! ollama list 2>/dev/null | grep -q "^${MODEL}"; then
        echo "📥 A descarregar modelo $MODEL (primeira utilização, pode demorar)..."
        ollama pull "$MODEL"
    fi

    # Pré-carregar o modelo em memória para garantir que responde
    echo "🔄 A carregar modelo $MODEL..."
    curl -sf -X POST http://localhost:11434/api/chat \
        -H "Content-Type: application/json" \
        -d "{\"model\":\"$MODEL\",\"messages\":[{\"role\":\"user\",\"content\":\"ready\"}],\"stream\":false}" \
        > /dev/null 2>&1 || true

    echo "✅ Modelo pronto."
fi

# Executar caspar
caspar "$@"
EXIT_CODE=$?

kill $OLLAMA_PID 2>/dev/null || true
exit $EXIT_CODE
