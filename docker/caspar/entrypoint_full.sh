#!/bin/bash
# Entrypoint da imagem caspar:full — arranca o Ollama, garante o modelo
# necessário para comandos de build-time, e delega no caspar.
set -e

# Forçar Ollama local — ignorar qualquer OLLAMA_HOST externo (a imagem base
# define OLLAMA_HOST=http://ollama:11434 para o docker-compose, que não se
# aplica nesta imagem onde o Ollama corre dentro do próprio container).
export OLLAMA_HOST=http://localhost:11434

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

# Para plugin add / build, garantir que o modelo está disponível e funcional —
# exceto quando o LLM não vai ser usado (--no-llm) ou nada vai ser gerado
# (--dry-run).
if echo "$*" | grep -qE "plugin add|build" \
   && ! echo "$*" | grep -qE -- "--no-llm|--dry-run"; then

    # Verificar se o modelo está listado; descarregar se necessário.
    if ! ollama list 2>/dev/null | grep -q "$MODEL"; then
        echo "📥 A descarregar o modelo $MODEL (primeira utilização, pode demorar)..."
        ollama pull "$MODEL"
        sleep 2
    fi

    # Verificar se o modelo responde de facto (teste real, não só listado).
    echo "🔍 A verificar o modelo $MODEL..."
    TEST_RESPONSE=$(curl -sf -X POST http://localhost:11434/api/chat \
        -H "Content-Type: application/json" \
        -d "{\"model\":\"$MODEL\",\"messages\":[{\"role\":\"user\",\"content\":\"hi\"}],\"stream\":false}" \
        2>/dev/null | head -c 100)

    if [ -z "$TEST_RESPONSE" ]; then
        echo "⚠️ O modelo não responde — a recarregar..."
        ollama pull "$MODEL"
        sleep 3
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
