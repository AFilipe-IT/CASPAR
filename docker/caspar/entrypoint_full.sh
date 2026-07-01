#!/bin/bash
set -e

export OLLAMA_HOST=http://localhost:11434
MODEL="${CASPAR_MODEL:-mistral:7b}"

# Iniciar Ollama em background
ollama serve &
OLLAMA_PID=$!

# Aguardar Ollama estar vivo (/api/tags responde) — até 30s
for i in $(seq 1 30); do
    if curl -sf http://localhost:11434/api/tags > /dev/null 2>&1; then
        break
    fi
    sleep 1
done

# Decidir se este comando precisa do LLM (plugin add/build/fetch sem --no-llm).
# 'plugin fetch --then-install' corre 'plugin add' internamente, logo precisa
# igualmente do modelo pré-carregado.
NEEDS_LLM=0
if echo "$*" | grep -qE "plugin add|plugin fetch|build" && \
   ! echo "$*" | grep -q -- "--no-llm"; then
    NEEDS_LLM=1
fi

# Args extra a passar ao caspar. CRÍTICO: forçar o mesmo modelo que descarregamos
# aqui — o CLI usa por omissão qwen2.5:14b, que não existe na imagem, e o Ollama
# devolve 404 em /api/chat para um modelo não descarregado.
EXTRA_ARGS=()

if [ "$NEEDS_LLM" -eq 1 ]; then
    # Descarregar o modelo se ainda não existir
    if ! ollama list 2>/dev/null | grep -q "^${MODEL}"; then
        echo "📥 A descarregar modelo $MODEL (primeira utilização, pode demorar)..."
        ollama pull "$MODEL"
    fi

    # Carregar o modelo em memória e confirmar que /api/chat responde 200
    # (um modelo descarregado mas ainda não carregado responde na primeira chamada).
    echo "🔄 A carregar modelo $MODEL..."
    for i in $(seq 1 30); do
        CODE=$(curl -s -o /dev/null -w "%{http_code}" -X POST \
            http://localhost:11434/api/chat \
            -H "Content-Type: application/json" \
            -d "{\"model\":\"$MODEL\",\"messages\":[{\"role\":\"user\",\"content\":\"ready\"}],\"stream\":false}" \
            2>/dev/null || true)
        if [ "$CODE" = "200" ]; then
            break
        fi
        sleep 2
    done

    if [ "$CODE" != "200" ]; then
        echo "❌ O modelo $MODEL não respondeu (HTTP $CODE). Abortar." >&2
        kill "$OLLAMA_PID" 2>/dev/null || true
        exit 1
    fi
    echo "✅ Modelo pronto."

    # Garantir que o caspar usa exatamente o modelo carregado — exceto se o
    # utilizador já tiver indicado um modelo explicitamente.
    if ! echo "$*" | grep -qE -- "--model|(^| )-m( |$)"; then
        EXTRA_ARGS+=(--model "$MODEL")
    fi
fi

# Executar caspar (sem abortar antes de terminar o Ollama)
set +e
caspar "$@" "${EXTRA_ARGS[@]}"
EXIT_CODE=$?
set -e

kill "$OLLAMA_PID" 2>/dev/null || true
exit $EXIT_CODE
