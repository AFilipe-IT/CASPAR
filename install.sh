#!/bin/bash
# install.sh — instalação local do CASPAR numa máquina nova (sem Docker).
set -e
echo "=== CASPAR Install ==="

# Verificar Python 3.11+
python3 --version || { echo "Python 3.11+ required"; exit 1; }

# Virtualenv
python3 -m venv .venv
source .venv/bin/activate

# Instalar
pip install --upgrade pip --quiet
pip install -e . --quiet

# Restaurar base de dados canónica a partir do SQL
sqlite3 ccss.db < data/ccss_canonical.sql

echo ""
echo "✅ CASPAR instalado com sucesso"
echo "   Activar: source .venv/bin/activate"
echo "   Testar:  caspar targets"
echo ""
echo "Para build-time (plugin add, build):"
echo "   Instalar Ollama: https://ollama.ai"
echo "   Descarregar modelo: ollama pull qwen2.5:14b"
