#!/bin/bash
# install-native.sh — instalação local do CASPAR numa máquina nova (sem Docker).
# Para instalação automática com Docker (traz Ollama incluído), usa install.sh.
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

# A consola web vem construída no repositório (frontend/dist é versionado),
# precisamente para não obrigar ninguém a instalar Node. O 'pip install -e'
# acima é editable, por isso o 'caspar serve' serve esta pasta directamente.
# Só avisamos se faltar: quem apagou o dist ou clonou parcialmente fica a saber
# porque é que a consola não aparece, em vez de descobrir com um 404.
if [ ! -f frontend/dist/index.html ]; then
    echo "⚠️  frontend/dist ausente — a consola web não vai estar disponível." >&2
    echo "    A API REST funciona na mesma. Para a repor: git checkout frontend/dist" >&2
fi

echo ""
echo "✅ CASPAR instalado com sucesso"
echo "   Activar: source .venv/bin/activate"
echo "   Testar:  caspar targets"
echo "   Consola: caspar serve   →  http://127.0.0.1:8000/app"
echo ""
echo "Para build-time (plugin add, build):"
echo "   Instalar Ollama: https://ollama.ai"
echo "   Descarregar modelo: ollama pull qwen2.5:14b"
