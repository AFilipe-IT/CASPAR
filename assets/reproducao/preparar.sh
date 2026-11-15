#!/usr/bin/env bash
# Reprodução independente: prepara uma máquina limpa para repetir as medições
# publicadas na dissertação a partir do pacote no PyPI, sem clonar o
# repositório. Uso:
#
#   curl -fsSL https://raw.githubusercontent.com/AFilipe-IT/cvm/master/scripts/reproducao/preparar.sh | bash
#
# Não toca em nada fora do directório de trabalho (por omissão ~/cvm-reproducao)
# e não precisa de sudo: o pacote é instalado num venv próprio.
set -euo pipefail

VER=1.0.0
KB=83b3ee01f415
DIR=${1:-$HOME/cvm-reproducao}
# Permite apontar para um clone local durante o desenvolvimento:
#   BASE=file:///home/.../cvm/scripts/reproducao bash preparar.sh
BASE=${BASE:-https://raw.githubusercontent.com/AFilipe-IT/cvm/master/scripts/reproducao}

say() { printf '\n\033[1m==\033[0m %s\n' "$1"; }
die() { printf '\n\033[31merro:\033[0m %s\n' "$1" >&2; exit 1; }

# -- pré-requisitos ----------------------------------------------------------
command -v python3 >/dev/null || die "python3 não está instalado (apt-get install python3 python3-venv)"
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' \
  || die "é preciso Python 3.10 ou superior (encontrado $(python3 -V 2>&1))"
python3 -c 'import venv' 2>/dev/null || die "falta o módulo venv (apt-get install python3-venv)"
if command -v curl >/dev/null; then GET='curl -fsSL -o'
elif command -v wget >/dev/null; then GET='wget -qO'
else die "é preciso curl ou wget"; fi

say "directório de trabalho: $DIR"
mkdir -p "$DIR"; cd "$DIR"

# -- o pacote ----------------------------------------------------------------
say "venv e instalação de cvm-caspar==$VER"
[ -d .venv ] || python3 -m venv .venv
# shellcheck disable=SC1091
source .venv/bin/activate
# A versão é fixada de propósito: é a que a dissertação mede, e fixá-la torna a
# instalação imune ao índice do PyPI em cache (max-age=600) na máquina.
pip install -q --upgrade pip
# O extra [api] traz o uvicorn/fastapi, que o `caspar serve` precisa para as
# tomadas da API e da consola web. A CLI funciona sem ele.
pip install -q --no-cache-dir "cvm-caspar[api]==$VER"
caspar --version

# -- o corpus experimental ---------------------------------------------------
# O wheel leva o pacote; o corpus dos dez pares viaja no sdist publicado.
if [ ! -d test_target ]; then
  say "corpus experimental (test_target/, dez pares) a partir do sdist publicado"
  tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
  pip download -q --no-binary :all: --no-deps --no-cache-dir -d "$tmp" "cvm-caspar==$VER"
  tar xzf "$tmp"/cvm_caspar-$VER.tar.gz --strip-components=1 "cvm_caspar-$VER/test_target"
  printf '  %s ficheiros\n' "$(find test_target -type f | wc -l)"
fi

# -- scripts de medição ------------------------------------------------------
# Não vão no pacote (não são código do produto), por isso vêm do repositório.
say "scripts de medição"
for f in determinismo.py verificar.sh; do
  [ -f "$f" ] || $GET "$f" "$BASE/$f"
  printf '  %s\n' "$f"
done

# -- base de conhecimento ----------------------------------------------------
say "base de conhecimento canónica (caspar init)"
caspar init

# -- verificação -------------------------------------------------------------
say "verificação: os dez pares contra os valores publicados"
bash verificar.sh caspar
got=$(caspar scan test_target/nginx.conf | grep -o 'sha256:[0-9a-f]*' | head -1)
if [ "$got" != "sha256:$KB" ]; then
  die "digest da base de conhecimento é $got, esperado sha256:$KB — esta não é a versão que a dissertação mede"
fi

cat <<EOF

Pronto. Para usar nesta sessão ou numa futura:

  cd $DIR && source .venv/bin/activate

Determinismo (cena 7):

  cp ccss.db ccss_alt.db
  python determinismo.py --runs 10 --db ccss.db --alt-db ccss_alt.db
EOF
