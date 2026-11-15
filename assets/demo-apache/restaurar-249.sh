#!/usr/bin/env bash
# Desfaz instalar-2.4.49.sh + vulneravel-249.sh: remove a árvore da build de
# origem e os links do PATH, e repõe o apache2 do sistema como estava.
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "corre com sudo"; exit 1; }
PREFIX=${PREFIX:-/opt/apache249}

rm -f /usr/local/bin/apache2 /usr/local/bin/apache2ctl
echo "  removidos: os links do PATH"

# A árvore só se apaga quando foi este script a instalá-la. Com um PREFIX dado
# por quem corre (uma build feita à mão), apagá-la seria destruir trabalho que
# não é nosso: desfaz-se o que a demonstração acrescentou e mais nada.
if [ "$PREFIX" = /opt/apache249 ]; then
  rm -rf "$PREFIX" /usr/local/src/httpd-2.4.49
  echo "  removidos: $PREFIX, fonte descomprimida"
  echo "  (os tarballs em /usr/local/src ficam, para não voltar a descarregar)"
else
  echo "  $PREFIX NÃO foi removido (PREFIX dado por ti — a build é tua)"
  if [ -f "$PREFIX/conf/httpd.conf.original" ]; then
    cp -a "$PREFIX/conf/httpd.conf.original" "$PREFIX/conf/httpd.conf"
    rm -rf "$PREFIX/conf/conf-enabled" "$PREFIX/conf/mods-enabled"
    echo "  httpd.conf reposto do backup; conf-enabled/ e mods-enabled/ removidos"
  fi
fi

if systemctl list-unit-files 2>/dev/null | grep -q '^apache2\.service'; then
  systemctl enable apache2 2>/dev/null || true
  echo "  serviço apache2 do sistema reactivado (não arrancado)"
fi
hash -r
echo "  which apache2 -> $(command -v apache2 || echo 'nenhum')"
