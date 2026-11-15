#!/usr/bin/env bash
# Instala o Apache httpd 2.4.49 a partir do código-fonte, em /opt/apache249,
# para que `caspar scan apache2 --live` detecte uma versão com linha em
# `version_exploits` — e portanto desenhe o painel de exploits públicos.
#
#   sudo bash instalar-2.4.49.sh
#   sudo bash vulneravel-249.sh      # aplica a configuração vulnerável
#   sudo bash restaurar-249.sh       # remove tudo
#
# ATENÇÃO: a 2.4.49 tem um path traversal com execução remota de código
# (CVE-2021-41773). Este script **não arranca** o serviço, e não deve ser
# arrancado: o CASPAR lê a configuração em disco, não precisa do processo.
# Usa uma VM descartável, sem exposição à rede, com snapshot feito antes.
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "corre com sudo"; exit 1; }

VER=2.4.49
PREFIX=${PREFIX:-/opt/apache249}
SRC=/usr/local/src/httpd-$VER
TGZ=httpd-$VER.tar.gz
BASE=https://archive.apache.org/dist/httpd

echo "== 1. dependências de compilação"
apt-get update -qq
apt-get install -y -qq build-essential wget libapr1-dev libaprutil1-dev \
                       libpcre3-dev libssl-dev libexpat1-dev

echo "== 2. código-fonte ($VER)"
mkdir -p /usr/local/src && cd /usr/local/src
[ -f "$TGZ" ]        || wget -q "$BASE/$TGZ"
[ -f "$TGZ.sha256" ] || wget -q "$BASE/$TGZ.sha256"
# O .sha256 publicado pelo Apache refere o nome da candidata a release
# ("httpd-2.4.49-rc1.tar.gz"), pelo que `sha256sum -c` falharia por nome. O que
# importa é o valor: compara-se o hash, antes de descomprimir.
esperado=$(awk '{print $1}' "$TGZ.sha256")
obtido=$(sha256sum "$TGZ" | awk '{print $1}')
[ "$esperado" = "$obtido" ] || { echo "  checksum FALHOU — não continuo"; exit 1; }
echo "  checksum ok ($obtido)"
rm -rf "$SRC"
tar xzf "$TGZ"

echo "== 3. compilação (demora alguns minutos)"
cd "$SRC"
# O APR e o APR-util vêm dos pacotes do sistema; aponta-se explicitamente para
# os seus `*-config` quando existem, que é o que falha mais vezes em silêncio.
APRFLAGS=""
[ -x /usr/bin/apr-1-config ] && APRFLAGS="--with-apr=/usr/bin/apr-1-config"
[ -x /usr/bin/apu-1-config ] && APRFLAGS="$APRFLAGS --with-apr-util=/usr/bin/apu-1-config"
# shellcheck disable=SC2086
./configure --prefix="$PREFIX" \
            --enable-so \
            --enable-mods-shared='most dav dav_fs info' \
            --with-mpm=prefork $APRFLAGS >/dev/null
make -j"$(nproc)" >/dev/null
make install >/dev/null
echo "  instalado em $PREFIX"

echo "== 4. binários no PATH antes dos do sistema"
# O resolver do CASPAR procura `apache2` no PATH e deduz a configuração de
# `apache2ctl -V` (HTTPD_ROOT + SERVER_CONFIG_FILE). /usr/local/bin vem antes de
# /usr/sbin no PATH por omissão, pelo que estes dois links decidem a detecção.
ln -sf "$PREFIX/bin/httpd"    /usr/local/bin/apache2
ln -sf "$PREFIX/bin/apachectl" /usr/local/bin/apache2ctl

echo "== 5. o apache2 do sistema não pode responder primeiro"
if systemctl list-unit-files 2>/dev/null | grep -q '^apache2\.service'; then
  systemctl stop apache2    2>/dev/null || true
  systemctl disable apache2 2>/dev/null || true
  echo "  serviço apache2 do sistema parado e desactivado (o binário continua instalado)"
fi

echo
echo "== 6. verificação"
hash -r
echo "  which apache2      -> $(command -v apache2)"
echo "  apache2 -v         -> $(apache2 -v | head -1)"
apache2ctl -V 2>/dev/null | grep -E 'HTTPD_ROOT|SERVER_CONFIG_FILE' | sed 's/^/  /'
echo
echo "  próximo passo:  sudo bash vulneravel-249.sh"
