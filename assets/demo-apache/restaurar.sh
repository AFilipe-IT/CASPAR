#!/usr/bin/env bash
# Desfaz o vulneravel.sh: repõe /etc/apache2 a partir do backup.
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "corre com sudo"; exit 1; }
BK=/root/apache2-backup
[ -d "$BK" ] || { echo "não há backup em $BK — repõe o snapshot da VM"; exit 1; }
rm -f /etc/apache2/conf-available/99-cvm-demo.conf /etc/apache2/conf-enabled/99-cvm-demo.conf
rm -rf /etc/apache2
cp -a "$BK" /etc/apache2
apache2ctl configtest
echo "  /etc/apache2 reposto a partir de $BK"
