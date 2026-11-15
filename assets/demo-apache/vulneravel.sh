#!/usr/bin/env bash
# Põe o apache2 desta máquina numa configuração deliberadamente vulnerável,
# para a demonstração do vídeo-anexo (ver docs/08_ROTEIRO_VIDEO.md).
#
#   sudo bash vulneravel.sh          # aplica
#   sudo bash restaurar.sh           # desfaz
#
# NÃO correr numa máquina com serviço real. Faz snapshot da VM antes.
# O scan lê a árvore de configuração; não é preciso reiniciar o apache2.
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "corre com sudo"; exit 1; }
[ -f /etc/apache2/apache2.conf ] || { echo "apache2 não está instalado: apt install -y apache2"; exit 1; }

BK=/root/apache2-backup
if [ ! -d "$BK" ]; then
  cp -a /etc/apache2 "$BK"
  echo "  backup: $BK (intacto, usado pelo restaurar.sh)"
else
  echo "  backup já existe em $BK — não foi tocado"
fi

# 1. módulos que a base de conhecimento pontua e que compõem as chains
a2enmod -q dav dav_fs status info userdir autoindex || true

# 2. utilizador e grupo privilegiados — é o finding de topo (base 9.4)
sed -i 's|^User .*|User root|; s|^Group .*|Group root|' /etc/apache2/apache2.conf
grep -qE '^User root' /etc/apache2/apache2.conf || echo 'User root' >> /etc/apache2/apache2.conf
grep -qE '^Group root' /etc/apache2/apache2.conf || echo 'Group root' >> /etc/apache2/apache2.conf

# 3. o resto das directivas, num único drop-in identificável
cat > /etc/apache2/conf-available/99-cvm-demo.conf <<'EOF'
# Configuração deliberadamente vulnerável — demonstração CVM/CASPAR.
# Remover com:  a2disconf 99-cvm-demo
ServerTokens Full
ServerSignature On
TraceEnable On
Timeout 300
KeepAlive Off
MaxKeepAliveRequests 0
LogLevel emerg
FileETag All
LimitRequestLine 0
LimitRequestFields 0
LimitRequestFieldSize 0
LimitRequestBody 0
SSLCompression On
<Directory />
    Options All
    AllowOverride All
    Require all granted
</Directory>
EOF
a2enconf -q 99-cvm-demo

echo
apache2ctl configtest || echo "  (configtest com avisos — o scan funciona de qualquer forma)"
echo
echo "  pronto. Verifica com:"
echo "    caspar scan apache2 --live"
echo "  esperado: 8.5 / 10 HIGH · highest finding User 8.5 · highest chain 10.0 CRITICAL"
