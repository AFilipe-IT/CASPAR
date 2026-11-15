#!/usr/bin/env bash
# Põe o Apache 2.4.49 de /opt/apache249 numa configuração deliberadamente
# vulnerável, com a mesma estrutura de inclusões do Debian (mods-enabled/,
# conf-enabled/), para a demonstração do vídeo-anexo (docs/08_ROTEIRO_VIDEO.md).
#
#   sudo bash vulneravel-249.sh      # aplica
#   sudo bash restaurar-249.sh       # desfaz
#
# O scan lê a árvore de configuração; não é preciso — nem se deve — arrancar o
# serviço. Snapshot da VM antes.
set -euo pipefail
[ "$(id -u)" -eq 0 ] || { echo "corre com sudo"; exit 1; }
PREFIX=${PREFIX:-/opt/apache249}
CONF=$PREFIX/conf
[ -x "$PREFIX/bin/httpd" ] || { echo "2.4.49 não está instalado: sudo bash instalar-2.4.49.sh"; exit 1; }

BK=$CONF/httpd.conf.original
[ -f "$BK" ] || { cp -a "$CONF/httpd.conf" "$BK"; echo "  backup: $BK"; }

mkdir -p "$CONF/mods-enabled" "$CONF/conf-enabled"

# 1. módulos que a base de conhecimento pontua e que compõem as chains.
#    Só se escreve o .load dos módulos que foram realmente compilados — assim o
#    ficheiro nunca refere um .so inexistente.
for pair in dav:mod_dav dav_fs:mod_dav_fs status:mod_status info:mod_info \
            userdir:mod_userdir autoindex:mod_autoindex; do
  name=${pair%%:*}; so=${pair##*:}
  if [ -f "$PREFIX/modules/$so.so" ]; then
    echo "LoadModule ${name}_module modules/$so.so" > "$CONF/mods-enabled/$name.load"
  else
    echo "  aviso: $so.so não foi compilado — $name fica de fora"
  fi
done

# 2. utilizador e grupo privilegiados — é o finding de topo (base 9.4 → 8.5)
sed -i 's|^User .*|User root|; s|^Group .*|Group root|' "$CONF/httpd.conf"
grep -qE '^User root'  "$CONF/httpd.conf" || echo 'User root'  >> "$CONF/httpd.conf"
grep -qE '^Group root' "$CONF/httpd.conf" || echo 'Group root' >> "$CONF/httpd.conf"

# 3. o httpd.conf de origem trai a demonstração se ficar como vem: os seus
#    blocos <Directory> têm `Options None FollowSymLinks` e `AllowOverride None`,
#    e o `fix` reescreve só o token mau, deixando um achado residual de Options
#    (e duas chains) de pé depois da remediação. Alinhá-los com o resto da
#    configuração vulnerável dá um estado inicial coerente — e um pós-fix limpo.
sed -i 's|^\( *\)Options .*|\1Options All|; s|^\( *\)AllowOverride .*|\1AllowOverride All|' \
    "$CONF/httpd.conf"

# 4. as duas inclusões que dão a travessia de Include em ecrã
grep -q 'mods-enabled' "$CONF/httpd.conf" || \
  sed -i '/^User root/i IncludeOptional mods-enabled/*.load' "$CONF/httpd.conf"
grep -q 'conf-enabled' "$CONF/httpd.conf" || \
  echo 'IncludeOptional conf-enabled/*.conf' >> "$CONF/httpd.conf"

# 5. o resto das directivas, num único drop-in identificável
cat > "$CONF/conf-enabled/99-cvm-demo.conf" <<'EOF'
# Configuração deliberadamente vulnerável — demonstração CVM/CASPAR.
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

echo
"$PREFIX/bin/apachectl" configtest || \
  echo "  (configtest com avisos — o scan funciona de qualquer forma)"
echo
echo "  pronto. Verifica com:"
echo "    caspar scan apache2 --live"
echo "  esperado:  Service: apache-httpd 2.4.49"
echo "             8.5 / 10 HIGH · highest finding User 8.5 · highest chain 10.0 · chains 8"
echo "             e, no dashboard, o painel de 7 exploits públicos"
