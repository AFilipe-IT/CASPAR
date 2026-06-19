# CCSS-Scan — worst-case test image
# Apache HTTP Server 2.4 com TODAS as 30 misconfigurations do banco.
# Usado para validar que o scanner deteta o conjunto completo.
FROM httpd:2.4

# Substituir a config pela versão worst-case
COPY httpd.conf /usr/local/apache2/conf/httpd.conf

# Nota: esta imagem NÃO arranca um Apache funcional (a config é
# deliberadamente insegura e algumas directivas conflituam). O objectivo
# é servir de alvo de análise estática para o CCSS-Scan, que lê a config
# sem a executar.
LABEL ccss.purpose="security-scan-test-target"
LABEL ccss.misconfigs="30"
