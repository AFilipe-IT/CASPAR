#!/usr/bin/env bash
# Confirma que esta máquina reproduz os números publicados na dissertação.
# Uso:  bash verificar.sh [caminho-do-caspar]
# O argumento é o executável (por omissão `caspar`); num clone do repositório:
#   bash scripts/reproducao/verificar.sh ".venv/bin/python -m cli.main"
set -u
CASPAR=${1:-caspar}
export COLUMNS=100
T=${TEST_TARGET:-test_target}
ok=0; bad=0

# O quarto argumento de check() passa opções extra ao scan. Serve para fixar a
# versão do serviço: a pontuação de um achado que expõe a versão (server_tokens,
# ServerTokens, Banner) é amplificada quando essa versão tem exploits públicos,
# e sem --service-version a versão vem do binário instalado no hospedeiro. Sem
# fixar, o mesmo ficheiro dá 7.5 numa máquina com nginx 1.24.0 e 5.5 numa sem
# nginx — a diferença é do hospedeiro, não do ficheiro nem da base.
score() { $CASPAR scan "$1" ${4:-} 2>&1 | grep -oE '[0-9]+\.[0-9] / 10' | head -1 | cut -d' ' -f1; }
check() { # <ficheiro> <esperado> <rótulo> [opções-extra]
  local got; got=$(score "$1" "$2" "$3" "${4:-}")
  if [ "$got" = "$2" ]; then printf '  \033[32mOK\033[0m   %-34s %s\n' "$3" "$got"; ok=$((ok+1))
  else printf '  \033[31mFALHA\033[0m %-34s %s (esperado %s)\n' "$3" "${got:-sem score}" "$2"; bad=$((bad+1)); fi
}

echo "== base de conhecimento =="
$CASPAR targets 2>&1 | tail -3
echo
echo "== dez pares do corpus (vulnerável) =="
check "$T/pod_vulnerable.yaml"          10.0 "kubernetes"
check "$T/mysql_demo/my.cnf"             9.4 "mysql"
check "$T/Dockerfile.vulnerable"         9.0 "dockerfile"
check "$T/httpd.conf"                    8.5 "apache-httpd  (sensível ao fix GEL/GRL)"
check "$T/azure_storage_vulnerable.tf"   8.5 "azure-iac"
check "$T/ssh_demo/sshd_config"          8.5 "ssh"
check "$T/nginx.conf"                    7.5 "nginx  (versão fixada: 1.24.0)" "--service-version 1.24.0"
check "$T/ubuntu_demo/sysctl.conf"       5.8 "ubuntu"
check "$T/redis_demo/redis.conf"         5.0 "redis"
check "$T/tomcat_demo/tomcat.conf"       5.0 "tomcat"
echo
echo "== contrapartes endurecidas (todas 0.0) =="
for f in pod_hardened.yaml mysql_hardened_demo/my.cnf Dockerfile.hardened httpd_hardened.conf \
         azure_storage_hardened.tf nginx_hardened.conf; do
  [ -f "$T/$f" ] && check "$T/$f" 0.0 "${f%%/*}"
done
echo
echo "== agregação de pior caso (chains fora do score) =="
$CASPAR scan "$T/httpd.conf" 2>&1 | grep -E "Highest finding" | head -1
echo
echo "== manifesto de reprodutibilidade =="
$CASPAR scan "$T/nginx.conf" 2>&1 | grep -o "reproducible:.*" | head -1
echo
echo "resultado: $ok ok, $bad falhas"
[ "$bad" -eq 0 ]
