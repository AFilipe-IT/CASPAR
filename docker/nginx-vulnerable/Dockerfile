# Imagem Nginx deliberadamente vulnerável para validação end-to-end do CCSS-Scan.
# O scanner extrai /etc/nginx/ via `docker cp` e analisa nginx.conf.
#
# Build:  docker build -t ccss-test-nginx:vulnerable docker/nginx-vulnerable/
# Scan:   ccss scan docker://ccss-test-nginx:vulnerable --report
FROM nginx:1.27-alpine

# Config vulnerável (dispara as 18 regras + 3 attack chains do banco)
COPY nginx.conf /etc/nginx/nginx.conf

# Certificado self-signed para que ssl_certificate exista de facto
# (as regras condicionais if_directive:ssl_certificate são activadas
#  pela presença da directiva no config, mas geramos o cert para a
#  imagem ser funcional/realista).
RUN apk add --no-cache openssl \
 && mkdir -p /etc/nginx/ssl \
 && openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
        -keyout /etc/nginx/ssl/server.key \
        -out /etc/nginx/ssl/server.crt \
        -subj "/CN=vulnerable.example.com"

EXPOSE 443
