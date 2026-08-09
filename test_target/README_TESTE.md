# Alvo de teste worst-case — CCSS-Scan

Contém as **30 misconfigurations** do banco, para validar a deteção completa.

## Ficheiros

- `httpd.conf` — config Apache realística (com caminhos `.so` reais nos LoadModule)
- `Dockerfile` — empacota a config numa imagem para testar o modo `docker://`

> Sem clone do repositório? `caspar demo` escreve configurações de exemplo
> (Apache e NGINX, vulnerável + endurecida) em qualquer instalação, incluindo
> a via Docker.

## Teste 1 — modo ficheiro

```bash
caspar scan test_target/httpd.conf --report --format dashboard -o relatorios/
```

## Teste 2 — modo Docker

```bash
docker build -t caspar-worstcase:latest test_target/
caspar scan docker://caspar-worstcase:latest --report --format dashboard -o relatorios/
```

## O que esperar

- **30 issues** detectadas (todas as do banco)
- **AV=Network** (há `Listen 80` e `Listen 443` — não-loopback)
- **Au=None** (sem AuthType+Require)
- Várias **attack chains** activas (privilege-escalation, webdav-rce, etc.)

Se aparecerem menos de 30, a directiva em falta indica ou um problema de
parsing/lookup ou uma regra que não dispara — usar como diagnóstico.

## Nota sobre valores exclusivos

`ServerTokens` (Full/Minor/OS), `SSLProtocol` (All/+SSLv3) e `Options`
(All/FollowSymLinks/Indexes) têm valores mutuamente exclusivos. Estão
isolados em blocos `<Directory>` distintos para que o parser os registe
todos (princípio worst-case). Num Apache funcional real só um de cada valeria,
mas para análise estática de cobertura isto está correcto.
