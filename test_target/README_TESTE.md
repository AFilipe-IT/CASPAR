# Alvo de teste worst-case — CCSS-Scan

Contém as **30 misconfigurations** do banco, para validar a deteção completa.

## Ficheiros

- `httpd.conf` — config Apache realística (com caminhos `.so` reais nos LoadModule)
- `Dockerfile` — empacota a config numa imagem para testar o modo `docker://`
- `gen_target.py` — script que gerou a config (regenerável)

## Pré-requisito

Aplicar o fix do LoadModule **antes** de testar (senão faltam 5 deteções):

```bash
python3 fix_loadmodule_parse.py    # na raiz ~/ccss_scan
```

## Teste 1 — modo ficheiro

```bash
ccss scan ~/ccss_scan/test_target/httpd.conf --report --format dashboard --output ~/relatorios/
```

## Teste 2 — modo Docker

```bash
cd ~/ccss_scan/test_target
docker build -t ccss-worstcase:latest .
ccss scan docker://ccss-worstcase:latest --report --format dashboard --output ~/relatorios/
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
