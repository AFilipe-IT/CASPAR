# Gravação — passo a passo

Folha única para ter ao lado durante a gravação.
Tudo corre dentro de **um** contentor: se fechares, perdes as correcções.

---

## 0 · Na VM, uma vez (fora de câmara)

```sh
docker pull alfilipe/caspar:demo
mkdir -p ~/reports
```

---

## 1 · Abrir o contentor (fora de câmara)

```sh
docker run --rm -it --init --hostname cvmtese \
  -v "$HOME/reports:/reports" \
  -w /home/caspar/app \
  --entrypoint bash alfilipe/caspar:demo -l
```

A partir daqui, tudo é escrito dentro deste contentor.

---

## 2 · Cena 1 — planos 2 e 3

```sh
caspar about
caspar targets
```

Esperado: `CASPAR 1.0.0`, `kb sha256:83b3ee01f415`, 514 regras · 32 chains · 12 alvos.

---

## 3 · Cena 2 e 3 — planos 5 a 15

```sh
caspar scan apache2 --live
caspar scan apache2 --live --report -f dashboard -o /reports
```

Esperado: `apache-httpd 2.4.49` · **8.5 / 10 HIGH** · 23 findings ·
`Chains triggered 8` · `Highest chain 10.0`.

O HTML fica em `~/reports/` **no anfitrião** — abre-o no browser para os planos 10 a 15.

> Usa `-o /reports`. Com `-o reports` o ficheiro não sai do contentor.

---

## 4 · Cena 4 — planos 16 a 22

```sh
caspar fix apache2 --live --dry-run
```

Esperado: `AUTOMATIC FIXES (29)` e `MANUAL STEPS (3)`.

```sh
caspar fix apache2 --live --in-place
apache2ctl configtest
```

Esperado: `Syntax OK`.

```sh
caspar scan apache2 --live
```

Esperado: **5.5 / 10 MEDIUM** · `Chains triggered 0`.

Agora as três linhas manuais:

```sh
cat >> /usr/local/apache2/conf/conf-enabled/99-cvm-demo.conf <<'EOF'
Header always append Content-Security-Policy "frame-ancestors 'self'"
Header set Referrer-Policy "strict-origin-when-cross-origin"
Header set Permissions-Policy "geolocation=(), microphone=(), camera=()"
EOF
apache2ctl configtest
caspar scan apache2 --live
```

Esperado: `Syntax OK` e **0.0 / 10 NONE**.

---

## 5 · Cena 5 — planos 23 a 25

```sh
cp /home/caspar/data/ccss.db /home/caspar/data/ccss_alt.db
python3 assets/reproducao/determinismo.py --runs 10 \
  --db /home/caspar/data/ccss.db \
  --alt-db /home/caspar/data/ccss_alt.db
```

Esperado: `total runs: 100` e `distinct digests per configuration: 1`.

---

## 6 · Repetir uma cena

```sh
exit
```

E volta ao passo 1 — o contentor novo traz a configuração vulnerável outra vez.

---

## Números que têm de aparecer no ecrã

| Momento | Score | Cadeias |
|---|---|---|
| Scan inicial | 8.5 HIGH | 8 |
| Depois do `fix --in-place` | 5.5 MEDIUM | 0 |
| Depois das 3 linhas `Header` | 0.0 NONE | 0 |

Rodapé em todas as execuções: `caspar 1.0.0 · kb sha256:83b3ee01f415`.
