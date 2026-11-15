# Gravação — passo a passo

Folha única para ter ao lado durante a gravação.

O Docker aparece uma vez, para trazer a aplicação. Depois disso não se escreve
`docker` outra vez: há `caspar`, há `apache2ctl`, e a configuração do Apache é
um directório normal em `~/cvm/apache-conf`.

---

## 0 · Instalar

```sh
curl -fsSL https://raw.githubusercontent.com/AFilipe-IT/CASPAR/master/install.sh | CASPAR_DEMO=1 sh
```

Fecha e reabre o terminal.

---

## 1 · Cena 1 — planos 2 e 3

```sh
caspar about
caspar targets
```

`CASPAR 1.0.0` · `kb sha256:83b3ee01f415` · 514 regras · 32 chains · 12 alvos.

---

## 2 · Cenas 2 e 3 — planos 5 a 15

```sh
caspar scan apache2 --live
caspar scan apache2 --live --report -f dashboard -o reports
```

**8.5 / 10 HIGH** · 23 findings · `Chains triggered 8` · `Highest chain 10.0`.

O HTML fica em `~/cvm/reports/`. Abre-o no browser para os planos 10 a 15.

---

## 3 · Cena 4 — planos 16 a 22

```sh
caspar fix apache2 --live --dry-run
```

`AUTOMATIC FIXES (29)` · `MANUAL STEPS (3)`.

```sh
caspar fix apache2 --live --in-place
apache2ctl configtest
caspar scan apache2 --live
```

`Syntax OK`, e depois **5.5 / 10 MEDIUM** · `Chains triggered 0`.

Agora as três correcções manuais. Abre o ficheiro:

```sh
nano ~/cvm/apache-conf/conf-enabled/99-cvm-demo.conf
```

e acrescenta no fim:

```apache
Header always append Content-Security-Policy "frame-ancestors 'self'"
Header set Referrer-Policy "strict-origin-when-cross-origin"
Header set Permissions-Policy "geolocation=(), microphone=(), camera=()"
```

```sh
apache2ctl configtest
caspar scan apache2 --live
```

`Syntax OK`, e depois **0.0 / 10 NONE**.

---

## 4 · Cena 5 — planos 23 a 25

```sh
determinismo.py --runs 10 --db ccss.db --alt-db ccss_alt.db
```

`total runs: 100` · `distinct digests per configuration: 1`.

---

## 5 · Entre tomadas

```sh
caspar-demo-reset
```

Repõe a configuração vulnerável. O scan seguinte volta a dar 8.5.

---

## Números que têm de aparecer no ecrã

| Momento | Score | Cadeias |
|---|---|---|
| Scan inicial | 8.5 HIGH | 8 |
| Depois do `fix --in-place` | 5.5 MEDIUM | 0 |
| Depois das 3 linhas `Header` | 0.0 NONE | 0 |

Rodapé em todas as execuções: `caspar 1.0.0 · kb sha256:83b3ee01f415`.
