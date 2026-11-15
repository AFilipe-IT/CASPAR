# Gravação — passo a passo

Folha única para ter ao lado durante a gravação.

O Docker aparece uma vez, para trazer a aplicação. Depois disso não se escreve
`docker` outra vez: há `caspar`, há `apache2ctl`, e a configuração do Apache é
um directório normal em `~/cvm/apache-conf`. A cena 5 usa um segundo alvo real
— o nginx instalado nesta VM — lido pelo mesmo contentor, sempre em leitura.

---

## 0 · Instalar (ou reinstalar)

```sh
curl -fsSL https://raw.githubusercontent.com/AFilipe-IT/CASPAR/master/install.sh | CASPAR_DEMO=1 bash
```

Fecha e reabre o terminal. **Reinstala mesmo que já tenhas instalado antes** —
é esta versão que publica a porta do `caspar serve` e monta `/etc/nginx` do
anfitrião; sem reinstalar, a cena 5 não funciona.

---

## 0.1 · Preparar o nginx (antes de gravar, fora de câmara)

```sh
nginx -v                                    # confirma que está instalado
sudo cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.original   # salvaguarda
sudo nano /etc/nginx/nginx.conf
```

Dentro do bloco `http { }`, garante estas cinco linhas (a maioria dos
`nginx.conf` do Ubuntu já tem `ssl_protocols TLSv1.3;` — não tocar nessa):

```nginx
server_tokens on;

add_header Content-Security-Policy "default-src 'self'; frame-ancestors 'self';" always;
add_header Strict-Transport-Security "max-age=63072000; includeSubDomains" always;
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
```

```sh
sudo nginx -t                               # Syntax OK
caspar scan nginx --live
```

Tem de dar **5.0 / 10 MEDIUM**, finding único `server_tokens`. Se der outro
número, falta alguma das quatro linhas `add_header` — sem elas o CSP em falta
já vale 5.5 por si só, e corrigir o `server_tokens` em câmara não move nada.

É só isto que fica deliberadamente errado: `server_tokens on`. É a única
linha que se toca durante a gravação, no plano 24.

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

O HTML fica em `~/cvm/reports/`. Para os planos 10 a 15, abre-o com:

```bash
caspar-report
```

Sem argumento abre o relatório mais recente, para não teres de escrever
um nome com timestamp em câmara.

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

Plano 23 — repete um dos scans já feitos (basta uma captura do rodapé, não
precisa de correr outra vez: `reproducible: caspar 1.0.0 · kb sha256:83b3ee01f415`).

Plano 24 — a consola web:

```sh
caspar serve
```

Abre `http://localhost:2027/app` → página **Watch** → botão **Installed
service** → selecciona `nginx` na lista (aparece como detectado) → deixa o
intervalo em 2 s → **Start watching**.

Confirma no ecrã: **5.0 / 10 · MEDIUM**, finding `server_tokens`.

Corta para o terminal:

```sh
sudo nano /etc/nginx/nginx.conf
```

Muda a única linha — `server_tokens on` → `server_tokens off` — grava, sai.

```sh
sudo nginx -t
```

Corta de volta ao browser, sem tocar em nada: a sessão já mostra
**0.0 / 10 · NONE**. Não recarregues a página — o ponto do plano é precisamente
que ela se actualiza sozinha.

---

## 5 · Entre tomadas

```sh
caspar-demo-reset
```

Repõe a configuração do Apache. O scan seguinte volta a dar 8.5.

Repor o nginx para repetires a cena 5 é à mão, porque é a configuração real
da máquina, não algo que o `caspar-demo-reset` toque. Os quatro `add_header`
continuam lá — só a linha do `server_tokens` voltou a mudar:

```sh
sudo sed -i 's/server_tokens off;/server_tokens on;/' /etc/nginx/nginx.conf
sudo nginx -t
caspar scan nginx --live    # confirma 5.0 / 10 MEDIUM
```

Se alguma coisa correu mal e preferes recomeçar do zero, `nginx.conf.original`
(passo 0.1) é a configuração de fábrica, sem nada do CASPAR — tens de repetir
todo o passo 0.1 a partir dela.

---

## 6 · Recomeçar do zero

```sh
caspar-demo-reset --all
```

Apaga a imagem, `~/cvm` e os comandos, depois de confirmares. Para voltar a
ter tudo, corre outra vez o passo 0 — a imagem é descarregada de novo.

---

## Números que têm de aparecer no ecrã

| Momento | Score | Cadeias |
|---|---|---|
| Scan inicial (apache) | 8.5 HIGH | 8 |
| Depois do `fix --in-place` | 5.5 MEDIUM | 0 |
| Depois das 3 linhas `Header` | 0.0 NONE | 0 |
| Watch, nginx, antes da correcção | 5.0 MEDIUM | 1 |
| Watch, nginx, depois (`server_tokens off`) | 0.0 NONE | 0 |

Rodapé em todas as execuções: `caspar 1.0.0 · kb sha256:83b3ee01f415`.
