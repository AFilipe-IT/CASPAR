"""
fix_doc_readme_nginx.py
------------------------
Atualiza o README.md com a Fase 3 (plugin Nginx).

Alterações:
  1. Tabela "Estado do projecto": Fase 3 passa a "em curso", com nota.
  2. Nova secção "## Target Nginx" a seguir à secção Target Apache, no mesmo
     formato (cobertura, decisões de design, limitações honestas).

Uso:
    python3 fix_doc_readme_nginx.py
"""

from __future__ import annotations
import sys
from pathlib import Path

path = Path("README.md")
if not path.exists():
    print("ERROR: README.md not found. Run from ~/ccss_scan.")
    sys.exit(1)

c = path.read_text(encoding="utf-8")
orig = c

if "## Target Nginx" in c:
    print("Já atualizado — a saltar.")
    sys.exit(0)

# ── 1. Atualizar a linha da Fase 3 na tabela de estado ──
old_phase3 = "| 3 | Plugins adicionais (Nginx, SSH, Ubuntu, Docker) | 🔜 A seguir |"
new_phase3 = "| **3** | Plugins adicionais — Nginx funcional; SSH/Ubuntu/Docker a seguir | 🔄 Em curso |"
if old_phase3 in c:
    c = c.replace(old_phase3, new_phase3, 1)
    print("\u2713 1: linha da Fase 3 atualizada")
else:
    print("\u26a0 1: linha da Fase 3 não encontrada verbatim")

# ── 2. Inserir secção Target Nginx antes de "## LLM pipeline (build time)" ──
# A secção Target Apache termina antes de "## LLM pipeline". Inserimos lá.
anchor = "## LLM pipeline (build time) — 3 stages"
nginx_section = '''## Target Nginx

Plugin da Fase 3, demonstra a extensibilidade da arquitectura para um servidor
com sintaxe de configuração fundamentalmente diferente (blocos `{}` + `;` em vez
do estilo chave-valor do Apache), com zero alterações às fórmulas do core.

### Cobertura

**8 misconfigurations**, todas ancoradas em secções reais do CIS NGINX Benchmark
v3.0.0, com narrativa completa gerada em Stage 3:

| Directiva | Valor | Secção CIS |
|---|---|---|
| `server_tokens` | on | 2.5.1 |
| `keepalive_timeout` | 65 / 0 | 2.4.3 |
| `send_timeout` | 0 | 2.4.4 |
| `client_max_body_size` | 0 | 5.2.2 |
| `ssl_protocols` | TLSv1 TLSv1.1 / SSLv3 | 4.1.4 |
| `proxy_pass` | http://127.0.0.1:8080 | 2.5.4 |

### Decisões de design (e limitações honestas)

- **Sem validação CCE/MAE**: ao contrário do Apache, o NGINX não tem ground truth
  CCE publicado. O Nginx é validado por **revisão manual**; o Apache mantém-se como
  o caso de validação quantitativa (MAE vs CCE). Contribuições complementares.
- **Só directivas com secção CIS dedicada**: directivas sem âncora no benchmark
  (`autoindex`, `ssl_prefer_server_ciphers`) foram excluídas para manter cada
  misconfiguration rastreável à fonte.
- **Sem attack chains ainda**: 0 vs 9 do Apache (trabalho futuro).

### O que o segundo plugin refinou no core

Adicionar o Nginx expôs três acoplamentos implícitos ao formato Apache, todos
corrigidos — evidência concreta de que a arquitectura é extensível:

1. **Parser RAG** (`core/rag.py`): o regex de secções só aceitava IDs de 2 níveis
   (`8.1`); o CIS NGINX usa 3 (`2.5.1`). Generalizado para 2+ níveis.
2. **Prompt de build e de narrativas**: tinham "Apache HTTP Server" / "httpd.conf"
   fixos. Passaram a receber o nome do serviço dinamicamente.

O build é também **idempotente**: refazer com uma lista de misconfigurations mais
pequena remove as entradas órfãs em vez de as deixar no banco.

### Build do Nginx

```bash
# Stage 1 (métricas) — usa o branch nginx do comando build
ccss build --target nginx --benchmark plugins/nginx/CIS_NGINX_Benchmark_v3.0.0.pdf

# Stage 3 (narrativas) — pipeline genérico, target nginx
python3 -m plugins.apache_httpd.build_narratives --db ccss.db --target nginx

# Scan
ccss scan /caminho/para/nginx.conf --report --format dashboard
```

---

'''
if anchor in c:
    c = c.replace(anchor, nginx_section + anchor, 1)
    print("\u2713 2: secção Target Nginx inserida")
else:
    print("\u26a0 2: anchor 'LLM pipeline' não encontrado")

path.write_text(c, encoding="utf-8")
print("\nREADME.md atualizado.")
