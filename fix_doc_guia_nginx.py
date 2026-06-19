"""
fix_doc_guia_nginx.py
----------------------
Atualiza o GUIA_TECNICO.md com a Fase 3 (plugin Nginx).

Três alterações:
  1. Secção 3: o build genérico deixou de ser "específico do Apache" — clarifica
     que llm_pipeline/chain_pipeline/narrative_pipeline/build_* servem ambos os
     plugins (vivem em apache_httpd/ por razões históricas).
  2. Adiciona uma subsecção "Plugin Nginx" ao mapa de ficheiros.
  3. Secção 9: passa de "fim da Fase 2" para incluir o estado da Fase 3, com as
     limitações honestas e os acoplamentos que a Fase 3 expôs e corrigiu.

Uso:
    python3 fix_doc_guia_nginx.py
"""

from __future__ import annotations
import sys
from pathlib import Path

path = Path("GUIA_TECNICO.md")
if not path.exists():
    print("ERROR: GUIA_TECNICO.md not found. Run from ~/ccss_scan.")
    sys.exit(1)

c = path.read_text(encoding="utf-8")
orig = c

if "Plugin Nginx (`plugins/nginx/`)" in c:
    print("Já atualizado — a saltar.")
    sys.exit(0)

# ── 1+2. Após a tabela do plugin Apache, acrescenta nota + tabela Nginx ──
anchor_apache_table = "| `validate_mae.py` | Valida scores contra o ground truth CCE |\n"
addition = anchor_apache_table + '''
> **Nota de arquitectura (Fase 3):** apesar de viverem na pasta `apache_httpd/`,
> os ficheiros `llm_pipeline.py`, `chain_pipeline.py`, `narrative_pipeline.py`,
> `build_llm.py` e `build_narratives.py` são **genéricos** — servem qualquer
> plugin. O plugin Nginx reutiliza-os tal como estão. Idealmente migrariam para
> `core/` (refactor futuro); por agora o Apache é a "casa" do código de build
> partilhado.

### Plugin Nginx (`plugins/nginx/`) — específico do Nginx

| Ficheiro | Responsabilidade |
|---|---|
| `parser.py` | Parser de raiz para a sintaxe Nginx (blocos `{}`, directivas `;`, `include`, contexto hierárquico `http>server>location`) |
| `rules.py` | Regras AV/Au específicas do Nginx (lê `listen`, `auth_basic`, `auth_request`) |
| `__init__.py` | Classe `NginxPlugin(Target)` + detecção (distingue de Apache) + auto-registo |
| `build_nginx.py` | Entry point do build — lista `ENTRIES` (8 misconfigs ancoradas no CIS NGINX v3.0.0); reutiliza o pipeline genérico do Apache |
| `CIS_NGINX_Benchmark_v3.0.0.pdf` | O benchmark-fonte para o RAG |

'''
if anchor_apache_table in c:
    c = c.replace(anchor_apache_table, addition, 1)
    print("\u2713 1+2: adicionada secção Plugin Nginx + nota de arquitectura")
else:
    print("\u26a0 1+2: anchor da tabela Apache não encontrado")

# ── 3. Substituir a secção 9 inteira ──
old_sec9_start = "## 9. Estado atual (fim da Fase 2)"
old_sec9_end = "\n---\n\n## 10. Glossário rápido"
i_start = c.find(old_sec9_start)
i_end = c.find(old_sec9_end)
if i_start != -1 and i_end != -1:
    new_sec9 = '''## 9. Estado atual (Fase 3 em curso — plugin Nginx funcional)

**Fase 2 (Apache) — fechada e validada:**
- 4 modos de scan, todos testados em máquina real
- Os 3 stages do LLM pipeline (métricas, chains, narrativas)
- CVE enrichment com NVD + KEV, key ativa
- Relatórios terminal / HTML / dashboard / JSON / SARIF
- 0% mismatch contra o ground truth CCE
- 30 misconfigurations, teste de cobertura automatizado que garante deteção completa

**Fase 3 (Nginx) — plugin funcional, paridade de relatório:**
- Parser de raiz para a sintaxe Nginx (blocos `{}` / `;`), distinta do Apache
- Detecção que distingue Nginx de Apache pelo conteúdo
- 8 misconfigurations, todas ancoradas em secções CIS NGINX v3.0.0 reais
- Build (Stage 1) + narrativas (Stage 3), agora **target-agnostic**
- Dashboard completo com drawer rico e terminologia 100% Nginx

**O que a Fase 3 expôs e corrigiu (acoplamentos implícitos ao Apache):**
Adicionar o 2.º plugin revelou três sítios onde o "core" assumia o formato Apache.
Corrigi-los tornou o sistema genuinamente extensível — é a evidência concreta de
extensibilidade para a tese:
1. **Parser RAG** (`core/rag.py`): o regex de secções só aceitava IDs de 2 níveis
   (`8.1`, estilo Apache); o CIS NGINX usa 3 (`2.5.1`). Generalizado para 2+ níveis.
2. **Prompt de build** (`llm_pipeline.py`): dizia "Apache HTTP Server" fixo.
3. **Prompt de narrativas** (`narrative_pipeline.py`): idem + "httpd.conf".
   Ambos passaram a receber o nome do serviço dinamicamente (`service_name`).

**Decisões de design da Fase 3 (limitações honestas):**
- **Sem CCE/MAE para Nginx**: o NGINX não tem ground truth CCE publicado como o
  Apache. O Nginx é validado por **revisão manual**; o Apache continua o caso de
  validação quantitativa. São contribuições complementares, não equivalentes.
- **Sem attack chains Nginx ainda**: 0 vs 9 do Apache (trabalho futuro).
- **Só directivas com secção CIS dedicada**: directivas sem âncora no benchmark
  (ex.: `autoindex`, `ssl_prefer_server_ciphers`) foram deliberadamente excluídas
  para manter cada misconfiguration rastreável à fonte.

**Pontos a ter em mente (transversais):**
- O factor de amplificação das chains precisa de fundamentação teórica para a tese
- As narrativas LLM são revisão-humana-recomendada (mitigadas, não garantidas)
- O build é agora **idempotente** (refazer com lista menor remove órfãs)
- O tempo de build LLM na máquina de referência é ~3 min/narrativa (CPU/GPU modesta)

**Por fazer (Fases 3-6):**
- Attack chains do Nginx; teste de cobertura Nginx
- Migrar o código de build genérico para `core/`
- Plugins SSH, Ubuntu, Docker
- Scheduler de refresh automático de CVE; report PDF; validação inter-analista (MAE)

'''
    c = c[:i_start] + new_sec9 + c[i_end + 1:]
    print("\u2713 3: secção 9 atualizada para Fase 3")
else:
    print("\u26a0 3: não encontrei os limites da secção 9")

path.write_text(c, encoding="utf-8")
print("\nGUIA_TECNICO.md atualizado.")
