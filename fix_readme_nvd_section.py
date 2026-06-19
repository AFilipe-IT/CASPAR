"""
fix_readme_nvd_section.py
----------------------------
Expande a secção "Configurar a NVD API key" no README com instruções
completas: onde fica o ficheiro, como trocar a key, como verificar que
está activa.

Uso:
    python3 fix_readme_nvd_section.py
"""

from pathlib import Path

path = Path("README.md")
content = path.read_text(encoding="utf-8")

old = """### Configurar a NVD API key (opcional mas recomendado)

```bash
cat > .env << 'EOF'
NVD_API_KEY=<a-tua-key>
EOF
```

Pede uma key gratuita em https://nvd.nist.gov/developers/request-an-api-key — sem ela o CVE enrichment usa 5 req/30s (lento mas funcional); com ela, 50 req/30s. O `.env` está no `.gitignore`, nunca é commitado."""

new = """### Configurar a NVD API key (opcional mas recomendado)

A key fica num ficheiro `.env` na **raiz do projecto** (`~/ccss_scan/.env`), nunca no código fonte. O `.gitignore` já o exclui — nunca é commitado, mesmo que faças `git add .`.

```bash
cd ~/ccss_scan
echo "NVD_API_KEY=<a-tua-key>" > .env
```

Pede uma key gratuita em https://nvd.nist.gov/developers/request-an-api-key (chega por email, normalmente em minutos). Sem key: 5 req/30s. Com key: 50 req/30s.

**Verificar que a key está activa:**

```bash
curl -s -o /tmp/nvd_test.json -w "HTTP_STATUS:%{http_code}\\n" \\
  "https://services.nvd.nist.gov/rest/json/cves/2.0?cveId=CVE-2004-2320" \\
  -H "apiKey: <a-tua-key>"
```

`HTTP_STATUS:200` com JSON de resposta → key activa. `403` → key inválida ou ainda não propagada (novas keys podem demorar algumas horas). `429` → rate limited, espera 30s e tenta de novo.

**Trocar a key** (se expirar ou for revogada): edita o mesmo ficheiro, não precisas de tocar em código nenhum.

```bash
echo "NVD_API_KEY=<nova-key>" > ~/ccss_scan/.env
```

O `core/cve_enricher.py` lê automaticamente de `.env` via `get_nvd_api_key()` — qualquer comando (`ccss refresh`, `ccss build`) já a usa sem precisares de passar `--nvd-key` manualmente."""

assert old in content, "Secção não encontrada — verifica se o README já foi editado manualmente"
content = content.replace(old, new, 1)
path.write_text(content, encoding="utf-8")
print("README.md actualizado — secção NVD API key expandida")
