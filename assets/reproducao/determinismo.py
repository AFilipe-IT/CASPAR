"""
assets/video/determinismo.py
----------------------------
Versão autónoma de scripts/determinism_scan.py, para correr fora do repositório.

O wheel publicado no PyPI (`cvm-caspar`) leva o pacote, não leva o diretório
scripts/, pelo que `python -m scripts.determinism_scan` não existe numa
instalação por pip. Este ficheiro repete a mesma medição usando apenas o que a
instalação já tem (config_assessment + cli._discovery) e o corpus em
test_target/, para que a experiência de determinismo possa ser repetida a
partir de `pip install cvm-caspar`, sem clonar o repositório.

A lógica -- o que entra no digest e o que fica de fora -- é a de
scripts/determinism_scan.py: o digest cobre o resultado da avaliação (score
global, severidade, achados ordenados com base e temporal, cadeias detetadas) e
deliberadamente não cobre o relatório JSON completo, que traz um scan_id e um
timestamp novos em cada execução por desenho.

Uso:
    python determinismo.py [--runs 10] [--db ccss.db] [--alt-db outra.db]
                           [--corpus test_target]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import defaultdict
from pathlib import Path

from config_assessment.core.db.database import Database
from config_assessment.core.runtime import scan as run_scan
from cli._discovery import _discover_plugins

# Versões fixadas por fixture. Um achado que expõe a versão do serviço é
# amplificado quando essa versão tem exploits públicos, e sem versão explícita
# o scan vai buscá-la ao binário instalado no hospedeiro — o que faria a
# pontuação depender da máquina. A dissertação mede o nginx com a 1.24.0.
PINNED_VERSIONS = {
    "nginx.conf": "1.24.0",
}

FIXTURES = [
    "pod_vulnerable.yaml",
    "mysql_demo/my.cnf",
    "Dockerfile.vulnerable",
    "httpd.conf",
    "azure_storage_vulnerable.tf",
    "ssh_demo/sshd_config",
    "nginx.conf",
    "ubuntu_demo/sysctl.conf",
    "redis_demo/redis.conf",
    "tomcat_demo/tomcat.conf",
]


def digest(result) -> str:
    """Digest estável apenas do resultado da avaliação."""
    payload = {
        "global_score": result.global_temporal_score,
        "severity": result.severity,
        "findings": sorted(
            (i.directive, i.bad_value, i.base_score, i.temporal_score)
            for i in result.issues
        ),
        "chains": sorted(
            (c.chain_id, c.amplified_score) for c in (result.chains or [])
        ),
    }
    blob = json.dumps(payload, sort_keys=True, ensure_ascii=False, default=str)
    return hashlib.sha256(blob.encode()).hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--runs", type=int, default=10)
    ap.add_argument("--db", default="ccss.db")
    ap.add_argument("--alt-db", default=None,
                    help="segunda base de dados com o mesmo conhecimento")
    ap.add_argument("--corpus", default="test_target",
                    help="diretório do corpus experimental")
    args = ap.parse_args()

    _discover_plugins()

    corpus = Path(args.corpus)
    dbs = [args.db] + ([args.alt_db] if args.alt_db else [])
    seen: dict[str, set[str]] = defaultdict(set)
    scores: dict[str, set[float]] = defaultdict(set)
    total = 0

    for db in dbs:
        per_db = args.runs // len(dbs) if len(dbs) > 1 else args.runs
        for name in FIXTURES:
            path = corpus / name
            if not path.exists():
                continue
            for _ in range(per_db):
                with Database(db) as handle:
                    result = run_scan(str(path), handle,
                                      version=PINNED_VERSIONS.get(name))
                seen[name].add(digest(result))
                scores[name].add(result.global_temporal_score)
                total += 1

    print(f"database files          : {len(dbs)}")
    print(f"configurations assessed : {len(seen)}")
    print(f"runs per configuration  : {total // max(len(seen), 1)}")
    print(f"total runs              : {total}")
    print()
    print(f"{'fixture':<44}{'digests':>8}{'scores':>8}  score")
    worst = 1
    for name in seen:
        d, s = len(seen[name]), len(scores[name])
        worst = max(worst, d, s)
        print(f"{str(corpus / name):<44}{d:>8}{s:>8}  {sorted(scores[name])[0]}")
    print()
    print(f"distinct digests per configuration : {worst}")
    return 0 if worst == 1 else 1


if __name__ == "__main__":
    sys.exit(main())
