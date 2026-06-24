"""
core/input_resolver.py
-----------------------
Resolve o input do utilizador para um caminho de ficheiro(s) de configuração.

Suporta 4 modos:

  Modo 1 — Ficheiro único
    ccss scan /tmp/httpd.conf
    → retorna o path directamente

  Modo 2 — Directório
    ccss scan /etc/apache2/
    → detecta o ponto de entrada (apache2.conf, httpd.conf, etc.)
    → o parser Apache segue os Includes recursivamente

  Modo 3 — Serviço instalado na máquina (--live)
    ccss scan --live apache2
    ccss scan --live httpd
    → detecta a instalação, encontra o ficheiro de config principal
    → usa `apache2ctl -V` / `httpd -V` para obter o ServerRoot real

  Modo 4 — Imagem Docker
    ccss scan docker://httpd:2.4
    ccss scan docker://nginx:latest
    → faz `docker pull` se necessário
    → extrai os ficheiros de config da imagem para um directório temporário
    → retorna esse directório (limpo depois do scan)

Cada modo retorna um ResolvedInput com:
  - path: caminho para ficheiro ou directório a passar ao parser
  - mode: "file" | "directory" | "live" | "docker"
  - cleanup: função opcional para limpar recursos temporários
  - metadata: informação extra (versão do serviço, imagem Docker, etc.)
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

logger = logging.getLogger(__name__)


# ------------------------------------------------------------------ #
# Result type                                                          #
# ------------------------------------------------------------------ #

@dataclass
class ResolvedInput:
    path: str                                    # path para o parser
    mode: str                                    # file | directory | live | docker
    cleanup: Optional[Callable[[], None]] = None # chamar após o scan
    metadata: dict = field(default_factory=dict) # info extra


# ------------------------------------------------------------------ #
# Detecção best-effort de versão (file / directory / docker)          #
# ------------------------------------------------------------------ #
#
# A versão é necessária para o cruzamento com CVEs/exploits (version_exploits).
# Nos modos --live a versão vem do binário; nos restantes modos tentamos, por
# best-effort e SEM rede, três fontes por esta ordem:
#   1. tag da imagem Docker (ex.: httpd:2.4.58 → "2.4.58")
#   2. binário do serviço no PATH (httpd -v, nginx -v, sshd -V, mysql --version)
#   3. texto dos ficheiros de configuração (raramente expõe a versão no Apache,
#      mas alguns serviços/cabeçalhos sim)
# Devolve None quando nenhuma fonte revela uma versão fiável — nesse caso o
# scan corre na mesma, apenas sem painel de exploits.

# Comandos por produto para obter a versão a partir do binário no PATH.
_VERSION_BINARIES: dict[str, list[tuple[list[str], str]]] = {
    "apache-httpd": [(["httpd", "-v"], r"Apache/(\d+\.\d+\.\d+)"),
                     (["apache2", "-v"], r"Apache/(\d+\.\d+\.\d+)")],
    "nginx":        [(["nginx", "-v"], r"nginx/(\d+\.\d+\.\d+)")],
    "ssh":          [(["sshd", "-V"], r"OpenSSH_(\d+\.\d+)"),
                     (["ssh", "-V"], r"OpenSSH_(\d+\.\d+)")],
    "mysql":        [(["mysql", "--version"], r"Ver\s+(\d+\.\d+\.\d+)"),
                     (["mysqld", "--version"], r"Ver\s+(\d+\.\d+\.\d+)")],
}

# Padrões de versão dentro do conteúdo dos ficheiros de configuração.
_VERSION_IN_CONFIG: dict[str, str] = {
    "apache-httpd": r"Apache/(\d+\.\d+\.\d+)",
    "nginx":        r"nginx/(\d+\.\d+\.\d+)",
    "ssh":          r"OpenSSH[_/](\d+\.\d+)",
    "mysql":        r"(?:MySQL|Ver)\s+(\d+\.\d+\.\d+)",
}


def version_from_docker_tag(image: str) -> str | None:
    """Extrair uma versão da tag de uma imagem Docker (ex.: httpd:2.4.58)."""
    if not image or ":" not in image:
        return None
    tag = image.rsplit(":", 1)[1]
    m = re.match(r"v?(\d+(?:\.\d+){1,3})", tag)
    return m.group(1) if m else None


def _version_from_binary(target_id: str) -> str | None:
    for argv, pattern in _VERSION_BINARIES.get(target_id, []):
        if shutil.which(argv[0]) is None:
            continue
        try:
            r = subprocess.run(argv, capture_output=True, text=True, timeout=5)
            m = re.search(pattern, (r.stdout or "") + (r.stderr or ""))
            if m:
                return m.group(1)
        except Exception:
            continue
    return None


def _version_from_config_text(target_id: str, config_path: str) -> str | None:
    pattern = _VERSION_IN_CONFIG.get(target_id)
    if not pattern:
        return None
    try:
        text = Path(config_path).read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return None
    m = re.search(pattern, text)
    return m.group(1) if m else None


def detect_version(target_id: str, config_path: str,
                   image: str | None = None) -> str | None:
    """Best-effort, offline. Devolve a versão ou None. Ordem: tag → binário → config."""
    if image:
        v = version_from_docker_tag(image)
        if v:
            logger.info("[version] from docker tag: %s", v)
            return v
    v = _version_from_binary(target_id)
    if v:
        logger.info("[version] from binary on PATH: %s", v)
        return v
    v = _version_from_config_text(target_id, config_path)
    if v:
        logger.info("[version] from config text: %s", v)
        return v
    return None


# ------------------------------------------------------------------ #
# Modo 1 — Ficheiro único                                              #
# ------------------------------------------------------------------ #

def resolve_file(path: str) -> ResolvedInput:
    """Validar e retornar um ficheiro de configuração."""
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Ficheiro não encontrado: {path}")
    if not p.is_file():
        raise ValueError(f"Não é um ficheiro: {path}")
    return ResolvedInput(
        path=str(p.resolve()),
        mode="file",
        metadata={"filename": p.name},
    )


# ------------------------------------------------------------------ #
# Modo 2 — Directório                                                  #
# ------------------------------------------------------------------ #

# Pontos de entrada por ordem de preferência
_ENTRY_POINTS = [
    "nginx.conf",
    "apache2.conf",
    "httpd.conf",
    "apache.conf",
    "httpd-ssl.conf",
    "sshd_config",   # SSH (não é .conf — tem de estar explícito)
    "mysqld.cnf",    # MySQL Debian (/etc/mysql/mysql.conf.d/)
    "my.cnf",        # MySQL genérico
]

# Config fragments that are NEVER a main entry point. Used to filter the
# directory fallback so we don't pick e.g. fastcgi.conf as the root config.
_CONFIG_FRAGMENTS = {
    "fastcgi.conf", "fastcgi_params", "scgi_params", "uwsgi_params",
    "mime.types", "proxy_params", "koi-win", "koi-utf", "win-utf",
}

def resolve_directory(path: str) -> ResolvedInput:
    """
    Encontrar o ponto de entrada principal numa directória Apache.

    O parser segue todos os Include/IncludeOptional automaticamente,
    por isso só precisamos de passar o ficheiro raiz.
    """
    p = Path(path)
    if not p.exists():
        raise FileNotFoundError(f"Directório não encontrado: {path}")
    if not p.is_dir():
        raise ValueError(f"Não é um directório: {path}")

    # Tentar pontos de entrada canónicos
    for entry in _ENTRY_POINTS:
        candidate = p / entry
        if candidate.exists():
            logger.info("Entry point found: %s", candidate)
            return ResolvedInput(
                path=str(candidate.resolve()),
                mode="directory",
                metadata={"root_dir": str(p), "entry_file": entry},
            )

    # Fallback: primeiro .conf no directório que NÃO seja um fragmento conhecido
    conf_files = [
        f for f in sorted(p.glob("*.conf"))
        if f.name not in _CONFIG_FRAGMENTS
    ]
    if conf_files:
        logger.info("Using first .conf: %s", conf_files[0])
        return ResolvedInput(
            path=str(conf_files[0].resolve()),
            mode="directory",
            metadata={"root_dir": str(p), "entry_file": conf_files[0].name},
        )

    raise FileNotFoundError(
        f"Nenhum ficheiro de configuração reconhecido encontrado em: {path}\n"
        f"Esperado um de: {', '.join(_ENTRY_POINTS)}"
    )


# ------------------------------------------------------------------ #
# Modo 3 — Serviço instalado (--live)                                  #
# ------------------------------------------------------------------ #

# Mapa de nome de serviço → caminhos de instalação por ordem de preferência
_SERVICE_PATHS = {
    "apache2": [
        "/etc/apache2/apache2.conf",          # Debian/Ubuntu
        "/etc/apache2/httpd.conf",
    ],
    "httpd": [
        "/etc/httpd/conf/httpd.conf",         # CentOS/RHEL/Fedora
        "/usr/local/apache2/conf/httpd.conf", # Compilado de fonte
        "/opt/homebrew/etc/httpd/httpd.conf", # macOS Homebrew
        "/usr/local/etc/httpd/httpd.conf",    # macOS Homebrew (Intel)
    ],
    "nginx": [
        "/etc/nginx/nginx.conf",
        "/usr/local/etc/nginx/nginx.conf",
    ],
    "sshd": [
        "/etc/ssh/sshd_config",
    ],
}


def _get_apache_version(binary: str) -> str:
    """Obter versão do Apache via `apache2 -v` ou `httpd -v`."""
    try:
        result = subprocess.run(
            [binary, "-v"],
            capture_output=True, text=True, timeout=5,
        )
        # "Server version: Apache/2.4.57 (Ubuntu)"
        m = re.search(r"Apache/(\d+\.\d+\.\d+)", result.stdout + result.stderr)
        return m.group(1) if m else "unknown"
    except Exception:
        return "unknown"


def _get_apache_config_path(binary: str) -> str | None:
    """
    Obter o caminho real do ficheiro de config via `apache2ctl -V`.
    Mais fiável do que caminhos hard-coded.
    """
    ctl = binary.replace("apache2", "apache2ctl").replace("httpd", "apachectl")
    for cmd in [ctl, "apache2ctl", "apachectl"]:
        try:
            result = subprocess.run(
                [cmd, "-V"],
                capture_output=True, text=True, timeout=5,
            )
            output = result.stdout + result.stderr
            # Suporta todos os formatos Ubuntu/Debian/RHEL:
            #   HTTPD_ROOT="/etc/apache2"   (com aspas duplas)
            #   HTTPD_ROOT=/etc/apache2     (sem aspas)
            #   -D HTTPD_ROOT=/etc/apache2  (com prefixo -D)
            root_m = re.search(
                r'HTTPD_ROOT[=\s]+["\']*([^"\'\s<>]+)["\']*', output)
            config_m = re.search(
                r'SERVER_CONFIG_FILE[=\s]+["\']*([^"\'\s<>]+)["\']*', output)
            if root_m and config_m:
                root = root_m.group(1).strip().strip('"')
                cfile = config_m.group(1).strip().strip('"')
                config = Path(root) / cfile
                if config.exists():
                    logger.info("apache2ctl -V: %s + %s -> %s", root, cfile, config)
                    return str(config)
                if Path(cfile).is_absolute() and Path(cfile).exists():
                    return cfile
        except (FileNotFoundError, subprocess.TimeoutExpired):
            continue
    return None


def resolve_live_service(service_name: str) -> ResolvedInput:
    """
    Detectar o ficheiro de configuração de um serviço instalado localmente.

    Tenta (por ordem):
      1. apache2ctl/apachectl -V  (mais fiável)
      2. Caminhos hard-coded por distro
    """
    service_lower = service_name.lower().strip()

    # Alias comuns
    aliases = {
        "apache": "apache2",
        "apache2": "apache2",
        "httpd": "httpd",
        "http": "httpd",
    }
    canonical = aliases.get(service_lower, service_lower)

    logger.info("Detecting live service: %s (canonical: %s)", service_name, canonical)

    # Tentar obter config via binário
    for binary in [canonical, f"/usr/sbin/{canonical}", f"/usr/bin/{canonical}"]:
        config_path = _get_apache_config_path(binary)
        if config_path:
            version = _get_apache_version(binary)
            logger.info("Config via %s -V: %s (v%s)", binary, config_path, version)
            return ResolvedInput(
                path=config_path,
                mode="live",
                metadata={
                    "service": canonical,
                    "version": version,
                    "binary": binary,
                    "config_path": config_path,
                },
            )

    # Fallback: caminhos hard-coded
    candidates = _SERVICE_PATHS.get(canonical, [])
    for candidate in candidates:
        if Path(candidate).exists():
            logger.info("Config via hard-coded path: %s", candidate)
            return ResolvedInput(
                path=candidate,
                mode="live",
                metadata={
                    "service": canonical,
                    "version": "unknown",
                    "config_path": candidate,
                },
            )

    raise FileNotFoundError(
        f"Serviço '{service_name}' não encontrado.\n"
        f"Caminhos tentados: {candidates}\n"
        f"Certifica-te que o serviço está instalado: sudo apt install {canonical}"
    )


# ------------------------------------------------------------------ #
# Modo 4 — Imagem Docker                                               #
# ------------------------------------------------------------------ #

# Caminhos de configuração típicos por imagem base
_DOCKER_CONFIG_PATHS = {
    "httpd":   ["/usr/local/apache2/conf/httpd.conf"],
    "apache":  ["/usr/local/apache2/conf/httpd.conf"],
    "apache2": ["/etc/apache2/apache2.conf"],
    "nginx":   ["/etc/nginx/nginx.conf"],
    "bitnami/apache": ["/opt/bitnami/apache2/conf/httpd.conf"],
}

# Directórios de configuração a extrair (além do ficheiro principal)
_DOCKER_CONFIG_DIRS = {
    "httpd":   ["/usr/local/apache2/conf/"],
    "apache2": ["/etc/apache2/"],
    "nginx":   ["/etc/nginx/"],
}

# Paths genéricos a tentar por ordem de prioridade, cobrindo TODOS os targets
# registados. O resolver extrai cada path para um tmpdir e o plugin decide via
# detect()/detection_confidence() — não é preciso saber o serviço de antemão.
CONFIG_PATHS_TO_TRY = [
    # Apache
    "/etc/apache2/",
    "/usr/local/apache2/conf/",
    "/etc/httpd/conf/",
    # Nginx
    "/etc/nginx/",
    "/usr/local/nginx/conf/",
    # SSH
    "/etc/ssh/",
    # MySQL
    "/etc/mysql/mysql.conf.d/",
    "/etc/mysql/",
    # PostgreSQL (para futuro)
    "/etc/postgresql/",
]


def _docker_available() -> bool:
    """Verificar se o Docker está disponível."""
    try:
        result = subprocess.run(
            ["docker", "info"],
            capture_output=True, timeout=10,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def _docker_image_exists(image: str) -> bool:
    """Verificar se a imagem já está no cache local."""
    try:
        result = subprocess.run(
            ["docker", "image", "inspect", image],
            capture_output=True, timeout=10,
        )
        return result.returncode == 0
    except Exception:
        return False


def _docker_pull(image: str) -> None:
    """Fazer pull da imagem Docker com output visível."""
    import sys
    print(f"  Pulling {image}...", flush=True)
    result = subprocess.run(
        ["docker", "pull", image],
        timeout=300,
    )
    if result.returncode != 0:
        raise RuntimeError(f"docker pull {image} failed")


def _get_image_basename(image: str) -> str:
    """Extrair nome base da imagem (sem tag e sem registry)."""
    # "registry.example.com/org/httpd:2.4" → "httpd"
    name = image.split("/")[-1].split(":")[0]
    return name


def _extract_config_from_image(image: str, tmpdir: str) -> str:
    """
    Extrair ficheiros de configuração de uma imagem Docker.

    Cria um container temporário, copia os ficheiros para tmpdir,
    e remove o container.

    Retorna o path do ficheiro/directório de configuração extraído.
    """
    basename = _get_image_basename(image)

    # Determinar o directório de config a extrair: primeiro os candidatos
    # específicos da imagem (por basename), depois a lista genérica que cobre
    # todos os targets registados (Apache, Nginx, SSH, MySQL, …).
    config_dir_candidates = list(_DOCKER_CONFIG_DIRS.get(basename, []))
    for path in CONFIG_PATHS_TO_TRY:
        if path not in config_dir_candidates:
            config_dir_candidates.append(path)

    # Criar container temporário (sem correr)
    logger.info("Creating temporary container from %s", image)
    result = subprocess.run(
        ["docker", "create", "--name", "ccss-scan-tmp", image],
        capture_output=True, text=True, timeout=30,
    )
    if result.returncode != 0:
        raise RuntimeError(f"docker create failed: {result.stderr}")

    container_id = result.stdout.strip()

    try:
        extracted_dir = None

        for config_dir in config_dir_candidates:
            # Tentar copiar o directório
            dest = os.path.join(tmpdir, "config")
            cp_result = subprocess.run(
                ["docker", "cp", f"ccss-scan-tmp:{config_dir}", dest],
                capture_output=True, timeout=30,
            )
            if cp_result.returncode == 0:
                logger.info("Extracted %s → %s", config_dir, dest)
                extracted_dir = dest
                break

        if not extracted_dir:
            raise FileNotFoundError(
                f"No recognised service config found in image {image}.\n"
                f"Tried: {config_dir_candidates}"
            )

        return extracted_dir

    finally:
        # Remover container temporário sempre
        subprocess.run(
            ["docker", "rm", "-f", "ccss-scan-tmp"],
            capture_output=True, timeout=15,
        )
        logger.info("Temporary container removed")


def resolve_docker(image_ref: str) -> ResolvedInput:
    """
    Extrair e resolver configuração de uma imagem Docker.

    image_ref pode ser:
      - "docker://httpd:2.4"      (com prefixo)
      - "httpd:2.4"               (sem prefixo, se --docker flag)
      - "docker://nginx:latest"
    """
    # Remover prefixo docker://
    image = image_ref.removeprefix("docker://").strip()
    if not image:
        raise ValueError("Nome de imagem Docker vazio")

    if not _docker_available():
        raise RuntimeError(
            "Docker nao esta disponivel ou nao esta em execucao.\n"
            "No WSL2: abre o Docker Desktop no Windows e aguarda que inicie.\n"
            "Verifica com: docker info"
        )

    # Pull se necessário
    if not _docker_image_exists(image):
        _docker_pull(image)
    else:
        logger.info("Image %s already in local cache", image)

    # Criar directório temporário para extrair a config
    tmpdir = tempfile.mkdtemp(prefix="ccss-scan-docker-")
    logger.info("Extracting config to %s", tmpdir)

    def cleanup():
        shutil.rmtree(tmpdir, ignore_errors=True)
        logger.debug("Cleaned up %s", tmpdir)

    try:
        extracted = _extract_config_from_image(image, tmpdir)

        # Resolver o ponto de entrada dentro do directório extraído
        resolved = resolve_directory(extracted)
        resolved.mode = "docker"
        resolved.cleanup = cleanup
        resolved.metadata.update({
            "image": image,
            "extracted_to": tmpdir,
        })

        # Propagar a versão da tag Docker para o metadata, para que o runtime
        # dispare a amplificação F1 (CVE/exploit) sem ter de a re-derivar.
        version = version_from_docker_tag(image)
        if version:
            resolved.metadata["version"] = version
            logger.info("[version] from docker tag: %s", version)

        return resolved

    except Exception:
        cleanup()
        raise


# ------------------------------------------------------------------ #
# Router principal                                                     #
# ------------------------------------------------------------------ #

def resolve(
    input_path: str,
    live: bool = False,
) -> ResolvedInput:
    """
    Resolver o input para um caminho de configuração.

    Regras de detecção automática:
      1. live=True → Modo 3 (serviço instalado)
      2. Começa com "docker://" → Modo 4 (imagem Docker)
      3. É um directório → Modo 2
      4. É um ficheiro → Modo 1
    """
    if live:
        return resolve_live_service(input_path)

    if input_path.startswith("docker://"):
        return resolve_docker(input_path)

    p = Path(input_path)

    if not p.exists():
        raise FileNotFoundError(
            f"Not found: {input_path}\n"
            f"Hint: use --live for installed services: caspar scan --live apache2\n"
            f"      use docker:// for images:        caspar scan docker://httpd:2.4"
        )

    if p.is_dir():
        return resolve_directory(input_path)

    return resolve_file(input_path)
