# docker/caspar/Dockerfile — CASPAR runtime image (full features)
#
# Build context MUST be the repository root:
#   docker build -t caspar:latest -f docker/caspar/Dockerfile .
#
# Includes: scan (file / directory / docker://), targets, fetch-exploits,
#           report generation. Build-time commands (plugin add / build) need
#           an external Ollama — see docker-compose.yml (profile "full").
FROM python:3.12-slim

# System dependencies:
#   sqlite3 — restore the canonical DB from SQL at build time
#   git     — used by some build-time tooling
#   curl    — health checks / online enrichment, fetch the docker client
#   ca-certificates — TLS for the above
#   poppler-utils — pdftotext, used to extract CIS Benchmark PDFs in plugin add
RUN apt-get update && apt-get install -y --no-install-recommends \
        sqlite3 \
        git \
        curl \
        ca-certificates \
        poppler-utils \
    && rm -rf /var/lib/apt/lists/*

# Docker *client* only (not the engine) — required for `caspar scan
# docker://<image>`, which talks to the mounted /var/run/docker.sock. The
# static client is ~30MB vs ~300MB for the full docker.io package.
ARG DOCKER_CLI_VERSION=27.3.1
RUN curl -fsSL "https://download.docker.com/linux/static/stable/x86_64/docker-${DOCKER_CLI_VERSION}.tgz" \
        | tar -xz -C /tmp \
    && mv /tmp/docker/docker /usr/local/bin/docker \
    && rm -rf /tmp/docker \
    && docker --version

# Non-root user
RUN useradd -m -u 1000 caspar
WORKDIR /home/caspar/app

# --- Python dependencies (layer-cached on pyproject.toml) -------------------
COPY pyproject.toml .
RUN pip install --no-cache-dir click pydantic openpyxl requests pypdf

# --- Application code -------------------------------------------------------
COPY . .
RUN pip install --no-cache-dir -e . --no-deps

# --- Canonical database: restored from SQL, never copied as a .db -----------
# Baked at a fixed *seed* path. At runtime the entrypoint copies it into the
# data dir (a volume) on first use, so the working DB persists across --rm.
RUN sqlite3 /home/caspar/app/ccss.seed.db < data/ccss_canonical.sql

# --- Persistent data dir (DB + fetched plugins) and reports -----------------
# CASPAR_DATA_DIR is meant to be a mounted volume so fetched plugins and the
# DB they write to survive a --rm container. Defaults keep zero-config runs
# working (the dir just lives inside the container when no volume is mounted).
ENV CASPAR_DATA_DIR=/home/caspar/data
ENV CASPAR_DB=/home/caspar/data/ccss.db
ENV CASPAR_PLUGINS_DIR=/home/caspar/data/plugins
RUN mkdir -p /home/caspar/data/plugins /home/caspar/reports \
    && chown -R caspar:caspar /home/caspar

COPY docker/caspar/seed_data.sh /usr/local/bin/caspar-seed
RUN chmod +x /usr/local/bin/caspar-seed

USER caspar
ENV OLLAMA_HOST=http://ollama:11434

# Seed the data dir (idempotent) then run caspar.
ENTRYPOINT ["/usr/local/bin/caspar-seed", "caspar"]
CMD ["--help"]
