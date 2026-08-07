# docker/caspar/Dockerfile — CASPAR runtime image (full features)
#
# Build context MUST be the repository root:
#   docker build -t caspar:latest -f docker/caspar/Dockerfile .
#
# Includes: scan (file / directory / docker://), targets, fetch-exploits,
#           report generation, and `caspar serve` (REST API + the CVM React
#           console). Build-time commands (plugin add / build) need an
#           external Ollama — see docker-compose.yml (profile "full").

# --- Stage 1: build the CVM React console ----------------------------------
# Built here rather than COPYing a local frontend/dist so the image is
# reproducible from source alone — a developer's stale local build can never
# end up baked into it. .dockerignore excludes frontend/dist for this reason.
FROM node:22-slim AS console

WORKDIR /build
# package*.json first so `npm ci` is layer-cached on dependency changes only.
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci

COPY frontend/ ./
RUN npm run build


# --- Stage 2: the runtime image --------------------------------------------
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
# The last three are the [api] extra — `caspar serve` needs them to host the
# REST API and the React console. They are installed explicitly (rather than
# via `-e .[api]`) to keep the `--no-deps` install below, which is what makes
# this layer cacheable on pyproject.toml alone.
RUN pip install --no-cache-dir click pydantic openpyxl requests pypdf pyyaml \
        "fastapi>=0.110" "uvicorn[standard]>=0.29" "python-multipart>=0.0.9"

# --- Application code -------------------------------------------------------
COPY . .
RUN pip install --no-cache-dir -e . --no-deps

# The console's built assets, from stage 1. _mount_frontend (in
# cli/commands/serve_cmds.py) looks for <repo>/frontend/dist and soft-fails if
# it is absent, so this path is what makes /app available in the image.
COPY --from=console /build/dist ./frontend/dist

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
# Reports go to /reports, which the caspar wrapper mounts as the caspar_reports
# volume — so a saved report survives the --rm container.
ENV CASPAR_REPORTS_DIR=/reports
RUN mkdir -p /home/caspar/data/plugins /reports \
    && chown -R caspar:caspar /home/caspar /reports

COPY docker/caspar/seed_data.sh /usr/local/bin/caspar-seed
RUN chmod +x /usr/local/bin/caspar-seed

USER caspar
ENV OLLAMA_HOST=http://ollama:11434

# Seed the data dir (idempotent) then run caspar.
ENTRYPOINT ["/usr/local/bin/caspar-seed", "caspar"]
CMD ["--help"]
