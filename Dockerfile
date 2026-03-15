# ─── Stage 1: ProjectDiscovery pre-built binaries ─────────────────────────────
# Download official release zips — no Go compiler needed, immune to Go version churn.
# TARGETOS / TARGETARCH are set automatically by Docker based on the build platform
# (linux/amd64 on x86, linux/arm64 on Apple Silicon M-series).
FROM debian:bookworm-slim AS pd-tools

ARG TARGETOS=linux
ARG TARGETARCH=amd64

RUN apt-get update && apt-get install -y --no-install-recommends \
        curl \
        unzip \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# subfinder — passive subdomain enumeration
RUN LATEST=$(curl -fsSL -o /dev/null -w '%{url_effective}' \
      https://github.com/projectdiscovery/subfinder/releases/latest \
      | sed 's|.*/tag/v||') \
    && curl -fsSL \
      "https://github.com/projectdiscovery/subfinder/releases/download/v${LATEST}/subfinder_${LATEST}_${TARGETOS}_${TARGETARCH}.zip" \
      -o /tmp/subfinder.zip \
    && unzip -q /tmp/subfinder.zip subfinder -d /tmp/subfinder \
    && mv /tmp/subfinder/subfinder /usr/local/bin/subfinder \
    && chmod +x /usr/local/bin/subfinder \
    && rm -rf /tmp/subfinder*

# httpx (PD) — HTTP probe / tech detection
RUN LATEST=$(curl -fsSL -o /dev/null -w '%{url_effective}' \
      https://github.com/projectdiscovery/httpx/releases/latest \
      | sed 's|.*/tag/v||') \
    && curl -fsSL \
      "https://github.com/projectdiscovery/httpx/releases/download/v${LATEST}/httpx_${LATEST}_${TARGETOS}_${TARGETARCH}.zip" \
      -o /tmp/httpx.zip \
    && unzip -q /tmp/httpx.zip httpx -d /tmp/httpx \
    && mv /tmp/httpx/httpx /usr/local/bin/pd-httpx \
    && chmod +x /usr/local/bin/pd-httpx \
    && rm -rf /tmp/httpx*

# ─── Stage 2: Adversa worker ──────────────────────────────────────────────────
FROM python:3.13-slim-bookworm

WORKDIR /app

# ── System packages ────────────────────────────────────────────────────────────
# nmap                — network/port scanner (Phase 1)
# curl/wget           — used by installer scripts below
# gnupg/apt-transport-https — for Trivy apt repo
# unzip               — needed by Joern installer
# default-jre-headless — required by Joern (JVM-based CPG tool)
# chromium            — Playwright browser (Phase 2 recon agent)
RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap \
        curl \
        wget \
        gnupg \
        apt-transport-https \
        ca-certificates \
        unzip \
        default-jre-headless \
        chromium \
        libcap2-bin \
    && rm -rf /var/lib/apt/lists/*

# ── Trivy (Aqua Security SCA scanner) ─────────────────────────────────────────
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
      | sh -s -- -b /usr/local/bin

# ── Joern (CPG / taint-flow analysis) ─────────────────────────────────────────
# Download and extract in one step, then clean up the ~300MB zip to keep layer small
# and avoid Docker overlay I/O errors on constrained storage.
RUN curl -fL https://github.com/joernio/joern/releases/latest/download/joern-install.sh \
      | sh -s -- --install-dir=/opt/joern --without-plugins \
    && ln -s /opt/joern/joern-cli/joern /usr/local/bin/joern \
    && ln -s /opt/joern/joern-cli/joern-parse /usr/local/bin/joern-parse \
    && rm -f /opt/joern/*.zip /tmp/joern* /root/joern*

# ── ProjectDiscovery tools from build stage ───────────────────────────────────
COPY --from=pd-tools /usr/local/bin/subfinder /usr/local/bin/subfinder
COPY --from=pd-tools /usr/local/bin/pd-httpx   /usr/local/bin/pd-httpx

# ── Python dependencies ────────────────────────────────────────────────────────
RUN pip install --no-cache-dir uv

COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev

# ── Node.js (lockfile generation for JS/TS targets) ──────────────────────────
# Only npm is needed — no need for full Node dev toolchain.
RUN curl -fsSL https://deb.nodesource.com/setup_22.x | bash - \
    && apt-get install -y --no-install-recommends nodejs \
    && rm -rf /var/lib/apt/lists/*

# ── Semgrep (installed as Python package, exposes CLI) ─────────────────────────
RUN uv run pip install --no-cache-dir semgrep

# ── Application source ─────────────────────────────────────────────────────────
COPY src/ ./src/

# Playwright browser path (configured in docker-compose.yml via env var)
ENV PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH=/usr/bin/chromium

# ── Non-root user ─────────────────────────────────────────────────────────────
# claude-agent-sdk refuses bypassPermissions under root for security reasons.
# Running as non-root is also a container security best practice.
RUN groupadd --gid 1000 adversa \
    && useradd --uid 1000 --gid adversa --create-home adversa \
    && chown -R adversa:adversa /app \
    && setcap cap_net_raw,cap_net_admin+eip /usr/bin/nmap

USER adversa

CMD ["uv", "run", "python", "-m", "src.temporal.worker"]
