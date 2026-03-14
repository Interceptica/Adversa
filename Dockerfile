# ─── Stage 1: Go tool installer ───────────────────────────────────────────────
# Builds projectdiscovery binaries (subfinder, httpx) from official releases.
FROM golang:1.23-bookworm AS go-tools

RUN go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest \
 && go install github.com/projectdiscovery/httpx/cmd/httpx@latest

# ─── Stage 2: Adversa worker ──────────────────────────────────────────────────
FROM python:3.13-slim-bookworm

WORKDIR /app

# ── System packages ────────────────────────────────────────────────────────────
# nmap        — network/port scanner (Phase 1)
# curl/wget   — needed by installer scripts below
# gnupg/apt-transport-https — for trivy apt repo
# default-jre — required by Joern (JVM-based CPG tool)
# chromium    — Playwright browser (Phase 2 recon agent)
RUN apt-get update && apt-get install -y --no-install-recommends \
        nmap \
        curl \
        wget \
        gnupg \
        apt-transport-https \
        ca-certificates \
        default-jre-headless \
        chromium \
    && rm -rf /var/lib/apt/lists/*

# ── Trivy (Aqua Security SCA scanner) ─────────────────────────────────────────
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
      | sh -s -- -b /usr/local/bin

# ── Joern (CPG / taint-flow analysis) ─────────────────────────────────────────
RUN curl -fL https://github.com/joernio/joern/releases/latest/download/joern-install.sh \
      | sh -s -- --prefix=/usr/local/joern \
    && ln -s /usr/local/joern/joern-cli/joern /usr/local/bin/joern

# ── Go-based tools from build stage ───────────────────────────────────────────
COPY --from=go-tools /go/bin/subfinder /usr/local/bin/subfinder
COPY --from=go-tools /go/bin/httpx     /usr/local/bin/httpx

# ── Python dependencies ────────────────────────────────────────────────────────
RUN pip install --no-cache-dir uv

COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev

# ── Semgrep (installed as Python package, exposes CLI) ─────────────────────────
RUN uv run pip install --no-cache-dir semgrep

# ── Application source ─────────────────────────────────────────────────────────
COPY src/ ./src/

# Playwright browser path (configured in docker-compose.yml via env var)
ENV PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH=/usr/bin/chromium

CMD ["uv", "run", "python", "-m", "src.temporal.worker"]
