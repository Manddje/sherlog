# Sherlog (IME Log Analyzer) — production image.
#
# One container, two layers:
#   - web:    Python 3.12 + FastAPI + uvicorn on :8080 (exactly ONE worker:
#             job caps, the analysis semaphore, the upload counter and the
#             restart recovery all assume a single process; app.py refuses to
#             start a second one against the same JOBS_DIR)
#   - engine: PowerShell 7.6 LTS (pwsh) running the headless analysis script.
#
# Build:  docker build -t sherlog .
# Run:    docker run -p 8080:8080 -v "$PWD/data:/data" sherlog
#
# Base image pinned by digest (ubuntu:24.04 — Python 3.12, supported until
# 2028). The mcr.microsoft.com/powershell images are no longer published for
# the 7.6 LTS line, so pwsh comes from Microsoft's package pool as a pinned,
# SHA-256-verified .deb. Bump both deliberately (see README "Updating").
FROM ubuntu:24.04@sha256:008173c23f95b170204355c12626cb5a965d779a7e1283b09e9cffbb1bf33ca3

ARG PWSH_VERSION=7.6.6
ARG PWSH_SHA256=9585f38ab5a026c3fc0995486e26e12050777960fef47a22dca98b577c5d27a7

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    POWERSHELL_TELEMETRY_OPTOUT=1 \
    POWERSHELL_UPDATECHECK=Off \
    PATH=/opt/venv/bin:$PATH

# python3 + venv for the web layer, cabextract to expand .cab files
# (Defender/MDM) in diagnostics packages, curl+ca-certificates to fetch pwsh.
# pwsh's own runtime deps (libicu, libssl, ...) are resolved by apt from the .deb.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        python3 python3-venv ca-certificates curl cabextract \
    && curl -fsSLo /tmp/pwsh.deb \
        "https://packages.microsoft.com/ubuntu/24.04/prod/pool/main/p/powershell/powershell_${PWSH_VERSION}-1.deb_amd64.deb" \
    && echo "${PWSH_SHA256}  /tmp/pwsh.deb" | sha256sum -c - \
    && apt-get install -y --no-install-recommends /tmp/pwsh.deb \
    && rm -f /tmp/pwsh.deb \
    && apt-get purge -y curl && apt-get autoremove -y \
    && rm -rf /var/lib/apt/lists/* \
    && pwsh -NoProfile -Command '$PSVersionTable.PSVersion.ToString()'

WORKDIR /app

# Python deps first for layer caching. requirements.txt is a fully pinned,
# hash-locked runtime lock (test deps live in requirements-dev.txt).
COPY requirements.txt /app/
RUN python3 -m venv /opt/venv \
    && pip install --no-cache-dir --require-hashes -r requirements.txt

# Application code: the analysis script, the collector + remediation scripts
# (served on /collect-script and shown on /diagnostics and /inbox), the web
# app and the headless wrapper. static/ holds the footer author photo.
COPY Get-IntuneManagementExtensionDiagnostics.ps1 /app/
COPY Collect-IntuneDiagnostics.ps1 /app/
COPY Remediate-CollectToSherlog.ps1 /app/
COPY app.py /app/
COPY scripts/ /app/scripts/
COPY static/ /app/static/

RUN chmod +x /app/scripts/run-analysis.sh /app/scripts/docker-entrypoint.sh \
    && chmod 0644 /app/Collect-IntuneDiagnostics.ps1 /app/Remediate-CollectToSherlog.ps1

# Non-root runtime user (uid 10001). The container starts as root so the
# entrypoint can chown the mounted JOBS_DIR volume, then drops to this user
# via setpriv before launching uvicorn.
RUN useradd --create-home --uid 10001 appuser \
    && mkdir -p /data/jobs \
    && chown -R appuser:appuser /data

ENV JOBS_DIR=/data/jobs
EXPOSE 8080

# Health: hit the unauthenticated /health endpoint (also checks pwsh presence).
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python3 -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/health', timeout=4).status==200 else 1)"

ENTRYPOINT ["/app/scripts/docker-entrypoint.sh"]
# --workers 1 is deliberate (see header). --proxy-headers makes the client IP
# (per-IP rate limits, access log) come from X-Forwarded-For. uvicorn reads
# FORWARDED_ALLOW_IPS: "*" suits Coolify/Traefik, where only the proxy can
# reach the container; narrow it to the proxy's address if the port is also
# published directly, or clients can spoof their IP to dodge rate limits.
ENV FORWARDED_ALLOW_IPS="*"
CMD ["python3", "-m", "uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8080", \
     "--workers", "1", "--proxy-headers"]
