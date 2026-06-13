# IME Log Analyzer — production image.
#
# One container, two layers:
#   - web:    Python 3 + FastAPI + uvicorn on :8080
#   - engine: PowerShell Core (pwsh, from the base image) running the
#             headless analysis script.
#
# Build:  docker build -t ime-analyzer .
# Run:    docker run -p 8080:8080 -v "$PWD/data:/data" ime-analyzer
FROM mcr.microsoft.com/powershell:lts-ubuntu-22.04

# python3 + pip to run the web layer, unzip as a safety net for the engine,
# cabextract to expand .cab files (Defender/MDM) in diagnostics packages.
# Clean the apt cache in the same layer to keep the image small.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        python3 \
        python3-pip \
        unzip \
        cabextract \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python deps first for better layer caching. Strip the test-only
# packages (httpx/pytest) — they aren't needed at runtime.
COPY requirements.txt /app/
RUN grep -viE '^(httpx|pytest|# Test)' requirements.txt > /tmp/req.txt \
    && pip3 install --no-cache-dir -r /tmp/req.txt \
    && rm /tmp/req.txt

# Application code: the analysis script, the collector script (shown and
# downloadable on /diagnostics), web app and headless wrapper.
COPY Get-IntuneManagementExtensionDiagnostics.ps1 /app/
COPY Collect-IntuneDiagnostics.ps1 /app/
COPY app.py /app/
COPY scripts/ /app/scripts/
# Landing-page screenshots and the sample logs behind the homepage demo button.
COPY static/ /app/static/
COPY testdata/ /app/testdata/

RUN chmod +x /app/scripts/run-analysis.sh /app/scripts/docker-entrypoint.sh \
    && chmod 0644 /app/Collect-IntuneDiagnostics.ps1

# Create the non-root runtime user (uid 10001). The container starts as root so
# the entrypoint can chown the mounted JOBS_DIR volume, then drops to this user
# via setpriv before launching uvicorn.
RUN useradd --create-home --uid 10001 appuser \
    && mkdir -p /data/jobs \
    && chown -R appuser:appuser /data

ENV JOBS_DIR=/data/jobs
EXPOSE 8080

# Health: hit the unauthenticated /health endpoint (also checks pwsh presence).
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python3 -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/health').status==200 else 1)"

ENTRYPOINT ["/app/scripts/docker-entrypoint.sh"]
CMD ["python3", "-m", "uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8080"]
