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

# python3 + pip to run the web layer, unzip as a safety net for the engine.
# Clean the apt cache in the same layer to keep the image small.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        python3 \
        python3-pip \
        unzip \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python deps first for better layer caching. Strip the test-only
# packages (httpx/pytest) — they aren't needed at runtime.
COPY requirements.txt /app/
RUN grep -viE '^(httpx|pytest|# Test)' requirements.txt > /tmp/req.txt \
    && pip3 install --no-cache-dir -r /tmp/req.txt \
    && rm /tmp/req.txt

# Application code: the analysis script, web app and headless wrapper.
COPY Get-IntuneManagementExtensionDiagnostics.ps1 /app/
COPY app.py /app/
COPY scripts/ /app/scripts/

RUN chmod +x /app/scripts/run-analysis.sh

# Non-root runtime user; /data is the job state directory and must be writable.
RUN useradd --create-home --uid 10001 appuser \
    && mkdir -p /data/jobs \
    && chown -R appuser:appuser /data
USER appuser

ENV JOBS_DIR=/data/jobs
EXPOSE 8080

# Health: hit the unauthenticated /health endpoint (also checks pwsh presence).
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD python3 -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/health').status==200 else 1)"

CMD ["python3", "-m", "uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8080"]
