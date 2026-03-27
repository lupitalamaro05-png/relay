FROM python:3.12-slim

# Security: run as non-root
RUN useradd -m -s /bin/bash plurallog

WORKDIR /app

# Install dependencies first (cache layer)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY plurallog_relay/ plurallog_relay/

# Create data directories
RUN mkdir -p /data/volumes && chown -R plurallog:plurallog /data

USER plurallog

# Default configuration — override with environment variables
ENV PLURALLOG_DB_PATH=/data/plurallog_relay.db
ENV PLURALLOG_VOLUME_PATH=/data/volumes
ENV PLURALLOG_HOST=0.0.0.0
ENV PLURALLOG_PORT=8443

EXPOSE 8443

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8443/api/v1/health')"

# Production: use gunicorn with 4 workers
CMD ["gunicorn", "plurallog_relay.app:create_app()", \
     "--bind", "0.0.0.0:8443", \
     "--workers", "4", \
     "--timeout", "120", \
     "--access-logfile", "-", \
     "--error-logfile", "-"]
