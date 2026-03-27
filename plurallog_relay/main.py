#!/usr/bin/env python3
"""
PluralLog Relay Server — Entry Point.

Usage:
    # Development (HTTP):
    python -m plurallog_relay.main

    # Production with TLS:
    PLURALLOG_TLS_CERT=/path/to/cert.pem PLURALLOG_TLS_KEY=/path/to/key.pem python -m plurallog_relay.main

    # Production with gunicorn (behind reverse proxy):
    gunicorn "plurallog_relay.app:create_app()" --bind 0.0.0.0:8443 --workers 4

    # Self-signed cert for testing:
    openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes -subj '/CN=localhost'

Environment variables (see config.py for full list):
    PLURALLOG_PORT                Port to listen on (default: 8443)
    PLURALLOG_HOST                Bind address (default: 0.0.0.0)
    PLURALLOG_DB_PATH             SQLite database path (default: plurallog_relay.db)
    PLURALLOG_VOLUME_PATH         Volume blob storage directory (default: volume_storage/)
    PLURALLOG_TLS_CERT            Path to TLS certificate (optional for dev)
    PLURALLOG_TLS_KEY             Path to TLS private key (optional for dev)
    PLURALLOG_MIN_PROTOCOL_VERSION  Minimum client protocol version (default: 1)
    PLURALLOG_MAX_VOLUME_SIZE     Max bytes per volume (default: 10MB)
    PLURALLOG_MAX_USER_STORAGE    Max total bytes per user (default: 50MB)
"""
import logging
import ssl
import sys

from .app import create_app
from . import config

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)


def main():
    app = create_app()

    use_tls = config.TLS_CERT_PATH and config.TLS_KEY_PATH
    ssl_ctx = None

    if use_tls:
        ssl_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_ctx.minimum_version = ssl.TLSVersion.TLSv1_3
        ssl_ctx.load_cert_chain(config.TLS_CERT_PATH, config.TLS_KEY_PATH)
        logger.info(f"TLS enabled (TLS 1.3+) with cert: {config.TLS_CERT_PATH}")
        proto = "https"
    else:
        logger.warning(
            "⚠  Running WITHOUT TLS. This is acceptable for development "
            "or when behind a TLS-terminating reverse proxy. "
            "In production, set PLURALLOG_TLS_CERT and PLURALLOG_TLS_KEY."
        )
        proto = "http"

    logger.info(f"PluralLog Relay Server starting on {proto}://{config.HOST}:{config.PORT}")
    logger.info(f"  Database:     {config.DATABASE_PATH}")
    logger.info(f"  Volumes:      {config.VOLUME_STORAGE_PATH}")
    logger.info(f"  Min protocol: v{config.MIN_PROTOCOL_VERSION}")
    logger.info(f"  Max volume:   {config.MAX_VOLUME_SIZE_BYTES // 1024 // 1024}MB")
    logger.info(f"  Max user:     {config.MAX_USER_STORAGE_BYTES // 1024 // 1024}MB")

    app.run(
        host=config.HOST,
        port=config.PORT,
        ssl_context=ssl_ctx,
        debug=False,
    )


if __name__ == "__main__":
    main()
