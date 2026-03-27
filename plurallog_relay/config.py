"""
Server configuration.
All values can be overridden via environment variables.
"""
import os

# ─── Protocol ──────────────────────────────────────────────────
MIN_PROTOCOL_VERSION = int(os.environ.get("PLURALLOG_MIN_PROTOCOL_VERSION", "1"))
LATEST_CLIENT_VERSION = os.environ.get("PLURALLOG_LATEST_CLIENT_VERSION", "")  # empty = no upgrade hint

# ─── Storage ───────────────────────────────────────────────────
DATABASE_PATH = os.environ.get("PLURALLOG_DB_PATH", "plurallog_relay.db")
VOLUME_STORAGE_PATH = os.environ.get("PLURALLOG_VOLUME_PATH", "volume_storage")

# ─── Limits ────────────────────────────────────────────────────
MAX_VOLUME_SIZE_BYTES = int(os.environ.get("PLURALLOG_MAX_VOLUME_SIZE", str(10 * 1024 * 1024)))  # 10MB per volume
MAX_USER_STORAGE_BYTES = int(os.environ.get("PLURALLOG_MAX_USER_STORAGE", str(50 * 1024 * 1024)))  # 50MB per user

# ─── Rate Limiting ───────────────────────────────────────────
RATE_LIMIT_AUTH_PER_MIN = int(os.environ.get("PLURALLOG_RATE_AUTH", "6"))
RATE_LIMIT_UPLOAD_PER_MIN = int(os.environ.get("PLURALLOG_RATE_UPLOAD", "12"))
RATE_LIMIT_GENERAL_PER_MIN = int(os.environ.get("PLURALLOG_RATE_GENERAL", "60"))
RATE_LIMIT_UNAUTH_PER_MIN = int(os.environ.get("PLURALLOG_RATE_UNAUTH", "10"))
RATE_LIMIT_DISCOVERY_PER_MIN = int(os.environ.get("PLURALLOG_RATE_DISCOVERY", "10"))

# ─── Auth ──────────────────────────────────────────────────────
SESSION_TOKEN_LIFETIME_SECONDS = int(os.environ.get("PLURALLOG_SESSION_LIFETIME", "3600"))  # 1 hour
CHALLENGE_NONCE_BYTES = 32

# ─── Proof of Work ─────────────────────────────────────────────
POW_DIFFICULTY_BITS = int(os.environ.get("PLURALLOG_POW_DIFFICULTY", "0"))  # 0 = disabled for dev

# ─── Discovery ─────────────────────────────────────────────────
MAX_DISCOVERY_RESULTS = 10

# ─── Invite codes ─────────────────────────────────────────────
INVITE_CODE_LENGTH = 12
INVITE_CODE_LIFETIME_HOURS = int(os.environ.get("PLURALLOG_INVITE_LIFETIME_HOURS", "72"))

# ─── TLS ───────────────────────────────────────────────────────
TLS_CERT_PATH = os.environ.get("PLURALLOG_TLS_CERT", "")
TLS_KEY_PATH = os.environ.get("PLURALLOG_TLS_KEY", "")

# ─── Server ────────────────────────────────────────────────────
HOST = os.environ.get("PLURALLOG_HOST", "0.0.0.0")
PORT = int(os.environ.get("PLURALLOG_PORT", "8443"))
