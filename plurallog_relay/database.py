"""
Database layer — SQLite for relational data.
Volume blobs are stored on the filesystem (see volume_store.py).

Try to ensure no plaintext user data ever touches this database.
The only cleartext stored here is: UUIDs, public keys, handles,
version numbers, timestamps, and sharing metadata.
"""
import sqlite3
import os
import threading
from datetime import datetime, timezone
from contextlib import contextmanager

from . import config


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


class Database:
    """Thread-safe SQLite wrapper for the relay server."""

    def __init__(self, db_path: str | None = None):
        self._db_path = db_path or config.DATABASE_PATH
        self._local = threading.local()
        self._init_schema()

    def _get_conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn") or self._local.conn is None:
            conn = sqlite3.connect(self._db_path)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA foreign_keys=ON")
            conn.execute("PRAGMA busy_timeout=5000")
            self._local.conn = conn
        return self._local.conn

    @contextmanager
    def transaction(self):
        conn = self._get_conn()
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise

    def query(self, sql: str, params=()) -> list[sqlite3.Row]:
        return self._get_conn().execute(sql, params).fetchall()

    def query_one(self, sql: str, params=()) -> sqlite3.Row | None:
        return self._get_conn().execute(sql, params).fetchone()

    def execute(self, sql: str, params=()) -> int:
        cur = self._get_conn().execute(sql, params)
        self._get_conn().commit()
        return cur.lastrowid or cur.rowcount

    def _init_schema(self):
        conn = self._get_conn()
        conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id              TEXT PRIMARY KEY,
            public_signing_key   TEXT NOT NULL,
            public_exchange_key  TEXT NOT NULL,
            handle          TEXT UNIQUE,
            client_type     TEXT NOT NULL CHECK(client_type IN ('system', 'friend')),
            protocol_version INTEGER NOT NULL DEFAULT 1,
            feature_set     TEXT NOT NULL DEFAULT '[]',
            storage_used_bytes INTEGER NOT NULL DEFAULT 0,
            created_at      TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_users_handle ON users(handle);
        CREATE INDEX IF NOT EXISTS idx_users_client_type ON users(client_type);

        CREATE TABLE IF NOT EXISTS volumes (
            user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            volume_name     TEXT NOT NULL,
            version         INTEGER NOT NULL DEFAULT 0,
            control_header  TEXT NOT NULL DEFAULT '{}',
            payload_path    TEXT NOT NULL DEFAULT '',
            signature       TEXT NOT NULL DEFAULT '',
            size_bytes      INTEGER NOT NULL DEFAULT 0,
            updated_at      TEXT NOT NULL,
            PRIMARY KEY (user_id, volume_name)
        );

        CREATE TABLE IF NOT EXISTS sharing (
            id              TEXT PRIMARY KEY,
            system_user_id  TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            friend_user_id  TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            status          TEXT NOT NULL DEFAULT 'pending'
                            CHECK(status IN ('pending', 'active', 'revoked')),
            permissions     TEXT NOT NULL DEFAULT '{}',
            encrypted_vek_blob TEXT,
            created_at      TEXT NOT NULL,
            updated_at      TEXT NOT NULL,
            UNIQUE(system_user_id, friend_user_id)
        );

        CREATE INDEX IF NOT EXISTS idx_sharing_system ON sharing(system_user_id);
        CREATE INDEX IF NOT EXISTS idx_sharing_friend ON sharing(friend_user_id);
        CREATE INDEX IF NOT EXISTS idx_sharing_status ON sharing(status);

        CREATE TABLE IF NOT EXISTS invite_codes (
            code            TEXT PRIMARY KEY,
            system_user_id  TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            created_at      TEXT NOT NULL,
            expires_at      TEXT NOT NULL,
            redeemed_by     TEXT REFERENCES users(id),
            redeemed_at     TEXT
        );

        CREATE TABLE IF NOT EXISTS auth_challenges (
            nonce           TEXT PRIMARY KEY,
            user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            expires_at      TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS auth_sessions (
            token           TEXT PRIMARY KEY,
            user_id         TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            expires_at      TEXT NOT NULL
        );

        CREATE INDEX IF NOT EXISTS idx_sessions_user ON auth_sessions(user_id);
        CREATE INDEX IF NOT EXISTS idx_sessions_expires ON auth_sessions(expires_at);

        -- Rate limiting table (sliding window counters)
        CREATE TABLE IF NOT EXISTS rate_limits (
            key             TEXT NOT NULL,
            window_start    INTEGER NOT NULL,
            count           INTEGER NOT NULL DEFAULT 1,
            PRIMARY KEY (key, window_start)
        );
        """)
        conn.commit()

    # ─── Users ──────────────────────────────────────────────────

    def create_user(self, user_id: str, public_signing_key: str,
                    public_exchange_key: str, handle: str | None,
                    client_type: str, protocol_version: int,
                    feature_set: str) -> None:
        self.execute(
            """INSERT INTO users
               (id, public_signing_key, public_exchange_key, handle,
                client_type, protocol_version, feature_set, created_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (user_id, public_signing_key, public_exchange_key, handle,
             client_type, protocol_version, feature_set, _utcnow()))

    def get_user(self, user_id: str) -> sqlite3.Row | None:
        return self.query_one("SELECT * FROM users WHERE id = ?", (user_id,))

    def get_user_by_handle(self, handle: str) -> sqlite3.Row | None:
        return self.query_one("SELECT * FROM users WHERE handle = ?", (handle,))

    def update_user(self, user_id: str, **fields) -> None:
        sets = ", ".join(f"{k} = ?" for k in fields)
        vals = list(fields.values()) + [user_id]
        self.execute(f"UPDATE users SET {sets} WHERE id = ?", vals)

    def delete_user(self, user_id: str) -> None:
        """Delete a user and all dependent data in correct FK order.

        SQLite's ON DELETE CASCADE *should* handle this, but the
        invite_codes.redeemed_by FK lacks ON DELETE SET NULL, so
        deleting a user who redeemed an invite causes an IntegrityError.
        We also wrap everything in a single transaction to avoid
        leaving the DB locked if one step fails.
        """
        with self.transaction() as conn:
            # Clear redeemed_by references (nullable FK without ON DELETE SET NULL)
            conn.execute(
                "UPDATE invite_codes SET redeemed_by = NULL, redeemed_at = NULL WHERE redeemed_by = ?",
                (user_id,))
            # Delete invite codes created by this user
            conn.execute("DELETE FROM invite_codes WHERE system_user_id = ?", (user_id,))
            # Delete sharing relationships (both sides)
            conn.execute("DELETE FROM sharing WHERE system_user_id = ? OR friend_user_id = ?",
                         (user_id, user_id))
            # Delete auth data
            conn.execute("DELETE FROM auth_sessions WHERE user_id = ?", (user_id,))
            conn.execute("DELETE FROM auth_challenges WHERE user_id = ?", (user_id,))
            # Delete volumes
            conn.execute("DELETE FROM volumes WHERE user_id = ?", (user_id,))
            # Finally delete the user
            conn.execute("DELETE FROM users WHERE id = ?", (user_id,))

    def count_users(self) -> int:
        row = self.query_one("SELECT COUNT(*) as cnt FROM users")
        return row["cnt"] if row else 0

    def discover_users(self, query: str, caller_type: str, limit: int = 10) -> list:
        # Cross-type discovery only
        target_type = "system" if caller_type == "friend" else "friend"
        return self.query(
            """SELECT id, handle, public_exchange_key, client_type,
                      protocol_version, feature_set
               FROM users
               WHERE client_type = ? AND handle LIKE ? AND handle IS NOT NULL
               LIMIT ?""",
            (target_type, f"%{query}%", limit))

    # ─── Volumes ────────────────────────────────────────────────

    def get_volume(self, user_id: str, volume_name: str) -> sqlite3.Row | None:
        return self.query_one(
            "SELECT * FROM volumes WHERE user_id = ? AND volume_name = ?",
            (user_id, volume_name))

    def upsert_volume(self, user_id: str, volume_name: str, version: int,
                      control_header: str, payload_path: str,
                      signature: str, size_bytes: int) -> None:
        self.execute(
            """INSERT INTO volumes
               (user_id, volume_name, version, control_header, payload_path,
                signature, size_bytes, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?, ?)
               ON CONFLICT(user_id, volume_name) DO UPDATE SET
                 version = excluded.version,
                 control_header = excluded.control_header,
                 payload_path = excluded.payload_path,
                 signature = excluded.signature,
                 size_bytes = excluded.size_bytes,
                 updated_at = excluded.updated_at""",
            (user_id, volume_name, version, control_header, payload_path,
             signature, size_bytes, _utcnow()))

    def list_volumes(self, user_id: str) -> list:
        return self.query(
            "SELECT volume_name, version, control_header, size_bytes, updated_at "
            "FROM volumes WHERE user_id = ?", (user_id,))

    def delete_volumes(self, user_id: str) -> None:
        self.execute("DELETE FROM volumes WHERE user_id = ?", (user_id,))

    def get_user_storage(self, user_id: str) -> int:
        row = self.query_one(
            "SELECT COALESCE(SUM(size_bytes), 0) as total FROM volumes WHERE user_id = ?",
            (user_id,))
        return row["total"] if row else 0

    # ─── Sharing ────────────────────────────────────────────────

    def create_sharing(self, sharing_id: str, system_user_id: str,
                       friend_user_id: str) -> None:
        self.execute(
            """INSERT INTO sharing
               (id, system_user_id, friend_user_id, status, permissions,
                created_at, updated_at)
               VALUES (?, ?, ?, 'pending', '{}', ?, ?)""",
            (sharing_id, system_user_id, friend_user_id, _utcnow(), _utcnow()))

    def get_sharing(self, sharing_id: str) -> sqlite3.Row | None:
        return self.query_one("SELECT * FROM sharing WHERE id = ?", (sharing_id,))

    def get_sharing_between(self, system_user_id: str,
                            friend_user_id: str) -> sqlite3.Row | None:
        return self.query_one(
            """SELECT * FROM sharing
               WHERE system_user_id = ? AND friend_user_id = ?
               AND status != 'revoked'""",
            (system_user_id, friend_user_id))

    def get_sharing_requests(self, user_id: str, user_type: str,
                             status: str = "pending") -> list:
        if status == "all":
            status_clause = "status IN ('pending', 'active')"
            params: tuple = ()
        else:
            status_clause = "status = ?"
            params = (status,)

        if user_type == "system":
            return self.query(
                f"""SELECT s.*, u.public_exchange_key as friend_exchange_public_key,
                           u.handle as friend_handle
                    FROM sharing s
                    JOIN users u ON u.id = s.friend_user_id
                    WHERE s.system_user_id = ? AND {status_clause}
                    ORDER BY s.created_at DESC""",
                (user_id,) + params)
        else:
            return self.query(
                f"""SELECT s.*, NULL as friend_exchange_public_key,
                           u.handle as system_handle,
                           u.public_exchange_key as system_exchange_public_key
                    FROM sharing s
                    JOIN users u ON u.id = s.system_user_id
                    WHERE s.friend_user_id = ? AND {status_clause}
                    ORDER BY s.created_at DESC""",
                (user_id,) + params)

    def update_sharing(self, sharing_id: str, **fields) -> None:
        fields["updated_at"] = _utcnow()
        sets = ", ".join(f"{k} = ?" for k in fields)
        vals = list(fields.values()) + [sharing_id]
        self.execute(f"UPDATE sharing SET {sets} WHERE id = ?", vals)

    def delete_sharing(self, sharing_id: str) -> None:
        self.execute("DELETE FROM sharing WHERE id = ?", (sharing_id,))

    def get_active_sharing(self, system_user_id: str,
                           friend_user_id: str) -> sqlite3.Row | None:
        return self.query_one(
            """SELECT * FROM sharing
               WHERE system_user_id = ? AND friend_user_id = ? AND status = 'active'""",
            (system_user_id, friend_user_id))

    # ─── Invite Codes ──────────────────────────────────────────

    def create_invite(self, code: str, system_user_id: str,
                      expires_at: str) -> None:
        self.execute(
            """INSERT INTO invite_codes (code, system_user_id, created_at, expires_at)
               VALUES (?, ?, ?, ?)""",
            (code, system_user_id, _utcnow(), expires_at))

    def get_invite(self, code: str) -> sqlite3.Row | None:
        return self.query_one(
            "SELECT * FROM invite_codes WHERE code = ?", (code,))

    def redeem_invite(self, code: str, friend_user_id: str) -> None:
        self.execute(
            """UPDATE invite_codes
               SET redeemed_by = ?, redeemed_at = ?
               WHERE code = ?""",
            (friend_user_id, _utcnow(), code))

    # ─── Auth ──────────────────────────────────────────────────

    def store_challenge(self, nonce: str, user_id: str,
                        expires_at: str) -> None:
        self.execute(
            """INSERT OR REPLACE INTO auth_challenges (nonce, user_id, expires_at)
               VALUES (?, ?, ?)""",
            (nonce, user_id, expires_at))

    def get_challenge(self, nonce: str) -> sqlite3.Row | None:
        return self.query_one(
            "SELECT * FROM auth_challenges WHERE nonce = ?", (nonce,))

    def delete_challenge(self, nonce: str) -> None:
        self.execute("DELETE FROM auth_challenges WHERE nonce = ?", (nonce,))

    def store_session(self, token: str, user_id: str,
                      expires_at: str) -> None:
        self.execute(
            """INSERT INTO auth_sessions (token, user_id, expires_at)
               VALUES (?, ?, ?)""",
            (token, user_id, expires_at))

    def get_session(self, token: str) -> sqlite3.Row | None:
        return self.query_one(
            "SELECT * FROM auth_sessions WHERE token = ?", (token,))

    def delete_sessions_for_user(self, user_id: str) -> None:
        self.execute(
            "DELETE FROM auth_sessions WHERE user_id = ?", (user_id,))

    def cleanup_expired(self) -> None:
        """Remove expired sessions, challenges, and rate limit entries."""
        now = _utcnow()
        self.execute("DELETE FROM auth_sessions WHERE expires_at < ?", (now,))
        self.execute("DELETE FROM auth_challenges WHERE expires_at < ?", (now,))
        import time
        window = int(time.time()) - 120  # 2 minutes ago
        self.execute("DELETE FROM rate_limits WHERE window_start < ?", (window,))

    # ─── Rate Limiting ─────────────────────────────────────────

    def check_rate_limit(self, key: str, max_per_minute: int) -> bool:
        """
        Sliding-window rate limiter.
        Returns True if the request is ALLOWED, False if rate-limited.
        """
        import time
        now = int(time.time())
        window = now // 60  # 1-minute windows

        row = self.query_one(
            "SELECT count FROM rate_limits WHERE key = ? AND window_start = ?",
            (key, window))

        if row and row["count"] >= max_per_minute:
            return False

        self.execute(
            """INSERT INTO rate_limits (key, window_start, count)
               VALUES (?, ?, 1)
               ON CONFLICT(key, window_start) DO UPDATE SET count = count + 1""",
            (key, window))
        return True
