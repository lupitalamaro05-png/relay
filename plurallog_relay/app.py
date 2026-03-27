"""
PluralLog Relay Server — Flask Application.

"""
import json
import time
import base64
import logging
from datetime import datetime, timezone, timedelta
from functools import wraps
from uuid import uuid4

from flask import Flask, request, jsonify, g

from . import __version__, config
from .database import Database
from .volume_store import VolumeStore
from .crypto import (
    verify_ed25519_signature,
    generate_nonce,
    generate_session_token,
    generate_invite_code,
    paillier_add_encrypted,
)
from .permissions import is_volume_allowed, permissions_to_volumes, VALID_VOLUME_NAMES

logger = logging.getLogger(__name__)

# ─── Global singletons (initialized in create_app) ────────────
db: Database = None  # type: ignore
volumes: VolumeStore = None  # type: ignore
_start_time: float = 0.0


def create_app(db_path: str | None = None, vol_path: str | None = None) -> Flask:
    global db, volumes, _start_time

    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = config.MAX_VOLUME_SIZE_BYTES + 1024 * 1024  # headroom for JSON envelope

    db = Database(db_path)
    volumes = VolumeStore(vol_path)
    _start_time = time.time()

    # ─── CORS (permissive — server is an API relay) ────────────
    @app.after_request
    def add_cors(response):
        response.headers["Access-Control-Allow-Origin"] = "*"
        response.headers["Access-Control-Allow-Headers"] = (
            "Content-Type, Authorization, X-Protocol-Version, X-Feature-Set, If-None-Match"
        )
        response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, PATCH, DELETE, OPTIONS"
        return response

    @app.before_request
    def handle_options():
        if request.method == "OPTIONS":
            return "", 204

    # ─── Minimal access logging (no bodies, no IPs per spec) ──
    @app.after_request
    def log_access(response):
        user_id = getattr(g, "user_id", "-")
        logger.info(
            f"{datetime.now(timezone.utc).isoformat()} "
            f"{request.method} {request.path} "
            f"{response.status_code} user={user_id}"
        )
        return response

    # ─── Version check middleware ──────────────────────────────
    @app.before_request
    def check_protocol_version():
        # Skip for health, admin, and OPTIONS
        if request.path == "/api/v1/health" or request.path.startswith("/api/v1/admin/") or request.method == "OPTIONS":
            return None
        version_str = request.headers.get("X-Protocol-Version")
        if version_str:
            try:
                client_version = int(version_str)
                if client_version < config.MIN_PROTOCOL_VERSION:
                    return jsonify({
                        "error": "upgrade_required",
                        "message": f"This server requires protocol version {config.MIN_PROTOCOL_VERSION} or higher. Please update your app.",
                    }), 426
            except ValueError:
                pass  # Non-numeric, ignore
        return None

    @app.after_request
    def add_upgrade_hint(response):
        if config.LATEST_CLIENT_VERSION:
            response.headers["X-Upgrade-Available"] = (
                f"A newer client version ({config.LATEST_CLIENT_VERSION}) is available."
            )
        return response

    # Register all route blueprints
    _register_routes(app)

    return app


# ─── Auth Helpers ──────────────────────────────────────────────

def _error(message: str, status: int = 400):
    return jsonify({"error": message, "message": message}), status


def _require_auth(f):
    """Decorator: require valid bearer token. Sets g.user_id and g.user."""
    @wraps(f)
    def wrapper(*args, **kwargs):
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return _error("Missing or invalid Authorization header", 401)
        token = auth[7:]

        session = db.get_session(token)
        if not session:
            return _error("Invalid session token", 401)

        if session["expires_at"] < datetime.now(timezone.utc).isoformat():
            db.execute("DELETE FROM auth_sessions WHERE token = ?", (token,))
            return _error("Session expired", 401)

        user = db.get_user(session["user_id"])
        if not user:
            return _error("User not found", 401)

        g.user_id = user["id"]
        g.user = user
        return f(*args, **kwargs)
    return wrapper


def _require_system(f):
    """Decorator: require authenticated system client."""
    @wraps(f)
    @_require_auth
    def wrapper(*args, **kwargs):
        if g.user["client_type"] != "system":
            return _error("Only system clients can perform this action", 403)
        return f(*args, **kwargs)
    return wrapper


def _require_friend(f):
    """Decorator: require authenticated friend client."""
    @wraps(f)
    @_require_auth
    def wrapper(*args, **kwargs):
        if g.user["client_type"] != "friend":
            return _error("Only friend clients can perform this action", 403)
        return f(*args, **kwargs)
    return wrapper


def _rate_limit(key_prefix: str, limit: int):
    """Decorator: apply rate limiting."""
    def decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            user_id = getattr(g, "user_id", request.remote_addr or "anon")
            rl_key = f"{key_prefix}:{user_id}"
            if not db.check_rate_limit(rl_key, limit):
                resp = jsonify({
                    "error": "rate_limited",
                    "message": "Too many requests. Please wait and try again.",
                })
                resp.status_code = 429
                resp.headers["Retry-After"] = "60"
                return resp
            return f(*args, **kwargs)
        return wrapper
    return decorator


# ─── Route Registration ───────────────────────────────────────

def _register_routes(app: Flask):


    # HEALTH


    @app.route("/api/v1/health", methods=["GET"])
    def health():
        return jsonify({
            "status": "ok",
            "version": __version__,
            "min_protocol_version": config.MIN_PROTOCOL_VERSION,
            "registered_users": db.count_users(),
            "uptime_seconds": int(time.time() - _start_time),
        })


    # REGISTRATION


    @app.route("/api/v1/register", methods=["POST"])
    @_rate_limit("register", config.RATE_LIMIT_UNAUTH_PER_MIN)
    def register():
        data = request.get_json(silent=True)
        if not data:
            return _error("Invalid JSON body")

        required = ["public_signing_key", "public_exchange_key", "client_type",
                     "protocol_version", "feature_set"]
        for field in required:
            if field not in data:
                return _error(f"Missing required field: {field}")

        client_type = data["client_type"]
        if client_type not in ("system", "friend"):
            return _error("client_type must be 'system' or 'friend'")

        protocol_version = data["protocol_version"]
        if isinstance(protocol_version, int) and protocol_version < config.MIN_PROTOCOL_VERSION:
            return jsonify({
                "error": "upgrade_required",
                "message": f"This server requires protocol version {config.MIN_PROTOCOL_VERSION}+",
            }), 426

        handle = data.get("handle")
        if handle:
            handle = str(handle).strip()[:64]
            if db.get_user_by_handle(handle):
                return _error("Handle already taken", 409)

        # Validate keys are valid base64
        try:
            base64.b64decode(data["public_signing_key"])
            base64.b64decode(data["public_exchange_key"])
        except Exception:
            return _error("Invalid base64 key encoding")

        user_id = str(uuid4())
        feature_set = json.dumps(data.get("feature_set", []))

        db.create_user(
            user_id=user_id,
            public_signing_key=data["public_signing_key"],
            public_exchange_key=data["public_exchange_key"],
            handle=handle if handle else None,
            client_type=client_type,
            protocol_version=protocol_version,
            feature_set=feature_set,
        )

        return jsonify({
            "user_id": user_id,
            "server_min_version": config.MIN_PROTOCOL_VERSION,
        }), 201


    # AUTHENTICATION (challenge-response with Ed25519)


    @app.route("/api/v1/auth/challenge", methods=["POST"])
    @_rate_limit("auth", config.RATE_LIMIT_AUTH_PER_MIN)
    def auth_challenge():
        data = request.get_json(silent=True)
        if not data or "user_id" not in data:
            return _error("Missing user_id")

        user = db.get_user(data["user_id"])
        if not user:
            return _error("User not found", 404)

        nonce = generate_nonce()
        expires = (datetime.now(timezone.utc) +
                   timedelta(minutes=5)).isoformat()

        db.store_challenge(nonce, data["user_id"], expires)

        return jsonify({
            "nonce": nonce,
            "expires_at": expires,
        })

    @app.route("/api/v1/auth/token", methods=["POST"])
    @_rate_limit("auth", config.RATE_LIMIT_AUTH_PER_MIN)
    def auth_token():
        data = request.get_json(silent=True)
        if not data:
            return _error("Invalid JSON body")

        required = ["user_id", "nonce", "signature"]
        for field in required:
            if field not in data:
                return _error(f"Missing required field: {field}")

        user = db.get_user(data["user_id"])
        if not user:
            return _error("User not found", 404)

        # Check challenge exists and is not expired
        challenge = db.get_challenge(data["nonce"])
        if not challenge:
            return _error("Invalid or expired challenge nonce", 403)

        if challenge["user_id"] != data["user_id"]:
            return _error("Challenge does not belong to this user", 403)

        if challenge["expires_at"] < datetime.now(timezone.utc).isoformat():
            db.delete_challenge(data["nonce"])
            return _error("Challenge expired", 403)

        # Verify Ed25519 signature over the nonce string
        # The client signs: utf8.encode(nonce) — the raw nonce string bytes
        nonce_bytes = data["nonce"].encode("utf-8")

        if not verify_ed25519_signature(
            user["public_signing_key"],
            nonce_bytes,
            data["signature"],
        ):
            return _error("Invalid signature", 403)

        # Consume the challenge
        db.delete_challenge(data["nonce"])

        # Issue session token
        token = generate_session_token()
        expires = (datetime.now(timezone.utc) +
                   timedelta(seconds=config.SESSION_TOKEN_LIFETIME_SECONDS)).isoformat()
        db.store_session(token, data["user_id"], expires)

        return jsonify({
            "token": token,
            "expires_at": expires,
        })


    # USER MANAGEMENT


    @app.route("/api/v1/users/me", methods=["PATCH"])
    @_require_auth
    @_rate_limit("general", config.RATE_LIMIT_GENERAL_PER_MIN)
    def update_user():
        data = request.get_json(silent=True)
        if not data:
            return _error("Invalid JSON body")

        updates = {}
        if "handle" in data:
            handle = data["handle"]
            if handle:
                handle = str(handle).strip()[:64]
                existing = db.get_user_by_handle(handle)
                if existing and existing["id"] != g.user_id:
                    return _error("Handle already taken", 409)
            updates["handle"] = handle

        if "protocol_version" in data:
            updates["protocol_version"] = data["protocol_version"]

        if "feature_set" in data:
            updates["feature_set"] = json.dumps(data["feature_set"])

        if updates:
            db.update_user(g.user_id, **updates)

        return jsonify({"status": "updated"})

    @app.route("/api/v1/users/me", methods=["DELETE"])
    @_require_auth
    def delete_user():
        user_id = g.user_id

        # Delete volume blobs from filesystem
        volumes.delete_user(user_id)

        # Delete all database records (cascading)
        db.delete_user(user_id)

        return "", 204


    # VOLUME UPLOAD (System App only)


    @app.route("/api/v1/volumes/<volume_name>", methods=["PUT"])
    @_require_system
    @_rate_limit("upload", config.RATE_LIMIT_UPLOAD_PER_MIN)
    def upload_volume(volume_name):
        if volume_name not in VALID_VOLUME_NAMES:
            return _error(f"Invalid volume name: {volume_name}")

        data = request.get_json(silent=True)
        if not data:
            return _error("Invalid JSON body")

        required = ["control_header", "encrypted_payload", "signature"]
        for field in required:
            if field not in data:
                return _error(f"Missing required field: {field}")

        control_header = data["control_header"]
        encrypted_payload_b64 = data["encrypted_payload"]
        signature_b64 = data["signature"]

        # Validate control header
        if control_header.get("volume_name") != volume_name:
            return _error("Volume name mismatch between URL and control header")

        new_version = control_header.get("version")
        if not isinstance(new_version, int) or new_version < 1:
            return _error("Version must be a positive integer")

        # Check version is strictly greater than stored
        existing = db.get_volume(g.user_id, volume_name)
        if existing and existing["version"] >= new_version:
            return jsonify({
                "error": "conflict",
                "message": f"Volume version must be > {existing['version']}, got {new_version}",
            }), 409

        # Decode payload
        try:
            payload_bytes = base64.b64decode(encrypted_payload_b64)
        except Exception:
            return _error("Invalid base64 in encrypted_payload")

        # Check size limits
        if len(payload_bytes) > config.MAX_VOLUME_SIZE_BYTES:
            return _error(f"Volume exceeds max size ({config.MAX_VOLUME_SIZE_BYTES} bytes)", 413)

        current_storage = db.get_user_storage(g.user_id)
        old_size = existing["size_bytes"] if existing else 0
        new_total = current_storage - old_size + len(payload_bytes)
        if new_total > config.MAX_USER_STORAGE_BYTES:
            return _error(f"User storage quota exceeded ({config.MAX_USER_STORAGE_BYTES} bytes)", 413)

        # Verify Ed25519 signature over (header_json || payload_bytes)
        # Client does: sign(utf8.encode(jsonEncode(header)) + padded_payload)
        header_json = json.dumps(control_header, separators=(",", ":"), sort_keys=False)
        # The client uses Dart's jsonEncode which produces compact JSON.
        # We need to match the exact bytes the client signed.
        # Re-serialize the control header to match the client's output.
        # The client sends header.toJson() which has specific key order:
        # volume_name, version, modified_at, size_bytes, event_tags
        client_header = {
            "volume_name": control_header["volume_name"],
            "version": control_header["version"],
            "modified_at": control_header["modified_at"],
            "size_bytes": control_header["size_bytes"],
            "event_tags": control_header.get("event_tags", []),
        }
        header_bytes = json.dumps(client_header, separators=(",", ":")).encode("utf-8")
        signature_message = header_bytes + payload_bytes

        if not verify_ed25519_signature(
            g.user["public_signing_key"],
            signature_message,
            signature_b64,
        ):
            return _error("Invalid volume signature", 403)

        # Store the encrypted blob on filesystem
        payload_path = volumes.store(g.user_id, volume_name, payload_bytes)

        # Update database
        db.upsert_volume(
            user_id=g.user_id,
            volume_name=volume_name,
            version=new_version,
            control_header=json.dumps(control_header),
            payload_path=payload_path,
            signature=signature_b64,
            size_bytes=len(payload_bytes),
        )

        # Update user storage counter
        db.update_user(g.user_id, storage_used_bytes=new_total)

        return jsonify({"status": "stored", "version": new_version})


    # VOLUME LISTING


    @app.route("/api/v1/volumes", methods=["GET"])
    @_require_auth
    @_rate_limit("general", config.RATE_LIMIT_GENERAL_PER_MIN)
    def list_volumes():
        rows = db.list_volumes(g.user_id)
        result = []
        for row in rows:
            try:
                header = json.loads(row["control_header"])
            except (json.JSONDecodeError, TypeError):
                header = {"volume_name": row["volume_name"],
                          "version": row["version"]}
            result.append(header)
        return jsonify({"volumes": result})


    # SELF-DOWNLOAD (System App backup — own volumes)


    @app.route("/api/v1/volumes/<volume_name>/download", methods=["GET"])
    @_require_system
    @_rate_limit("general", config.RATE_LIMIT_GENERAL_PER_MIN)
    def download_own_volume(volume_name):
        """
        Download own encrypted volume blob for backup/multi-device sync.
        The system user already holds the VEK locally, so no key blob is needed.
        Supports conditional GET via If-None-Match with version counter.
        """
        if volume_name not in VALID_VOLUME_NAMES:
            return _error(f"Invalid volume name: {volume_name}")

        vol = db.get_volume(g.user_id, volume_name)
        if not vol:
            return _error("Volume not found", 404)

        # Conditional GET
        if_none_match = request.headers.get("If-None-Match")
        if if_none_match:
            try:
                client_version = int(if_none_match)
                if client_version >= vol["version"]:
                    return "", 304
            except ValueError:
                pass

        payload_bytes = volumes.load(g.user_id, volume_name)
        if payload_bytes is None:
            return _error("Volume data missing from storage", 500)

        try:
            control_header = json.loads(vol["control_header"])
        except (json.JSONDecodeError, TypeError):
            control_header = {}

        return jsonify({
            "control_header": control_header,
            "encrypted_payload": base64.b64encode(payload_bytes).decode(),
            "signature": vol["signature"],
        })


    # SHARED VOLUME DOWNLOAD (Friend Client only)


    @app.route("/api/v1/shared/<system_user_id>/volumes/<volume_name>", methods=["GET"])
    @_require_friend
    @_rate_limit("general", config.RATE_LIMIT_GENERAL_PER_MIN)
    def download_shared_volume(system_user_id, volume_name):
        if volume_name not in VALID_VOLUME_NAMES:
            return _error(f"Invalid volume name: {volume_name}")

        # Check active sharing relationship
        sharing = db.get_active_sharing(system_user_id, g.user_id)
        if not sharing:
            return _error("No active sharing relationship", 403)

        # Check per-volume permissions
        if not is_volume_allowed(sharing["permissions"], volume_name):
            return _error("This volume is not shared with you", 403)

        # Get volume metadata
        vol = db.get_volume(system_user_id, volume_name)
        if not vol:
            return _error("Volume not found", 404)

        # Conditional GET: If-None-Match with version counter
        if_none_match = request.headers.get("If-None-Match")
        if if_none_match:
            try:
                client_version = int(if_none_match)
                if client_version >= vol["version"]:
                    return "", 304
            except ValueError:
                pass

        # Load encrypted blob
        payload_bytes = volumes.load(system_user_id, volume_name)
        if payload_bytes is None:
            return _error("Volume data missing from storage", 500)

        try:
            control_header = json.loads(vol["control_header"])
        except (json.JSONDecodeError, TypeError):
            control_header = {}

        return jsonify({
            "control_header": control_header,
            "encrypted_payload": base64.b64encode(payload_bytes).decode(),
            "signature": vol["signature"],
            "encrypted_vek_blob": sharing["encrypted_vek_blob"],
        })

    @app.route("/api/v1/shared/<system_user_id>/volumes", methods=["GET"])
    @_require_friend
    @_rate_limit("general", config.RATE_LIMIT_GENERAL_PER_MIN)
    def list_shared_volumes(system_user_id):
        # Check active sharing relationship
        sharing = db.get_active_sharing(system_user_id, g.user_id)
        if not sharing:
            return _error("No active sharing relationship", 403)

        # Get all volumes for the system user
        all_vols = db.list_volumes(system_user_id)

        # Filter by permissions
        try:
            perms = json.loads(sharing["permissions"])
        except (json.JSONDecodeError, TypeError):
            perms = {}
        allowed_volumes = permissions_to_volumes(perms)

        # Also check friend's feature set compatibility
        friend_features = set()
        try:
            fs = json.loads(g.user["feature_set"])
            for feat in fs:
                friend_features.add(feat.split(":")[0])
        except (json.JSONDecodeError, TypeError):
            pass

        result = []
        compatibility_notes = []
        for row in all_vols:
            vname = row["volume_name"]
            if vname not in allowed_volumes:
                continue

            # Check friend feature compatibility
            if friend_features and vname not in friend_features and vname != "meta":
                compatibility_notes.append(
                    f"Volume '{vname}' omitted: your client does not support it."
                )
                continue

            try:
                header = json.loads(row["control_header"])
            except (json.JSONDecodeError, TypeError):
                header = {"volume_name": vname, "version": row["version"]}
            result.append(header)

        resp = {"volumes": result}
        if compatibility_notes:
            resp["compatibility_notes"] = compatibility_notes
        return jsonify(resp)


    # DISCOVERY


    @app.route("/api/v1/discover", methods=["GET"])
    @_require_auth
    @_rate_limit("discovery", config.RATE_LIMIT_DISCOVERY_PER_MIN)
    def discover():
        query = request.args.get("handle", "").strip()
        if len(query) < 2:
            return _error("Search query must be at least 2 characters")

        rows = db.discover_users(
            query, g.user["client_type"], config.MAX_DISCOVERY_RESULTS)

        results = []
        for row in rows:
            try:
                fs = json.loads(row["feature_set"])
            except (json.JSONDecodeError, TypeError):
                fs = []
            results.append({
                "user_id": row["id"],
                "handle": row["handle"],
                "public_exchange_key": row["public_exchange_key"],
                "client_type": row["client_type"],
                "protocol_version": row["protocol_version"],
                "feature_set": fs,
            })

        return jsonify({"results": results})


    # SHARING REQUESTS


    @app.route("/api/v1/sharing/request", methods=["POST"])
    @_require_auth
    @_rate_limit("general", config.RATE_LIMIT_GENERAL_PER_MIN)
    def create_sharing_request():
        data = request.get_json(silent=True)
        if not data:
            return _error("Invalid JSON body")

        from_id = data.get("from_user_id")
        to_id = data.get("to_user_id")
        if not from_id or not to_id:
            return _error("Missing from_user_id or to_user_id")

        # The authenticated user must be the sender
        if from_id != g.user_id:
            return _error("from_user_id must match authenticated user", 403)

        # Directionality: friend -> system only
        from_user = db.get_user(from_id)
        to_user = db.get_user(to_id)

        if not from_user or not to_user:
            return _error("User not found", 404)

        if from_user["client_type"] != "friend" or to_user["client_type"] != "system":
            return _error(
                "Sharing requests must be from a friend client to a system client. "
                "System→Friend, System→System, and Friend→Friend are not allowed.",
                400,
            )

        # Check for existing non-revoked relationship
        existing = db.get_sharing_between(to_id, from_id)
        if existing:
            if existing["status"] == "pending":
                return _error("A sharing request is already pending", 409)
            elif existing["status"] == "active":
                return _error("An active sharing relationship already exists", 409)

        sharing_id = str(uuid4())
        db.create_sharing(sharing_id, system_user_id=to_id, friend_user_id=from_id)

        # Return the relationship with the friend's exchange key
        return jsonify({
            "id": sharing_id,
            "system_user_id": to_id,
            "friend_user_id": from_id,
            "friend_exchange_public_key": from_user["public_exchange_key"],
            "status": "pending",
            "permissions": {},
            "encrypted_vek_blob": None,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }), 201

    @app.route("/api/v1/sharing/requests", methods=["GET"])
    @_require_auth
    @_rate_limit("general", config.RATE_LIMIT_GENERAL_PER_MIN)
    def list_sharing_requests():
        status = request.args.get("status", "pending")
        if status not in ("pending", "active", "all"):
            return _error("status must be 'pending', 'active', or 'all'")

        rows = db.get_sharing_requests(g.user_id, g.user["client_type"], status)

        results = []
        for row in rows:
            try:
                perms = json.loads(row["permissions"])
            except (json.JSONDecodeError, TypeError):
                perms = {}
            results.append({
                "id": row["id"],
                "system_user_id": row["system_user_id"],
                "friend_user_id": row["friend_user_id"],
                "friend_exchange_public_key": row["friend_exchange_public_key"],
                "friend_handle": row["friend_handle"] if "friend_handle" in row.keys() else None,
                "system_handle": row["system_handle"] if "system_handle" in row.keys() else None,
                "system_exchange_public_key": row["system_exchange_public_key"] if "system_exchange_public_key" in row.keys() else None,
                "status": row["status"],
                "permissions": perms,
                "encrypted_vek_blob": row["encrypted_vek_blob"],
                "created_at": row["created_at"],
                "updated_at": row["updated_at"],
            })

        return jsonify({"requests": results})

    @app.route("/api/v1/sharing/respond", methods=["POST"])
    @_require_system
    @_rate_limit("general", config.RATE_LIMIT_GENERAL_PER_MIN)
    def respond_to_sharing():
        data = request.get_json(silent=True)
        if not data:
            return _error("Invalid JSON body")

        request_id = data.get("request_id")
        accepted = data.get("accepted")

        if not request_id or accepted is None:
            return _error("Missing request_id or accepted")

        sharing = db.get_sharing(request_id)
        if not sharing:
            return _error("Sharing request not found", 404)

        if sharing["system_user_id"] != g.user_id:
            return _error("Only the system user can respond to this request", 403)

        if sharing["status"] != "pending":
            return _error(f"Cannot respond to a request with status '{sharing['status']}'")

        if accepted:
            vek_blob = data.get("encrypted_vek_blob")
            if not vek_blob:
                return _error("encrypted_vek_blob is required when accepting")

            permissions = data.get("permissions", {})

            db.update_sharing(
                request_id,
                status="active",
                encrypted_vek_blob=vek_blob,
                permissions=json.dumps(permissions),
            )
        else:
            # Rejected — delete the request entirely
            db.delete_sharing(request_id)

        return jsonify({"status": "accepted" if accepted else "rejected"})

    @app.route("/api/v1/sharing/<sharing_id>", methods=["DELETE"])
    @_require_auth
    @_rate_limit("general", config.RATE_LIMIT_GENERAL_PER_MIN)
    def revoke_sharing(sharing_id):
        sharing = db.get_sharing(sharing_id)
        if not sharing:
            return _error("Sharing relationship not found", 404)

        # Either party can revoke
        if g.user_id not in (sharing["system_user_id"], sharing["friend_user_id"]):
            return _error("Not authorized to revoke this relationship", 403)

        db.delete_sharing(sharing_id)

        return "", 204

    @app.route("/api/v1/sharing/<sharing_id>/permissions", methods=["PATCH"])
    @_require_system
    @_rate_limit("general", config.RATE_LIMIT_GENERAL_PER_MIN)
    def update_sharing_permissions(sharing_id):
        data = request.get_json(silent=True)
        if not data or "permissions" not in data:
            return _error("Missing permissions")

        sharing = db.get_sharing(sharing_id)
        if not sharing:
            return _error("Sharing relationship not found", 404)

        if sharing["system_user_id"] != g.user_id:
            return _error("Only the system user can update permissions", 403)

        if sharing["status"] != "active":
            return _error("Can only update permissions on active relationships")

        db.update_sharing(
            sharing_id,
            permissions=json.dumps(data["permissions"]),
        )

        return jsonify({"status": "updated"})


    # INVITE CODES


    @app.route("/api/v1/sharing/invite", methods=["POST"])
    @_require_system
    @_rate_limit("general", config.RATE_LIMIT_GENERAL_PER_MIN)
    def create_invite():
        code = generate_invite_code()
        expires = (datetime.now(timezone.utc) +
                   timedelta(hours=config.INVITE_CODE_LIFETIME_HOURS)).isoformat()

        db.create_invite(code, g.user_id, expires)

        return jsonify({
            "code": code,
            "expires_at": expires,
        }), 201

    @app.route("/api/v1/sharing/redeem", methods=["POST"])
    @_require_auth
    @_rate_limit("general", config.RATE_LIMIT_GENERAL_PER_MIN)
    def redeem_invite():
        data = request.get_json(silent=True)
        if not data or "code" not in data:
            return _error("Missing invite code")

        code = data["code"].strip().upper()
        invite = db.get_invite(code)

        if not invite:
            return _error("Invalid invite code", 404)

        if invite["redeemed_by"]:
            return _error("This invite code has already been redeemed", 410)

        if invite["expires_at"] < datetime.now(timezone.utc).isoformat():
            return _error("This invite code has expired", 410)

        # Verify the redeemer is a friend client
        if g.user["client_type"] != "friend":
            return _error("Only friend clients can redeem invite codes", 400)

        system_user_id = invite["system_user_id"]

        # Check for existing relationship
        existing = db.get_sharing_between(system_user_id, g.user_id)
        if existing:
            return _error("A sharing relationship already exists", 409)

        # Redeem the code
        db.redeem_invite(code, g.user_id)

        # Create a pending sharing request
        sharing_id = str(uuid4())
        db.create_sharing(sharing_id, system_user_id, g.user_id)

        friend_user = db.get_user(g.user_id)

        return jsonify({
            "id": sharing_id,
            "system_user_id": system_user_id,
            "friend_user_id": g.user_id,
            "friend_exchange_public_key": friend_user["public_exchange_key"] if friend_user else None,
            "status": "pending",
            "permissions": {},
            "encrypted_vek_blob": None,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "updated_at": datetime.now(timezone.utc).isoformat(),
        }), 201


    # HOMOMORPHIC ANALYTICS AGGREGATION


    @app.route("/api/v1/analytics/aggregate", methods=["POST"])
    @_require_friend
    @_rate_limit("general", config.RATE_LIMIT_GENERAL_PER_MIN)
    def analytics_aggregate():
        """
        Perform Paillier homomorphic summation on analytics counters.

        The friend client sends:
        {
            "system_user_id": "...",
            "public_key": {"n": "..."}, // Paillier public key
            "counters": {
                "switch_count": ["<enc1>", "<enc2>", ...],
                "mood_score": ["<enc1>", "<enc2>", ...],
            }
        }

        The server sums each counter group WITHOUT decrypting,
        and returns the encrypted sums.

        SECURITY: The server shouldn't see plaintext counter values.
        It only performs Enc(a) * Enc(b) = Enc(a+b) on ciphertexts.
        """
        data = request.get_json(silent=True)
        if not data:
            return _error("Invalid JSON body")

        system_user_id = data.get("system_user_id")
        public_key = data.get("public_key")
        counters = data.get("counters")

        if not system_user_id or not public_key or not counters:
            return _error("Missing system_user_id, public_key, or counters")

        # Verify active sharing with analytics permission
        sharing = db.get_active_sharing(system_user_id, g.user_id)
        if not sharing:
            return _error("No active sharing relationship", 403)

        if not is_volume_allowed(sharing["permissions"], "analytics"):
            return _error("Analytics are not shared with you", 403)

        # Perform homomorphic addition
        public_key_json = json.dumps(public_key)
        results = {}
        for counter_name, ciphertexts in counters.items():
            if not isinstance(ciphertexts, list):
                continue
            result = paillier_add_encrypted(public_key_json, ciphertexts)
            results[counter_name] = result

        return jsonify({"aggregates": results})


    # PERIODIC MAINTENANCE


    @app.route("/api/v1/_maintenance", methods=["POST"])
    def maintenance():
        """
        Cleanup expired sessions, challenges, and rate limits.
        In production, call this periodically via cron or a scheduler.
        """
        db.cleanup_expired()
        return jsonify({"status": "ok"})
