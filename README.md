# PluralLog Relay Server

**Untrusted relay for encrypted volume storage, discovery, and homomorphic analytics.**

This server implements the PluralLog Federation protocol — a zero-trust relay that stores encrypted data blobs for plural system users (via the PluralLog System App) and provides read-only access to trusted friends/family (via the PluralLog Friend Client).

## Security Model

The server is designed to be **fully (in concept) untrusted**. It never sees plaintext user data:

- **All volume payloads** are AES-256-GCM encrypted client-side before upload. The server stores them as opaque blobs.
- **Signature verification** uses Ed25519 public keys registered at signup — the server never holds private keys.
- **Paillier homomorphic encryption** allows the server to compute aggregate analytics (e.g. "sum of daily switch counts") on ciphertexts without decrypting them.
- **No request bodies or volume contents are logged.** Access logs contain only timestamp, method, path, status code, and user ID.
- **System user controls all sharing.** Data flows exclusively from the System App to Friend Clients — never the reverse. Friends can *request* a connection, but the system user decides whether to accept, which volumes to share, and can revoke access at any time. The server enforces this at the protocol level.
- **Per-volume permissions** are enforced server-side — friends can only download volumes the system user has explicitly shared. Despite this, even if shared they shouldn't be easily divulged or decrypted. 

### What the server CAN see (plaintext metadata)
- User IDs, handles, public keys
- Volume version counters and modification timestamps (rounded to nearest hour)
- Volume sizes (padded to 4KB boundaries by the client)
- Bloom filter tags indicating volume types with updates
- Sharing relationship existence and permission flags

### What the server CANNOT see
- Any member names, descriptions, pronouns, or profiles
- Any message text, journal entries, or poll content
- Which member is fronting or front history details
- Any custom field data
- Volume Encryption Keys or derived keys
- Paillier counter plaintext values

## Quick Start

### Option 1: Run directly with Python

```bash
# Install dependencies
pip install -r requirements.txt

# Run in development mode (HTTP, no TLS)
python -m plurallog_relay

# Run with TLS
PLURALLOG_TLS_CERT=cert.pem PLURALLOG_TLS_KEY=key.pem python -m plurallog_relay

# Generate a self-signed cert for testing
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem \
    -days 365 -nodes -subj '/CN=localhost'
```

### Option 2: Docker

```bash
# Build and run
docker compose up -d

### With TLS modify dockerfile first, then run as usual (place certs in ./certs/, uncomment volumes/env in docker-compose.yml)
docker compose up -d

Takes ~130s on my computer (wehich sucks) so not a terrible process.
```

### Option 3: Gunicorn (production, behind reverse proxy)

```bash
pip install -r requirements.txt
gunicorn "plurallog_relay.app:create_app()" \
    --bind 0.0.0.0:8443 \
    --workers 4 \
    --timeout 120
```


## Configuration

All settings are controlled via environment variables:

| Variable | Default | Description |
|---|---|---|
| `PLURALLOG_PORT` | `8443` | Listen port |
| `PLURALLOG_HOST` | `0.0.0.0` | Bind address |
| `PLURALLOG_DB_PATH` | `plurallog_relay.db` | SQLite database path |
| `PLURALLOG_VOLUME_PATH` | `volume_storage/` | Encrypted blob storage directory |
| `PLURALLOG_TLS_CERT` | *(none)* | TLS certificate path |
| `PLURALLOG_TLS_KEY` | *(none)* | TLS private key path |
| `PLURALLOG_MIN_PROTOCOL_VERSION` | `1` | Minimum client protocol version |
| `PLURALLOG_MAX_VOLUME_SIZE` | `10485760` | Max bytes per volume (10MB) |
| `PLURALLOG_MAX_USER_STORAGE` | `52428800` | Max total bytes per user (50MB) |
| `PLURALLOG_POW_DIFFICULTY` | `0` | Proof-of-work difficulty bits (0 = disabled) |
| `PLURALLOG_SESSION_LIFETIME` | `3600` | Auth token lifetime in seconds |
| `PLURALLOG_INVITE_LIFETIME_HOURS` | `72` | Invite code validity period |
| `PLURALLOG_RATE_AUTH` | `6` | Auth requests per minute per user |
| `PLURALLOG_RATE_UPLOAD` | `12` | Volume uploads per minute per user |
| `PLURALLOG_RATE_GENERAL` | `60` | General requests per minute per user |
| `PLURALLOG_RATE_UNAUTH` | `10` | Unauthenticated requests per minute |
| `PLURALLOG_RATE_DISCOVERY` | `10` | Discovery queries per minute per user |

## API Endpoints

### Health
| Method | Path | Description |
|---|---|---|
| `GET` | `/api/v1/health` | Server status, version, uptime |

### Registration & Auth
| Method | Path | Auth | Description |
|---|---|---|---|
| `POST` | `/api/v1/register` | None | Register (system or friend) |
| `POST` | `/api/v1/auth/challenge` | None | Request Ed25519 challenge nonce |
| `POST` | `/api/v1/auth/token` | None | Submit signed challenge for session token |

### User Management
| Method | Path | Auth | Description |
|---|---|---|---|
| `PATCH` | `/api/v1/users/me` | Bearer | Update handle, version, features |
| `DELETE` | `/api/v1/users/me` | Bearer | Delete account and all data |

### Volumes (Data flows System → Friend)
| Method | Path | Auth | Description |
|---|---|---|---|
| `PUT` | `/api/v1/volumes/{name}` | System only | Upload encrypted volume |
| `GET` | `/api/v1/volumes` | Bearer | List own volume metadata |
| `GET` | `/api/v1/shared/{uid}/volumes` | Friend only | List shared volume metadata |
| `GET` | `/api/v1/shared/{uid}/volumes/{name}` | Friend only | Download shared volume |

### Discovery & Sharing (System user controls access)
| Method | Path | Auth | Description |
|---|---|---|---|
| `GET` | `/api/v1/discover?handle={q}` | Bearer | Cross-type user search |
| `POST` | `/api/v1/sharing/request` | Bearer | Friend requests access from system user |
| `GET` | `/api/v1/sharing/requests` | Bearer | List requests (pending/active/all) |
| `POST` | `/api/v1/sharing/respond` | System only | Accept/reject a friend's request |
| `PATCH` | `/api/v1/sharing/{id}/permissions` | System only | Update which volumes a friend can see |
| `DELETE` | `/api/v1/sharing/{id}` | Either party | Revoke sharing relationship |
| `POST` | `/api/v1/sharing/invite` | System only | Generate one-time invite code |
| `POST` | `/api/v1/sharing/redeem` | Friend only | Redeem invite code |

### Analytics (Homomorphic)
| Method | Path | Auth | Description |
|---|---|---|---|
| `POST` | `/api/v1/analytics/aggregate` | Friend only | Paillier homomorphic summation |

## Connecting the Flutter App

1. Start the relay server on a device accessible to both the System App and Friend Client.
2. In the **PluralLog System App**: go to **Settings → Federation**, enter the server URL (e.g. `http://192.168.1.50:8443` or `https://your-domain.com:8443`), and tap **Enable Federation**.
3. The app will register, authenticate, and begin syncing encrypted volumes automatically.
4. To share with a friend: generate an invite code from the Federation screen, or have the friend search for your handle.
5. When a friend requests access, you'll see it as a pending request — you choose which data categories to share.
6. In the **PluralLog Friend app** (when developed): enter the same server URL, then search or redeem the invite code.

## Running Tests

```bash
pip install pytest pynacl phe
python -m pytest tests/test_server.py -v
# python -m pytest to run all, pass in admin test file to test admin routes
```

The test suite covers:
- Health endpoint
- Registration (system & friend, duplicates, protocol version enforcement)
- Ed25519 challenge-response authentication (valid & invalid signatures)
- Volume upload with real cryptographic signature verification
- Version conflict detection (409 on stale uploads)
- Friend upload rejection (only system clients can upload)
- Cross-type discovery (friends find systems, systems find friends, same-type hidden)
- Full sharing lifecycle (request → accept → upload → download → conditional GET → revoke)
- Directionality enforcement (system→friend requests rejected)
- Invite code generation, redemption, and single-use enforcement
- Permission updates on active relationships
- Account deletion with cascade cleanup
- Paillier homomorphic addition (sum encrypted values, verify decrypted result)
- Permission-to-volume mapping logic

## Architecture

```
plurallog_relay/
├── __init__.py          # Package version
├── __main__.py          # python -m plurallog_relay entry point
├── main.py              # Server startup, TLS configuration
├── app.py               # Flask app factory, all API routes
├── config.py            # Environment-driven configuration
├── database.py          # SQLite schema, queries, rate limiting
├── volume_store.py      # Filesystem blob storage for encrypted volumes
├── crypto.py            # Ed25519 verification, Paillier HE, secure random
└── permissions.py       # Permission flag → volume name mapping
```

## License

See project root for license terms (undecided, MIT?).
