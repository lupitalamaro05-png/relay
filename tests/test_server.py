"""
Integration tests for the PluralLog Relay Server.
Tests the full lifecycle: register → auth → upload → discover → share → download → revoke.
Test cryptography to ensure the server's signature verification
is compatible with what the Flutter client produces.
"""
import json
import base64
import os
import sys
import tempfile
import unittest

import nacl.signing
import nacl.public
from nacl.encoding import RawEncoder

# Add parent to path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from plurallog_relay.app import create_app
from plurallog_relay import config


class TestPluralLogRelay(unittest.TestCase):
    """Full integration test suite."""

    def setUp(self):
        """Create a fresh app + database for each test."""
        self.tmpdir = tempfile.mkdtemp()
        db_path = os.path.join(self.tmpdir, "test.db")
        vol_path = os.path.join(self.tmpdir, "volumes")

        self.app = create_app(db_path=db_path, vol_path=vol_path)
        self.app.config["TESTING"] = True
        self.client = self.app.test_client()

        # Generate real Ed25519 + X25519 keypairs for system user
        self.sys_signing_key = nacl.signing.SigningKey.generate()
        self.sys_signing_pub = self.sys_signing_key.verify_key
        self.sys_exchange_key = nacl.public.PrivateKey.generate()
        self.sys_exchange_pub = self.sys_exchange_key.public_key

        # Generate keypairs for friend user
        self.friend_signing_key = nacl.signing.SigningKey.generate()
        self.friend_signing_pub = self.friend_signing_key.verify_key
        self.friend_exchange_key = nacl.public.PrivateKey.generate()
        self.friend_exchange_pub = self.friend_exchange_key.public_key

    def _b64(self, raw_bytes: bytes) -> str:
        return base64.b64encode(raw_bytes).decode()

    def _headers(self, token: str = None):
        h = {
            "Content-Type": "application/json",
            "X-Protocol-Version": "1",
            "X-Feature-Set": "members:1,fronts:1,journal:1,chat:1,polls:1,analytics:1,meta:1",
        }
        if token:
            h["Authorization"] = f"Bearer {token}"
        return h

    # ─── Health ────────────────────────────────────────────────

    def test_health(self):
        r = self.client.get("/api/v1/health")
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertEqual(data["status"], "ok")
        self.assertIn("version", data)
        self.assertIn("min_protocol_version", data)
        self.assertIn("uptime_seconds", data)

    # ─── Registration ──────────────────────────────────────────

    def test_register_system(self):
        r = self.client.post("/api/v1/register",
            headers=self._headers(),
            json={
                "public_signing_key": self._b64(bytes(self.sys_signing_pub)),
                "public_exchange_key": self._b64(bytes(self.sys_exchange_pub)),
                "handle": "test_system",
                "client_type": "system",
                "protocol_version": 1,
                "feature_set": ["members:1", "fronts:1"],
            })
        self.assertEqual(r.status_code, 201)
        data = r.get_json()
        self.assertIn("user_id", data)
        self.assertIn("server_min_version", data)

    def test_register_duplicate_handle(self):
        self._register_system("dup_handle")
        r = self.client.post("/api/v1/register",
            headers=self._headers(),
            json={
                "public_signing_key": self._b64(bytes(nacl.signing.SigningKey.generate().verify_key)),
                "public_exchange_key": self._b64(bytes(nacl.public.PrivateKey.generate().public_key)),
                "handle": "dup_handle",
                "client_type": "system",
                "protocol_version": 1,
                "feature_set": [],
            })
        self.assertEqual(r.status_code, 409)

    def test_register_protocol_too_old(self):
        """Test 426 when client version is below server minimum."""
        old_min = config.MIN_PROTOCOL_VERSION
        config.MIN_PROTOCOL_VERSION = 99
        try:
            r = self.client.post("/api/v1/register",
                headers={"Content-Type": "application/json", "X-Protocol-Version": "1"},
                json={
                    "public_signing_key": self._b64(bytes(self.sys_signing_pub)),
                    "public_exchange_key": self._b64(bytes(self.sys_exchange_pub)),
                    "client_type": "system",
                    "protocol_version": 1,
                    "feature_set": [],
                })
            self.assertEqual(r.status_code, 426)
        finally:
            config.MIN_PROTOCOL_VERSION = old_min

    # ─── Auth ──────────────────────────────────────────────────

    def test_auth_challenge_response(self):
        user_id = self._register_system()
        token = self._authenticate(user_id, self.sys_signing_key)
        self.assertIsNotNone(token)

    def test_auth_bad_signature(self):
        user_id = self._register_system()

        # Get challenge
        r = self.client.post("/api/v1/auth/challenge",
            headers=self._headers(), json={"user_id": user_id})
        nonce = r.get_json()["nonce"]

        # Sign with wrong key
        wrong_key = nacl.signing.SigningKey.generate()
        sig = wrong_key.sign(nonce.encode("utf-8"), encoder=RawEncoder)
        signature_bytes = sig[:64]  # First 64 bytes are signature

        r = self.client.post("/api/v1/auth/token",
            headers=self._headers(),
            json={
                "user_id": user_id,
                "nonce": nonce,
                "signature": self._b64(signature_bytes),
            })
        self.assertEqual(r.status_code, 403)

    # ─── Volume Upload & Signature Verification ────────────────

    def test_volume_upload(self):
        user_id = self._register_system()
        token = self._authenticate(user_id, self.sys_signing_key)

        self._upload_volume(token, "meta", 1, b"encrypted_meta_data")
        self.assertEqual(True, True)  # No exception means success

    def test_volume_version_conflict(self):
        user_id = self._register_system()
        token = self._authenticate(user_id, self.sys_signing_key)

        self._upload_volume(token, "meta", 1, b"data_v1")

        # Try uploading same version again → 409
        r = self._upload_volume_raw(token, "meta", 1, b"data_v1_again")
        self.assertEqual(r.status_code, 409)

    def test_volume_list(self):
        user_id = self._register_system()
        token = self._authenticate(user_id, self.sys_signing_key)

        self._upload_volume(token, "meta", 1, b"meta_data")
        self._upload_volume(token, "members", 1, b"members_data")

        r = self.client.get("/api/v1/volumes", headers=self._headers(token))
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertEqual(len(data["volumes"]), 2)

    # ─── Friend cannot upload ──────────────────────────────────

    def test_friend_cannot_upload(self):
        friend_id = self._register_friend()
        token = self._authenticate(friend_id, self.friend_signing_key)

        r = self._upload_volume_raw(token, "meta", 1, b"data", signing_key=self.friend_signing_key)
        self.assertEqual(r.status_code, 403)

    # ─── Discovery ─────────────────────────────────────────────

    def test_discovery_cross_type(self):
        self._register_system("sys_discoverable")
        friend_id = self._register_friend("friend_searcher")
        friend_token = self._authenticate(friend_id, self.friend_signing_key)

        r = self.client.get("/api/v1/discover?handle=sys_dis",
                            headers=self._headers(friend_token))
        self.assertEqual(r.status_code, 200)
        results = r.get_json()["results"]
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["handle"], "sys_discoverable")
        self.assertEqual(results[0]["client_type"], "system")

    def test_discovery_same_type_hidden(self):
        """System users shouldn't see other system users."""
        self._register_system("sys_one")
        sys2_signing = nacl.signing.SigningKey.generate()
        sys2_exchange = nacl.public.PrivateKey.generate()
        r = self.client.post("/api/v1/register",
            headers=self._headers(),
            json={
                "public_signing_key": self._b64(bytes(sys2_signing.verify_key)),
                "public_exchange_key": self._b64(bytes(sys2_exchange.public_key)),
                "handle": "sys_two",
                "client_type": "system",
                "protocol_version": 1,
                "feature_set": [],
            })
        sys2_id = r.get_json()["user_id"]
        sys2_token = self._authenticate(sys2_id, sys2_signing)

        r = self.client.get("/api/v1/discover?handle=sys_one",
                            headers=self._headers(sys2_token))
        results = r.get_json()["results"]
        self.assertEqual(len(results), 0)

    # ─── Full Sharing Flow ─────────────────────────────────────

    def test_full_sharing_lifecycle(self):
        """
        End-to-end: register both → friend requests sharing →
        system accepts → system uploads → friend downloads → revoke.
        """
        # 1. Register both users
        sys_id = self._register_system("my_system")
        friend_id = self._register_friend("my_friend")

        sys_token = self._authenticate(sys_id, self.sys_signing_key)
        friend_token = self._authenticate(friend_id, self.friend_signing_key)

        # 2. Friend sends sharing request
        r = self.client.post("/api/v1/sharing/request",
            headers=self._headers(friend_token),
            json={"from_user_id": friend_id, "to_user_id": sys_id})
        self.assertEqual(r.status_code, 201)
        sharing = r.get_json()
        sharing_id = sharing["id"]
        self.assertEqual(sharing["status"], "pending")
        self.assertIsNotNone(sharing["friend_exchange_public_key"])

        # 3. System user sees pending request
        r = self.client.get("/api/v1/sharing/requests",
                            headers=self._headers(sys_token))
        self.assertEqual(r.status_code, 200)
        requests = r.get_json()["requests"]
        self.assertEqual(len(requests), 1)
        self.assertEqual(requests[0]["id"], sharing_id)
        self.assertIsNotNone(requests[0]["friend_exchange_public_key"])

        # 4. System user accepts with permissions
        r = self.client.post("/api/v1/sharing/respond",
            headers=self._headers(sys_token),
            json={
                "request_id": sharing_id,
                "accepted": True,
                "encrypted_vek_blob": self._b64(b"fake_wrapped_vek_for_test"),
                "permissions": {
                    "share_front_status": True,
                    "share_members": True,
                    "share_front_history": False,
                    "share_journal": False,
                    "share_mood_trends": False,
                    "share_polls": False,
                },
            })
        self.assertEqual(r.status_code, 200)

        # 5. System user uploads volumes
        self._upload_volume(sys_token, "meta", 1, b"encrypted_meta")
        self._upload_volume(sys_token, "members", 1, b"encrypted_members")
        self._upload_volume(sys_token, "fronts", 1, b"encrypted_fronts")
        self._upload_volume(sys_token, "journal", 1, b"encrypted_journal")

        # 6. Friend lists shared volumes (should see meta, members, fronts only)
        r = self.client.get(f"/api/v1/shared/{sys_id}/volumes",
                            headers=self._headers(friend_token))
        self.assertEqual(r.status_code, 200)
        vol_names = [v["volume_name"] for v in r.get_json()["volumes"]]
        self.assertIn("meta", vol_names)
        self.assertIn("members", vol_names)
        self.assertIn("fronts", vol_names)
        self.assertNotIn("journal", vol_names)  # Not shared

        # 7. Friend downloads a shared volume
        r = self.client.get(f"/api/v1/shared/{sys_id}/volumes/members",
                            headers=self._headers(friend_token))
        self.assertEqual(r.status_code, 200)
        data = r.get_json()
        self.assertIn("encrypted_payload", data)
        self.assertIn("encrypted_vek_blob", data)
        self.assertEqual(data["encrypted_vek_blob"],
                         self._b64(b"fake_wrapped_vek_for_test"))

        # 8. Friend tries to download journal (not shared) → 403
        r = self.client.get(f"/api/v1/shared/{sys_id}/volumes/journal",
                            headers=self._headers(friend_token))
        self.assertEqual(r.status_code, 403)

        # 9. Conditional GET (304 Not Modified)
        r = self.client.get(f"/api/v1/shared/{sys_id}/volumes/members",
                            headers={**self._headers(friend_token),
                                     "If-None-Match": "1"})
        self.assertEqual(r.status_code, 304)

        # 10. System user revokes
        r = self.client.delete(f"/api/v1/sharing/{sharing_id}",
                               headers=self._headers(sys_token))
        self.assertEqual(r.status_code, 204)

        # 11. Friend can no longer download
        r = self.client.get(f"/api/v1/shared/{sys_id}/volumes/members",
                            headers=self._headers(friend_token))
        self.assertEqual(r.status_code, 403)

    # ─── Directionality Enforcement ────────────────────────────

    def test_sharing_wrong_direction(self):
        """System → friend requests should be rejected."""
        sys_id = self._register_system("sys_dir")
        friend_id = self._register_friend("friend_dir")
        sys_token = self._authenticate(sys_id, self.sys_signing_key)

        r = self.client.post("/api/v1/sharing/request",
            headers=self._headers(sys_token),
            json={"from_user_id": sys_id, "to_user_id": friend_id})
        self.assertEqual(r.status_code, 400)

    # ─── Invite Codes ──────────────────────────────────────────

    def test_invite_code_flow(self):
        sys_id = self._register_system("sys_invite")
        friend_id = self._register_friend("friend_invite")

        sys_token = self._authenticate(sys_id, self.sys_signing_key)
        friend_token = self._authenticate(friend_id, self.friend_signing_key)

        # Generate invite
        r = self.client.post("/api/v1/sharing/invite",
                             headers=self._headers(sys_token))
        self.assertEqual(r.status_code, 201)
        code = r.get_json()["code"]
        self.assertEqual(len(code), config.INVITE_CODE_LENGTH)

        # Friend redeems
        r = self.client.post("/api/v1/sharing/redeem",
            headers=self._headers(friend_token),
            json={"code": code})
        self.assertEqual(r.status_code, 201)
        self.assertEqual(r.get_json()["status"], "pending")

        # Code cannot be reused
        # Need a new friend for this
        friend2_signing = nacl.signing.SigningKey.generate()
        friend2_exchange = nacl.public.PrivateKey.generate()
        r2 = self.client.post("/api/v1/register",
            headers=self._headers(),
            json={
                "public_signing_key": self._b64(bytes(friend2_signing.verify_key)),
                "public_exchange_key": self._b64(bytes(friend2_exchange.public_key)),
                "handle": "friend_invite2",
                "client_type": "friend",
                "protocol_version": 1,
                "feature_set": [],
            })
        f2_id = r2.get_json()["user_id"]
        f2_token = self._authenticate(f2_id, friend2_signing)

        r = self.client.post("/api/v1/sharing/redeem",
            headers=self._headers(f2_token),
            json={"code": code})
        self.assertEqual(r.status_code, 410)

    # ─── Permission Updates ────────────────────────────────────

    def test_update_permissions(self):
        sys_id = self._register_system("sys_perm")
        friend_id = self._register_friend("friend_perm")
        sys_token = self._authenticate(sys_id, self.sys_signing_key)
        friend_token = self._authenticate(friend_id, self.friend_signing_key)

        # Friend requests, system accepts with limited perms
        r = self.client.post("/api/v1/sharing/request",
            headers=self._headers(friend_token),
            json={"from_user_id": friend_id, "to_user_id": sys_id})
        sharing_id = r.get_json()["id"]

        self.client.post("/api/v1/sharing/respond",
            headers=self._headers(sys_token),
            json={
                "request_id": sharing_id,
                "accepted": True,
                "encrypted_vek_blob": self._b64(b"vek"),
                "permissions": {"share_front_status": True, "share_members": True},
            })

        # Update to also share journal
        r = self.client.patch(f"/api/v1/sharing/{sharing_id}/permissions",
            headers=self._headers(sys_token),
            json={"permissions": {
                "share_front_status": True,
                "share_members": True,
                "share_journal": True,
            }})
        self.assertEqual(r.status_code, 200)

    # ─── Account Deletion ──────────────────────────────────────

    def test_delete_account(self):
        sys_id = self._register_system("sys_delete")
        token = self._authenticate(sys_id, self.sys_signing_key)

        self._upload_volume(token, "meta", 1, b"data")

        r = self.client.delete("/api/v1/users/me", headers=self._headers(token))
        self.assertEqual(r.status_code, 204)

        # Should no longer be able to auth
        r = self.client.post("/api/v1/auth/challenge",
            headers=self._headers(), json={"user_id": sys_id})
        self.assertEqual(r.status_code, 404)

    # ─── Active Sharing List ───────────────────────────────────

    def test_list_active_sharings(self):
        sys_id = self._register_system("sys_active")
        friend_id = self._register_friend("friend_active")
        sys_token = self._authenticate(sys_id, self.sys_signing_key)
        friend_token = self._authenticate(friend_id, self.friend_signing_key)

        # Create and accept sharing
        r = self.client.post("/api/v1/sharing/request",
            headers=self._headers(friend_token),
            json={"from_user_id": friend_id, "to_user_id": sys_id})
        sharing_id = r.get_json()["id"]

        self.client.post("/api/v1/sharing/respond",
            headers=self._headers(sys_token),
            json={
                "request_id": sharing_id,
                "accepted": True,
                "encrypted_vek_blob": self._b64(b"vek"),
                "permissions": {"share_front_status": True},
            })

        # List active sharings
        r = self.client.get("/api/v1/sharing/requests?status=active",
                            headers=self._headers(sys_token))
        self.assertEqual(r.status_code, 200)
        active = r.get_json()["requests"]
        self.assertEqual(len(active), 1)
        self.assertEqual(active[0]["status"], "active")

    # ─── Helpers ───────────────────────────────────────────────

    def _register_system(self, handle=None) -> str:
        r = self.client.post("/api/v1/register",
            headers=self._headers(),
            json={
                "public_signing_key": self._b64(bytes(self.sys_signing_pub)),
                "public_exchange_key": self._b64(bytes(self.sys_exchange_pub)),
                "handle": handle,
                "client_type": "system",
                "protocol_version": 1,
                "feature_set": ["members:1", "fronts:1", "journal:1",
                                "chat:1", "polls:1", "analytics:1", "meta:1"],
            })
        return r.get_json()["user_id"]

    def _register_friend(self, handle=None) -> str:
        r = self.client.post("/api/v1/register",
            headers=self._headers(),
            json={
                "public_signing_key": self._b64(bytes(self.friend_signing_pub)),
                "public_exchange_key": self._b64(bytes(self.friend_exchange_pub)),
                "handle": handle,
                "client_type": "friend",
                "protocol_version": 1,
                "feature_set": ["members:1", "fronts:1", "journal:1",
                                "chat:1", "polls:1", "analytics:1", "meta:1"],
            })
        return r.get_json()["user_id"]

    def _authenticate(self, user_id: str, signing_key: nacl.signing.SigningKey) -> str:
        # Get challenge
        r = self.client.post("/api/v1/auth/challenge",
            headers=self._headers(), json={"user_id": user_id})
        nonce = r.get_json()["nonce"]

        # Sign the nonce bytes (matching the Dart client: utf8.encode(nonce))
        nonce_bytes = nonce.encode("utf-8")
        signed = signing_key.sign(nonce_bytes, encoder=RawEncoder)
        # nacl.signing.SigningKey.sign returns signature(64) + message
        signature_bytes = signed[:64]

        # Exchange for token
        r = self.client.post("/api/v1/auth/token",
            headers=self._headers(),
            json={
                "user_id": user_id,
                "nonce": nonce,
                "signature": self._b64(signature_bytes),
            })
        self.assertEqual(r.status_code, 200, f"Auth failed: {r.get_json()}")
        return r.get_json()["token"]

    def _upload_volume(self, token: str, volume_name: str, version: int,
                       payload: bytes, signing_key=None):
        r = self._upload_volume_raw(token, volume_name, version, payload, signing_key)
        self.assertEqual(r.status_code, 200, f"Upload failed: {r.get_json()}")

    def _upload_volume_raw(self, token: str, volume_name: str, version: int,
                           payload: bytes, signing_key=None):
        if signing_key is None:
            signing_key = self.sys_signing_key

        # Pad to 4KB boundary
        pad_size = ((len(payload) + 4095) // 4096) * 4096
        padded = payload + b'\x00' * (pad_size - len(payload))

        import time
        now = int(time.time())
        rounded = (now // 3600) * 3600

        header = {
            "volume_name": volume_name,
            "version": version,
            "modified_at": rounded,
            "size_bytes": len(padded),
            "event_tags": ["test"],
        }

        # Sign: header_json_bytes + payload_bytes
        # Must match the Dart client's JSON serialization
        header_json = json.dumps(header, separators=(",", ":"))
        sign_input = header_json.encode("utf-8") + padded

        signed = signing_key.sign(sign_input, encoder=RawEncoder)
        signature_bytes = signed[:64]

        return self.client.put(
            f"/api/v1/volumes/{volume_name}",
            headers=self._headers(token),
            json={
                "control_header": header,
                "encrypted_payload": self._b64(padded),
                "signature": self._b64(signature_bytes),
            })


class TestPaillierHomomorphic(unittest.TestCase):
    """Test Paillier homomorphic operations — server sums without decrypting."""

    def test_homomorphic_addition(self):
        from phe import paillier as phe_paillier
        from plurallog_relay.crypto import paillier_add_encrypted

        # Generate key pair (client-side operation)
        pub_key, priv_key = phe_paillier.generate_paillier_keypair(n_length=1024)

        # Encrypt some values (client-side)
        vals = [5, 12, 8, 3]
        ciphertexts = []
        for v in vals:
            enc = pub_key.encrypt(v)
            ct_data = json.dumps({
                "ciphertext": str(enc.ciphertext(be_secure=True)),
                "exponent": enc.exponent,
            })
            ciphertexts.append(base64.b64encode(ct_data.encode()).decode())

        # Server performs homomorphic sum (NO decryption)
        pk_json = json.dumps({"n": str(pub_key.n)})
        result_b64 = paillier_add_encrypted(pk_json, ciphertexts)
        self.assertIsNotNone(result_b64)

        # Client decrypts the result
        result_data = json.loads(base64.b64decode(result_b64))
        from phe import EncryptedNumber, PaillierPublicKey
        enc_sum = EncryptedNumber(
            pub_key,
            ciphertext=int(result_data["ciphertext"]),
            exponent=int(result_data["exponent"]),
        )
        decrypted_sum = priv_key.decrypt(enc_sum)
        self.assertEqual(decrypted_sum, sum(vals))  # 28

    def test_homomorphic_single_value(self):
        from phe import paillier as phe_paillier
        from plurallog_relay.crypto import paillier_add_encrypted

        pub_key, priv_key = phe_paillier.generate_paillier_keypair(n_length=1024)
        enc = pub_key.encrypt(42)
        ct = json.dumps({
            "ciphertext": str(enc.ciphertext(be_secure=True)),
            "exponent": enc.exponent,
        })
        ct_b64 = base64.b64encode(ct.encode()).decode()

        pk_json = json.dumps({"n": str(pub_key.n)})
        result_b64 = paillier_add_encrypted(pk_json, [ct_b64])
        self.assertIsNotNone(result_b64)

        result_data = json.loads(base64.b64decode(result_b64))
        from phe import EncryptedNumber
        enc_result = EncryptedNumber(
            pub_key,
            ciphertext=int(result_data["ciphertext"]),
            exponent=int(result_data["exponent"]),
        )
        self.assertEqual(priv_key.decrypt(enc_result), 42)


class TestPermissions(unittest.TestCase):
    """Test permission-to-volume mapping."""

    def test_default_always_includes_meta(self):
        from plurallog_relay.permissions import permissions_to_volumes
        vols = permissions_to_volumes({})
        self.assertIn("meta", vols)

    def test_front_status_enables_fronts(self):
        from plurallog_relay.permissions import permissions_to_volumes
        vols = permissions_to_volumes({"share_front_status": True})
        self.assertIn("fronts", vols)
        self.assertIn("meta", vols)

    def test_full_permissions(self):
        from plurallog_relay.permissions import permissions_to_volumes
        vols = permissions_to_volumes({
            "share_front_status": True,
            "share_members": True,
            "share_front_history": True,
            "share_journal": True,
            "share_mood_trends": True,
            "share_polls": True,
        })
        self.assertIn("meta", vols)
        self.assertIn("members", vols)
        self.assertIn("fronts", vols)
        self.assertIn("journal", vols)
        self.assertIn("analytics", vols)
        self.assertIn("polls", vols)


if __name__ == "__main__":
    unittest.main(verbosity=2)
