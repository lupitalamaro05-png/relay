"""
Cryptographic utilities for the relay server.

This module only handles:
  - Ed25519 signature VERIFICATION (not signing)
  - Secure random generation (for nonces, tokens, invite codes)
  - Paillier homomorphic addition on ciphertexts (no plaintext access)

The server never possesses any private keys except its own session token signing.
"""
import base64
import secrets
import hashlib
import json
import logging
from typing import Optional

import nacl.signing
import nacl.exceptions
from phe import paillier, EncryptedNumber, PaillierPublicKey

from . import config

logger = logging.getLogger(__name__)


# ─── Ed25519 Signature Verification ───────────────────────────

def verify_ed25519_signature(
    public_key_b64: str,
    message: bytes,
    signature_b64: str,
) -> bool:
    """
    Verify an Ed25519 signature.
    The server uses this to authenticate users and validate volume uploads.
    """
    try:
        pub_bytes = base64.b64decode(public_key_b64)
        sig_bytes = base64.b64decode(signature_b64)
        verify_key = nacl.signing.VerifyKey(pub_bytes)
        # nacl.signing expects signature + message concatenated for verify
        verify_key.verify(message, sig_bytes)
        return True
    except (nacl.exceptions.BadSignatureError, Exception) as e:
        logger.debug(f"Signature verification failed: {e}")
        return False


# ─── Secure Random ─────────────────────────────────────────────

def generate_nonce(n_bytes: int = config.CHALLENGE_NONCE_BYTES) -> str:
    """Generate a cryptographically random nonce, returned as base64."""
    return base64.b64encode(secrets.token_bytes(n_bytes)).decode()


def generate_session_token() -> str:
    """Generate a cryptographically random session token."""
    return secrets.token_urlsafe(48)


def generate_invite_code(length: int = config.INVITE_CODE_LENGTH) -> str:
    """Generate a random alphanumeric invite code."""
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # No ambiguous charsatcers
    return "".join(secrets.choice(alphabet) for _ in range(length))


# ─── Proof of Work ─────────────────────────────────────────────

def verify_proof_of_work(challenge: str, solution: str,
                         difficulty: int = config.POW_DIFFICULTY_BITS) -> bool:
    """
    Verify a Hashcash-style proof-of-work.
    If difficulty is 0 (dev mode), always passes.
    """
    if difficulty == 0:
        return True

    combined = f"{challenge}:{solution}".encode()
    hash_bytes = hashlib.sha256(combined).digest()

    # Check that the first `difficulty` bits are zero
    full_bytes = difficulty // 8
    remaining_bits = difficulty % 8

    for i in range(full_bytes):
        if hash_bytes[i] != 0:
            return False
    if remaining_bits > 0:
        mask = (0xFF >> remaining_bits) ^ 0xFF
        if hash_bytes[full_bytes] & mask != 0:
            return False
    return True


# ─── Paillier Homomorphic Operations ──────────────────────────

def paillier_add_encrypted(
    public_key_json: str,
    ciphertexts: list[str],
) -> Optional[str]:
    """
    Perform additive homomorphic summation on Paillier-encrypted counters.

    The server can compute Enc(a) + Enc(b) = Enc(a+b) without knowing a or b.
    This is used for analytics aggregation (e.g., sum daily switch counts into weekly).

    Args:
        public_key_json: JSON-serialized Paillier public key from the system user.
        ciphertexts: List of base64-encoded Paillier ciphertexts to sum.

    Returns:
        Base64-encoded encrypted sum, or None on error.

    SECURITY: The server learns NOTHING about the plaintext values.
    It only manipulates ciphertexts using the public key.
    """
    try:
        pk_data = json.loads(public_key_json)
        pub_key = PaillierPublicKey(n=int(pk_data["n"]))

        encrypted_numbers = []
        for ct_b64 in ciphertexts:
            ct_data = json.loads(base64.b64decode(ct_b64).decode())
            enc_num = EncryptedNumber(
                pub_key,
                ciphertext=int(ct_data["ciphertext"]),
                exponent=int(ct_data.get("exponent", 0)),
            )
            encrypted_numbers.append(enc_num)

        if not encrypted_numbers:
            return None

        # Homomorphic addition: sum all ciphertexts
        result = encrypted_numbers[0]
        for enc in encrypted_numbers[1:]:
            result = result + enc

        # Serialize the result
        result_data = {
            "ciphertext": str(result.ciphertext(be_secure=True)),
            "exponent": result.exponent,
        }
        return base64.b64encode(json.dumps(result_data).encode()).decode()

    except Exception as e:
        logger.error(f"Paillier homomorphic addition failed: {e}")
        return None


def paillier_add_list(
    public_key_json: str,
    counter_groups: dict[str, list[str]],
) -> dict[str, Optional[str]]:
    """
    Sum multiple named counter groups homomorphically.

    Args:
        public_key_json: Paillier public key.
        counter_groups: Dict mapping counter_name -> list of ciphertexts.

    Returns:
        Dict mapping counter_name -> encrypted sum (base64), or None if failed.
    """
    results = {}
    for name, ciphertexts in counter_groups.items():
        results[name] = paillier_add_encrypted(public_key_json, ciphertexts)
    return results
