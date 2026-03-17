"""Cryptographic utilities using Ed25519 for agent identity and audit-trail integrity."""

import base64
import hashlib
import json
from typing import Tuple

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
    PublicFormat,
)


def generate_keypair() -> Tuple[str, str]:
    """Generate an Ed25519 keypair for an agent.

    Returns:
        Tuple of (private_key_b64, public_key_b64) as base64-encoded raw bytes.
        The private key must be stored securely by the agent; the server never
        persists it.
    """
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()

    private_bytes = private_key.private_bytes(
        Encoding.Raw, PrivateFormat.Raw, NoEncryption()
    )
    public_bytes = public_key.public_bytes(Encoding.Raw, PublicFormat.Raw)

    return (
        base64.b64encode(private_bytes).decode("utf-8"),
        base64.b64encode(public_bytes).decode("utf-8"),
    )


def sign_data(private_key_b64: str, data: dict) -> str:
    """Sign a data dictionary with an Ed25519 private key.

    Args:
        private_key_b64: Base64-encoded raw private-key bytes.
        data: Dictionary to sign (JSON-serialised with sorted keys).

    Returns:
        Base64-encoded Ed25519 signature.
    """
    private_bytes = base64.b64decode(private_key_b64)
    private_key = Ed25519PrivateKey.from_private_bytes(private_bytes)
    message = json.dumps(data, sort_keys=True, default=str).encode("utf-8")
    return base64.b64encode(private_key.sign(message)).decode("utf-8")


def verify_signature(public_key_b64: str, data: dict, signature_b64: str) -> bool:
    """Verify an Ed25519 signature over a data dictionary.

    Args:
        public_key_b64: Base64-encoded raw public-key bytes.
        data: Dictionary that was originally signed.
        signature_b64: Base64-encoded signature to verify.

    Returns:
        True if the signature is valid, False otherwise.
    """
    try:
        public_bytes = base64.b64decode(public_key_b64)
        public_key = Ed25519PublicKey.from_public_bytes(public_bytes)
        message = json.dumps(data, sort_keys=True, default=str).encode("utf-8")
        signature = base64.b64decode(signature_b64)
        public_key.verify(signature, message)
        return True
    except (InvalidSignature, Exception):
        return False


def compute_hash(data: dict) -> str:
    """Compute a SHA-256 hash of a data dictionary.

    Args:
        data: Dictionary to hash (JSON-serialised with sorted keys).

    Returns:
        Hex-encoded SHA-256 hash string.
    """
    message = json.dumps(data, sort_keys=True, default=str).encode("utf-8")
    return hashlib.sha256(message).hexdigest()


def compute_chain_hash(entry_core: dict, previous_hash: str) -> str:
    """Compute an audit-chain hash that links this entry to the previous one.

    Args:
        entry_core: The audit entry fields (excluding entry_hash and signature).
        previous_hash: Hash of the immediately preceding audit entry.

    Returns:
        Hex-encoded SHA-256 hash string.
    """
    return compute_hash({"entry": entry_core, "previous_hash": previous_hash})
