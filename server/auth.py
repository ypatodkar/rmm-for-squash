from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import load_der_public_key

ENROLLMENT_TOKEN_TTL_SECONDS = 3600


def hash_token(token: str) -> str:
    """Tokens are stored hashed; a database leak must not yield usable tokens."""
    return hashlib.sha256(token.encode()).hexdigest()


def new_enrollment_token() -> str:
    return "enr_" + secrets.token_urlsafe(32)


def new_operator_key() -> str:
    return "op_" + secrets.token_urlsafe(32)


def load_operator_keys() -> dict[str, str]:
    """Maps API key -> operator name. Configured via SQUASH_OPERATOR_KEYS as
    name:key pairs, comma separated."""
    raw = os.environ.get("SQUASH_OPERATOR_KEYS", "").strip()
    keys: dict[str, str] = {}
    for pair in filter(None, (p.strip() for p in raw.split(","))):
        name, _, key = pair.partition(":")
        if name and key:
            keys[key] = name
    return keys


def match_operator(presented: str | None, keys: dict[str, str]) -> str | None:
    """Constant-time comparison against every configured key."""
    if not presented:
        return None
    for key, name in keys.items():
        if hmac.compare_digest(presented, key):
            return name
    return None


def new_challenge() -> str:
    return base64.b64encode(os.urandom(32)).decode()


def verify_device_signature(public_key_b64: str, challenge_b64: str, signature_b64: str) -> bool:
    """Agent signs the server-issued challenge with its enrolment private key.
    Key is SubjectPublicKeyInfo DER (P-256); signature is DER ECDSA/SHA-256."""
    try:
        public_key = load_der_public_key(base64.b64decode(public_key_b64))
        if not isinstance(public_key, ec.EllipticCurvePublicKey):
            return False
        public_key.verify(
            base64.b64decode(signature_b64),
            base64.b64decode(challenge_b64),
            ec.ECDSA(hashes.SHA256()),
        )
        return True
    except (InvalidSignature, ValueError, TypeError):
        return False
