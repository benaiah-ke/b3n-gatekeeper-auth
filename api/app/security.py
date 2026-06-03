from __future__ import annotations

import base64
import hashlib
import secrets
from datetime import UTC, datetime, timedelta
from typing import Any

from argon2 import PasswordHasher
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jose import JWTError, jwt

from app.config import settings

password_hasher = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=2)

_ephemeral_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)


def now_utc() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


def utc_after(**kwargs: Any) -> datetime:
    return now_utc() + timedelta(**kwargs)


def hash_password(password: str) -> str:
    return password_hasher.hash(password)


def verify_password(password: str, password_hash: str | None) -> bool:
    if not password_hash:
        return False
    try:
        return password_hasher.verify(password_hash, password)
    except Exception:
        return False


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def token_hint(token: str) -> str:
    return token[-8:]


def new_opaque_token(prefix: str = "gk") -> str:
    return f"{prefix}_{secrets.token_urlsafe(32)}"


def new_code(length: int = 8) -> str:
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def b64url_digest(value: bytes) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(value).digest()).rstrip(b"=").decode("ascii")


def verify_pkce(verifier: str, challenge: str, method: str) -> bool:
    if method.upper() == "S256":
        expected = b64url_digest(verifier.encode("ascii"))
    elif method.lower() == "plain":
        expected = verifier
    else:
        return False
    return secrets.compare_digest(expected, challenge)


def _private_key_pem() -> str:
    if settings.jwt_private_key_pem:
        return settings.jwt_private_key_pem.replace("\\n", "\n")
    return _ephemeral_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("ascii")


def _public_key_pem() -> str:
    if settings.jwt_public_key_pem:
        return settings.jwt_public_key_pem.replace("\\n", "\n")
    return _ephemeral_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")


def public_jwk() -> dict[str, str]:
    public_key = serialization.load_pem_public_key(_public_key_pem().encode("utf-8"))
    numbers = public_key.public_numbers()  # type: ignore[attr-defined]
    n = base64.urlsafe_b64encode(
        numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, "big")
    ).rstrip(b"=").decode("ascii")
    e = base64.urlsafe_b64encode(
        numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, "big")
    ).rstrip(b"=").decode("ascii")
    return {
        "kty": "RSA",
        "use": "sig",
        "kid": settings.jwt_key_id,
        "alg": "RS256",
        "n": n,
        "e": e,
    }


def create_access_token(
    *,
    subject: str,
    audience: str | list[str],
    scopes: list[str],
    token_type: str,
    client_id: str | None = None,
    org_id: str | None = None,
    workspace_id: str | None = None,
    project_id: str | None = None,
    extra: dict[str, Any] | None = None,
) -> str:
    jwt_now = datetime.now(UTC)
    payload: dict[str, Any] = {
        "iss": settings.issuer,
        "sub": subject,
        "aud": audience,
        "azp": client_id,
        "scope": " ".join(sorted(set(scopes))),
        "token_type": token_type,
        "org_id": org_id,
        "workspace_id": workspace_id,
        "project_id": project_id,
        "jti": secrets.token_urlsafe(16),
        "iat": int(jwt_now.timestamp()),
        "exp": int((jwt_now + timedelta(seconds=settings.access_token_ttl_seconds)).timestamp()),
    }
    if extra:
        payload.update(extra)
    return jwt.encode(
        payload,
        _private_key_pem(),
        algorithm="RS256",
        headers={"kid": settings.jwt_key_id},
    )


def decode_access_token(token: str, audience: str | None = None) -> dict[str, Any]:
    kwargs: dict[str, Any] = {
        "issuer": settings.issuer,
        "algorithms": ["RS256"],
        "options": {"verify_aud": bool(audience)},
    }
    if audience:
        kwargs["audience"] = audience
    try:
        return jwt.decode(token, _public_key_pem(), **kwargs)
    except JWTError as exc:
        raise ValueError("Invalid access token") from exc
