from __future__ import annotations

import base64
import hashlib
import hmac
import os
import secrets
import struct
import time
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from pathlib import Path
from typing import Any

from argon2 import PasswordHasher
from cryptography.fernet import Fernet, InvalidToken
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


def new_totp_secret() -> str:
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def new_recovery_code() -> str:
    alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
    left = "".join(secrets.choice(alphabet) for _ in range(5))
    right = "".join(secrets.choice(alphabet) for _ in range(5))
    return f"{left}-{right}"


def normalize_recovery_code(code: str) -> str:
    return "".join(character for character in code.upper() if character.isalnum())


def _secret_fernet() -> Fernet:
    key = base64.urlsafe_b64encode(hashlib.sha256(settings.secret_key.encode("utf-8")).digest())
    return Fernet(key)


def encrypt_secret(secret: str) -> str:
    return _secret_fernet().encrypt(secret.encode("utf-8")).decode("ascii")


def decrypt_secret(encrypted: str) -> str:
    try:
        return _secret_fernet().decrypt(encrypted.encode("ascii")).decode("utf-8")
    except InvalidToken as exc:
        raise ValueError("Invalid encrypted secret") from exc


def encrypt_mfa_secret(secret: str) -> str:
    return encrypt_secret(secret)


def decrypt_mfa_secret(encrypted: str) -> str:
    try:
        return decrypt_secret(encrypted)
    except ValueError as exc:
        raise ValueError("Invalid MFA secret") from exc


def _totp_key(secret: str) -> bytes:
    normalized = secret.replace(" ", "").upper()
    padded = normalized + ("=" * ((8 - len(normalized) % 8) % 8))
    return base64.b32decode(padded, casefold=True)


def hotp_code(secret: str, counter: int, digits: int = 6) -> str:
    digest = hmac.new(_totp_key(secret), struct.pack(">Q", counter), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset : offset + 4])[0] & 0x7FFFFFFF
    return str(value % (10**digits)).zfill(digits)


def totp_code(secret: str, *, at_time: int | None = None, period: int = 30, digits: int = 6) -> str:
    timestamp = int(time.time()) if at_time is None else at_time
    return hotp_code(secret, timestamp // period, digits=digits)


def verify_totp_code(secret: str, code: str, *, window: int = 1, period: int = 30, digits: int = 6) -> bool:
    sanitized = "".join(character for character in code if character.isdigit())
    if len(sanitized) != digits:
        return False
    counter = int(time.time()) // period
    return any(
        secrets.compare_digest(hotp_code(secret, counter + offset, digits=digits), sanitized)
        for offset in range(-window, window + 1)
    )


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


def _normalise_pem(value: str) -> str:
    return value.replace("\\n", "\n")


def _private_key_to_pem(private_key: rsa.RSAPrivateKey) -> str:
    return private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode("ascii")


def _public_key_to_pem(private_key: rsa.RSAPrivateKey) -> str:
    return private_key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("ascii")


def _derive_public_pem(private_pem: str) -> str:
    private_key = serialization.load_pem_private_key(private_pem.encode("utf-8"), password=None)
    if not isinstance(private_key, rsa.RSAPrivateKey):
        raise RuntimeError("GateKeeper JWT private key must be an RSA private key")
    return _public_key_to_pem(private_key)


def _read_or_create_keypair(private_path: Path, public_path: Path) -> tuple[str, str]:
    if private_path.exists():
        private_pem = private_path.read_text(encoding="utf-8")
        public_pem = (
            public_path.read_text(encoding="utf-8")
            if public_path.exists()
            else _derive_public_pem(private_pem)
        )
        if not public_path.exists():
            _write_key_file(public_path, public_pem, 0o644)
        return private_pem, public_pem

    if public_path.exists():
        raise RuntimeError("GateKeeper JWT key directory contains a public key without a private key")

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = _private_key_to_pem(private_key)
    public_pem = _public_key_to_pem(private_key)
    private_path.parent.mkdir(parents=True, exist_ok=True)
    if not _write_key_file(private_path, private_pem, 0o600):
        return _read_or_create_keypair(private_path, public_path)
    _write_key_file(public_path, public_pem, 0o644)
    return private_pem, public_pem


def _write_key_file(path: Path, content: str, mode: int) -> bool:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    try:
        fd = os.open(path, flags, mode)
    except FileExistsError:
        return False
    with os.fdopen(fd, "w", encoding="utf-8") as file:
        file.write(content)
    return True


@lru_cache(maxsize=1)
def _keypair_pem() -> tuple[str, str]:
    if settings.jwt_private_key_pem:
        private_pem = _normalise_pem(settings.jwt_private_key_pem)
        public_pem = (
            _normalise_pem(settings.jwt_public_key_pem)
            if settings.jwt_public_key_pem
            else _derive_public_pem(private_pem)
        )
        return private_pem, public_pem

    if settings.jwt_public_key_pem:
        raise RuntimeError("GateKeeper JWT_PUBLIC_KEY_PEM requires JWT_PRIVATE_KEY_PEM")

    if settings.jwt_key_dir:
        key_dir = Path(settings.jwt_key_dir)
        return _read_or_create_keypair(key_dir / "jwt_private.pem", key_dir / "jwt_public.pem")

    return _private_key_to_pem(_ephemeral_key), _public_key_to_pem(_ephemeral_key)


def _private_key_pem() -> str:
    return _keypair_pem()[0]


def _public_key_pem() -> str:
    return _keypair_pem()[1]


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
