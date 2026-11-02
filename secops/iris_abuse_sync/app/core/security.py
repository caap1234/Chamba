import base64
import hashlib
import hmac
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, InvalidHashError
from cryptography.fernet import Fernet, InvalidToken

from app.core.config import settings

_ph = PasswordHasher(
    time_cost=2,
    memory_cost=65536,
    parallelism=2,
    hash_len=32,
    salt_len=16,
)


def _derive_fernet_key(master_seed: str) -> bytes:
    digest = hashlib.sha256(master_seed.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(digest)


_fernet = Fernet(_derive_fernet_key(settings.APP_MASTER_KEY))


def hash_password(plain_password: str) -> str:
    """Genera hash seguro Argon2id de una contraseña."""
    return _ph.hash(plain_password)


def verify_password(plain_password: str, password_hash: str) -> bool:
    """Verifica contraseña contra hash Argon2id."""
    if not plain_password or not password_hash:
        return False
    try:
        return _ph.verify(password_hash, plain_password)
    except (VerifyMismatchError, InvalidHashError, Exception):
        return False


def generate_session_token() -> tuple[str, str]:
    """Devuelve (raw_token, token_sha256_hash)."""
    raw = secrets.token_urlsafe(40)
    token_hash = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    return raw, token_hash


def hash_session_token(raw_token: str) -> str:
    return hashlib.sha256((raw_token or "").encode("utf-8")).hexdigest()


def generate_csrf_token(session_token_hash: str) -> str:
    return hmac.new(
        settings.APP_SECRET_KEY.encode("utf-8"),
        session_token_hash.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def verify_csrf_token(session_token_hash: str, csrf_token: str) -> bool:
    if not session_token_hash or not csrf_token:
        return False
    expected = generate_csrf_token(session_token_hash)
    return hmac.compare_digest(expected, csrf_token)


def encrypt_secret(plaintext: str) -> tuple[str, str]:
    """Cifra un secreto (API key, contraseña IMAP, token) y devuelve (ciphertext, key_hint)."""
    if not plaintext:
        return "", ""
    clean = plaintext.strip()
    ciphertext = _fernet.encrypt(clean.encode("utf-8")).decode("utf-8")
    if len(clean) <= 6:
        hint = "••••••"
    else:
        hint = f"{clean[:3]}••••••••{clean[-3:]}"
    return ciphertext, hint


def decrypt_secret(ciphertext: str) -> Optional[str]:
    """Descifra un secreto almacenado en encrypted_secrets."""
    if not ciphertext:
        return None
    try:
        return _fernet.decrypt(ciphertext.encode("utf-8")).decode("utf-8")
    except (InvalidToken, Exception):
        return None


def utcnow() -> datetime:
    return datetime.now(timezone.utc)

