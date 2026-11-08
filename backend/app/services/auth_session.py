"""Local password/TOTP authentication with opaque, hash-only session storage.

Missing policy retains the reviewed legacy deployment until a local bootstrap
finishes. A present but invalid policy never silently falls back to legacy.
"""

import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import struct
import unicodedata
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from pathlib import Path
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidKey, InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from fastapi import HTTPException, Request
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError, SQLAlchemyError

from app.database.session import SessionLocal
from app.models.auth import AuthLoginLimit, AuthSession, AuthUser

COOKIE_NAME = "__Host-ccvm_session"
IDLE_TIMEOUT = timedelta(minutes=30)
ABSOLUTE_TIMEOUT = timedelta(hours=8)
LOGIN_WINDOW = timedelta(minutes=15)
LOGIN_BACKOFF = timedelta(minutes=5)
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
AUTH_ERROR = "Anmeldung fehlgeschlagen. Zugangsdaten und Authenticator-Code prüfen."
POLICY_OWNER_UID = 0


@dataclass(frozen=True)
class AuthPolicy:
    origin: str
    version: int = 1
    mode: str = "local"


@dataclass(frozen=True)
class AuthPrincipal:
    user_id: int
    username: str
    session_hash: str
    csrf_token: str
    expires_at: datetime


def now():
    return datetime.now(UTC)


def utc(value):
    # SQLite's test adapter drops offsets; PostgreSQL retains timezone-aware UTC.
    return value.replace(tzinfo=UTC) if value.tzinfo is None else value.astimezone(UTC)


def policy_path():
    return Path(
        os.environ.get(
            "CCVM_AUTH_POLICY_FILE",
            str(Path(__file__).resolve().parents[2] / ".ccvm-auth" / "auth-policy.json"),
        )
    )


def policy_directory(*, create=False):
    parent = policy_path().parent
    if create:
        parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if parent.resolve() != parent.absolute():
        raise ValueError("Authentication policy directory must not use symlinks")
    descriptor = os.open(parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        metadata = os.fstat(descriptor)
        if metadata.st_uid != POLICY_OWNER_UID or stat.S_IMODE(metadata.st_mode) & 0o022:
            raise ValueError(
                "Authentication policy directory must be root-owned and not writable by others"
            )
    finally:
        os.close(descriptor)
    return parent


def validate_origin(origin):
    if not isinstance(origin, str) or len(origin) > 255:
        raise ValueError("A single HTTPS origin is required")
    parsed = urlsplit(origin)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path
        or parsed.query
        or parsed.fragment
        or origin != f"https://{parsed.netloc}"
        or any(character.isspace() for character in origin)
    ):
        raise ValueError("A single HTTPS origin without a path is required")
    # Parsing the port also rejects malformed port specifications.
    _ = parsed.port
    return origin


def auth_policy():
    path = policy_path()
    try:
        policy_directory()
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except FileNotFoundError:
        return None
    except (OSError, ValueError) as error:
        raise HTTPException(503, "Anmeldung ist nicht korrekt konfiguriert") from error
    try:
        with os.fdopen(descriptor, "rb") as stream:
            metadata = os.fstat(stream.fileno())
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != POLICY_OWNER_UID
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or metadata.st_size > 4096
            ):
                raise ValueError("Private root-owned authentication policy required")
            payload = json.loads(stream.read(4097))
        if (
            not isinstance(payload, dict)
            or set(payload) != {"version", "mode", "origin"}
            or type(payload["version"]) is not int
            or payload["version"] != 1
            or payload["mode"] != "local"
        ):
            raise ValueError("Unsupported authentication policy")
        return AuthPolicy(origin=validate_origin(payload["origin"]))
    except (ValueError, TypeError, OSError) as error:
        raise HTTPException(503, "Anmeldung ist nicht korrekt konfiguriert") from error


def auth_enabled():
    return auth_policy() is not None


def require_local_https(request):
    policy = auth_policy()
    if policy is None:
        raise HTTPException(503, "Lokale Anmeldung ist noch nicht eingerichtet")
    if request.url.scheme != "https":
        raise HTTPException(403, "Anmeldung erfordert HTTPS")
    return policy


def require_same_origin(request: Request):
    policy = require_local_https(request)
    if (
        request.headers.get("origin") != policy.origin
        or request.headers.get("x-ccvm-request") != "1"
    ):
        raise HTTPException(403, "Anfrage stammt nicht vom konfigurierten CCVM-Ursprung")
    return policy


def auth_key(purpose=b"totp"):
    # Import lazily: audit_vault delegates to require_session in local mode.
    from app.services.audit_vault import vault_key

    try:
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"ccvm-local-auth-v1/" + purpose,
        ).derive(vault_key())
    except ValueError as error:
        raise HTTPException(503, "Anmeldung ist nicht korrekt konfiguriert") from error


def digest(value):
    return hashlib.sha256(value.encode("ascii")).hexdigest()


def normalize_username(value):
    if not isinstance(value, str):
        raise ValueError("Benutzername ist ungültig")
    value = value.strip().lower()
    if not re.fullmatch(r"[a-z0-9][a-z0-9._@-]{0,127}", value):
        raise ValueError("Benutzername: 1–128 Zeichen, Buchstaben, Zahlen, . _ @ oder -")
    return value


def password_bytes(password):
    return unicodedata.normalize("NFC", password).encode("utf-8")


def validate_password(password, username):
    if not isinstance(password, str) or not 15 <= len(password) <= 128:
        raise ValueError("Passwort muss 15–128 Zeichen lang sein")
    blocked = {
        "passwordpassword",
        "passwordpassword1",
        "123456789012345",
        "1234567890123456",
        "qwertyuiopasdfgh",
        "cloudcollabcloudcollab",
        "cloudcollab12345",
        username,
        username * 2,
        username * 3,
    }
    if password.casefold().strip() in blocked:
        raise ValueError("Dieses leicht erratbare Passwort ist nicht zulässig")
    return password


def hash_password(password):
    return Argon2id(
        salt=secrets.token_bytes(16), length=32, iterations=2, lanes=1, memory_cost=19456
    ).derive_phc_encoded(password_bytes(password))


@lru_cache(maxsize=1)
def dummy_password_hash():
    return hash_password(secrets.token_urlsafe(32))


def verify_password(encoded, password):
    try:
        Argon2id.verify_phc_encoded(password_bytes(password), encoded)
        return True
    except (InvalidKey, ValueError):
        return False


def generate_totp_secret():
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii")


def totp_code(secret, step=None):
    step = int(now().timestamp()) // 30 if step is None else step
    key = base64.b32decode(secret, casefold=False)
    mac = hmac.digest(key, struct.pack(">Q", step), "sha1")
    offset = mac[-1] & 0x0F
    number = struct.unpack(">I", mac[offset : offset + 4])[0] & 0x7FFFFFFF
    return f"{number % 1000000:06d}"


def verify_totp(secret, code, last_step=-1):
    if not isinstance(code, str) or not re.fullmatch(r"[0-9]{6}", code):
        return None
    current = int(now().timestamp()) // 30
    matched = None
    for step in (current - 1, current, current + 1):
        equal = hmac.compare_digest(totp_code(secret, step), code)
        if equal and step > last_step:
            matched = step
    return matched


def encrypt_totp(username, secret):
    nonce = secrets.token_bytes(12)
    return nonce + AESGCM(auth_key()).encrypt(
        nonce, secret.encode("ascii"), b"ccvm-totp-v1\0" + username.encode("ascii")
    )


def decrypt_totp(user):
    encrypted = user.totp_ciphertext
    try:
        return (
            AESGCM(auth_key())
            .decrypt(
                encrypted[:12], encrypted[12:], b"ccvm-totp-v1\0" + user.username.encode("ascii")
            )
            .decode("ascii")
        )
    except (InvalidTag, ValueError, UnicodeError) as error:
        raise HTTPException(503, "Anmeldung ist nicht korrekt konfiguriert") from error


def create_operator(db, username, password, totp_secret, confirmed_step=-1):
    username = normalize_username(username)
    validate_password(password, username)
    # Validate the supplied enrollment secret before storing its ciphertext.
    if len(base64.b32decode(totp_secret, casefold=False)) != 20:
        raise ValueError("Authenticator-Schlüssel ist ungültig")
    user = AuthUser(
        username=username,
        password_hash=hash_password(password),
        totp_ciphertext=encrypt_totp(username, totp_secret),
        totp_last_step=confirmed_step,
        enabled=True,
        updated_at=now(),
    )
    db.add(user)
    db.flush()
    return user


def csrf_token(raw_token):
    return (
        base64.urlsafe_b64encode(
            hmac.digest(auth_key(b"csrf"), b"ccvm-csrf-v1\0" + raw_token.encode("ascii"), "sha256")
        )
        .rstrip(b"=")
        .decode("ascii")
    )


def principal_payload(principal):
    return {
        "mode": "local",
        "authenticated": True,
        "user": {"username": principal.username},
        "csrf_token": principal.csrf_token,
        "expires_at": principal.expires_at.isoformat(),
    }


def _limit_row(db, key_hash, moment):
    row = db.scalar(
        select(AuthLoginLimit).where(AuthLoginLimit.key_hash == key_hash).with_for_update()
    )
    if row is None:
        try:
            with db.begin_nested():
                db.add(AuthLoginLimit(key_hash=key_hash, failures=0, window_started_at=moment))
                db.flush()
        except IntegrityError:
            # A concurrent process inserted the same durable limiter first.
            pass
        row = db.scalar(
            select(AuthLoginLimit).where(AuthLoginLimit.key_hash == key_hash).with_for_update()
        )
    if moment - utc(row.window_started_at) >= LOGIN_WINDOW:
        row.window_started_at = moment
        row.failures = 0
        row.blocked_until = None
    return row


def authenticate(request, username, password, code):
    require_same_origin(request)
    moment = now()
    try:
        normalized = normalize_username(username)
    except ValueError:
        normalized = "invalid:" + hashlib.sha256(username.encode("utf-8")).hexdigest()
    client_ip = request.client.host if request.client else "unknown"
    account_key, ip_key = digest("account\0" + normalized), digest("ip\0" + client_ip)
    keys = {account_key: 5, ip_key: 20}
    try:
        with SessionLocal() as db:
            # Every login locks its IP then its single account. Check the IP
            # before creating account rows, bounding growth during a flood.
            # The user lock serializes successful OTP consumption in PG.
            ip_row = _limit_row(db, ip_key, moment)
            if ip_row.blocked_until and utc(ip_row.blocked_until) > moment:
                db.commit()
                raise HTTPException(429, AUTH_ERROR, headers={"Retry-After": "300"})
            rows = [(ip_key, ip_row), (account_key, _limit_row(db, account_key, moment))]
            if any(row.blocked_until and utc(row.blocked_until) > moment for _, row in rows):
                db.commit()
                raise HTTPException(429, AUTH_ERROR, headers={"Retry-After": "300"})
            user = db.scalar(
                select(AuthUser).where(AuthUser.username == normalized).with_for_update()
            )
            valid = verify_password(user.password_hash if user else dummy_password_hash(), password)
            step = None
            if user is not None and user.enabled and valid:
                step = verify_totp(decrypt_totp(user), code, user.totp_last_step)
            if step is None:
                for key, row in rows:
                    row.failures += 1
                    if row.failures >= keys[key]:
                        row.blocked_until = moment + LOGIN_BACKOFF
                db.commit()
                raise HTTPException(401, AUTH_ERROR)
            user.totp_last_step = step
            for key, row in rows:
                if key == account_key:
                    row.failures = 0
                    row.blocked_until = None
            raw_token = secrets.token_urlsafe(32)
            csrf = csrf_token(raw_token)
            expires = moment + ABSOLUTE_TIMEOUT
            record = AuthSession(
                token_hash=digest(raw_token),
                user_id=user.id,
                csrf_hash=digest(csrf),
                created_at=moment,
                last_seen_at=moment,
                expires_at=expires,
            )
            db.add(record)
            principal = AuthPrincipal(user.id, user.username, record.token_hash, csrf, expires)
            db.commit()
            return raw_token, principal
    except SQLAlchemyError as error:
        raise HTTPException(503, "Anmeldung ist vorübergehend nicht verfügbar") from error


def session_principal(request, *, required=True):
    require_local_https(request)
    if request.method not in SAFE_METHODS:
        require_same_origin(request)
    cached = getattr(request.state, "ccvm_auth", None)
    if cached is not None:
        return cached
    raw_token = request.cookies.get(COOKIE_NAME, "")
    if not re.fullmatch(r"[A-Za-z0-9_-]{43}", raw_token):
        if required:
            raise HTTPException(401, "Anmeldung erforderlich")
        return None
    moment = now()
    try:
        with SessionLocal() as db:
            record = db.scalar(
                select(AuthSession)
                .where(AuthSession.token_hash == digest(raw_token))
                .with_for_update()
            )
            user = db.get(AuthUser, record.user_id) if record else None
            if (
                record is None
                or record.revoked_at is not None
                or user is None
                or not user.enabled
                or utc(record.expires_at) <= moment
                or utc(record.last_seen_at) + IDLE_TIMEOUT <= moment
            ):
                if record is not None and record.revoked_at is None:
                    record.revoked_at = moment
                    db.commit()
                if required:
                    raise HTTPException(401, "Anmeldung erforderlich")
                return None
            csrf = csrf_token(raw_token)
            if not hmac.compare_digest(digest(csrf), record.csrf_hash):
                raise HTTPException(401, "Anmeldung erforderlich")
            if request.method not in SAFE_METHODS:
                supplied = request.headers.get("x-csrf-token", "")
                if not hmac.compare_digest(supplied.encode("utf-8"), csrf.encode("ascii")):
                    raise HTTPException(403, "Sicherheitsprüfung der Anfrage fehlgeschlagen")
            record.last_seen_at = moment
            principal = AuthPrincipal(
                user.id, user.username, record.token_hash, csrf, utc(record.expires_at)
            )
            db.commit()
            request.state.ccvm_auth = principal
            return principal
    except SQLAlchemyError as error:
        raise HTTPException(503, "Anmeldung ist vorübergehend nicht verfügbar") from error


def require_session(request: Request):
    return session_principal(request, required=True)


def revoke_session(principal):
    try:
        with SessionLocal() as db:
            record = db.get(AuthSession, principal.session_hash)
            if record is not None:
                record.revoked_at = now()
                db.commit()
    except SQLAlchemyError as error:
        raise HTTPException(503, "Abmelden ist vorübergehend nicht verfügbar") from error
