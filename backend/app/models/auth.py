"""Local operators and revocable server-side sessions; no plaintext credentials."""

from sqlalchemy import BigInteger, Boolean, DateTime, ForeignKey, Integer, LargeBinary, String
from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy.sql import func

from app.database.session import Base


class AuthUser(Base):
    __tablename__ = "auth_users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    username: Mapped[str] = mapped_column(String(128), unique=True)
    password_hash: Mapped[str] = mapped_column(String(512))
    totp_ciphertext: Mapped[bytes] = mapped_column(LargeBinary)
    totp_last_step: Mapped[int] = mapped_column(BigInteger, default=-1, server_default="-1")
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, server_default="true")
    created_at = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())
    updated_at = mapped_column(DateTime(timezone=True), nullable=False, server_default=func.now())


class AuthSession(Base):
    __tablename__ = "auth_sessions"

    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[int] = mapped_column(ForeignKey("auth_users.id"), index=True)
    csrf_hash: Mapped[str] = mapped_column(String(64))
    created_at = mapped_column(DateTime(timezone=True), nullable=False)
    last_seen_at = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at = mapped_column(DateTime(timezone=True))


class AuthLoginLimit(Base):
    __tablename__ = "auth_login_limits"

    key_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    failures: Mapped[int] = mapped_column(Integer, default=0, server_default="0")
    window_started_at = mapped_column(DateTime(timezone=True), nullable=False)
    blocked_until = mapped_column(DateTime(timezone=True))
