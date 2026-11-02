from datetime import datetime, timezone
from sqlalchemy import Boolean, Column, DateTime, ForeignKey, Integer, JSON, String, Text
from sqlalchemy.orm import relationship
from app.core.database import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(64), unique=True, nullable=False, index=True)
    email = Column(String(160), unique=True, nullable=False, index=True)
    full_name = Column(String(160), nullable=False)
    password_hash = Column(String(256), nullable=False)
    # Roles: admin, supervisor, analyst, readonly
    role = Column(String(32), nullable=False, default="analyst", index=True)
    # Organizaciones permitidas: ["NBX", "HP"]
    allowed_orgs = Column(JSON, nullable=False, default=lambda: ["NBX", "HP"])
    iris_user_id = Column(Integer, nullable=True, default=2)
    is_active = Column(Boolean, nullable=False, default=True)
    last_login_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow, onupdate=_utcnow)

    sessions = relationship("UserSession", back_populates="user", cascade="all, delete-orphan")


class UserSession(Base):
    __tablename__ = "user_sessions"

    id = Column(Integer, primary_key=True, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    token_hash = Column(String(128), unique=True, nullable=False, index=True)
    csrf_token = Column(String(128), nullable=False)
    ip_address = Column(String(64), nullable=True)
    user_agent = Column(String(512), nullable=True)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    revoked_at = Column(DateTime(timezone=True), nullable=True)
    created_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)

    user = relationship("User", back_populates="sessions")


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id = Column(Integer, primary_key=True, index=True)
    timestamp = Column(DateTime(timezone=True), nullable=False, default=_utcnow, index=True)
    user_id = Column(Integer, nullable=True, index=True)
    username = Column(String(64), nullable=False, default="system")
    action = Column(String(96), nullable=False, index=True)
    module = Column(String(64), nullable=False, index=True)
    organization = Column(String(16), nullable=True, index=True)
    iris_alert_id = Column(Integer, nullable=True, index=True)
    iris_case_id = Column(Integer, nullable=True, index=True)
    before_json = Column(JSON, nullable=True)
    after_json = Column(JSON, nullable=True)
    ip_address = Column(String(64), nullable=True)
    details = Column(Text, nullable=True)

