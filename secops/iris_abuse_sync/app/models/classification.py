from datetime import datetime, timezone
from sqlalchemy import Boolean, Column, DateTime, Integer, JSON, String, Text
from app.core.database import Base


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class PlaybookTemplate(Base):
    __tablename__ = "playbook_templates"

    id = Column(Integer, primary_key=True, index=True)
    code = Column(String(64), unique=True, nullable=False, index=True)
    name = Column(String(160), nullable=False)
    category_code = Column(String(64), nullable=False, index=True)
    description = Column(Text, nullable=True)
    is_active = Column(Boolean, nullable=False, default=True)
    # Lista de pasos [{order, title, description, mandatory, required_evidence, suggested_action_type}]
    steps_json = Column(JSON, nullable=False, default=list)
    created_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow)
    updated_at = Column(DateTime(timezone=True), nullable=False, default=_utcnow, onupdate=_utcnow)

