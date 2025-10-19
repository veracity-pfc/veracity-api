from sqlalchemy import String, Text, TIMESTAMP, func, ForeignKey, JSON
from sqlalchemy.dialects.postgresql import UUID, JSONB, ENUM as PGEnum
from sqlalchemy.orm import Mapped, mapped_column
import enum
import uuid
from datetime import datetime
from typing import Optional, Dict, Any

from .database import Base

class UserRole(str, enum.Enum):
    user = "user"
    admin = "admin"

class UserStatus(str, enum.Enum):
    active = "active"
    inactive = "inactive"

class AnalysisType(str, enum.Enum):
    url = "url"
    image = "image"

class AnalysisStatus(str, enum.Enum):
    pending = "pending"
    done = "done"
    error = "error"

class RiskLabel(str, enum.Enum):
    safe = "safe"
    suspicious = "suspicious"
    malicious = "malicious"
    fake = "fake"
    unknown = "unknown"

class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    email: Mapped[str] = mapped_column(String, unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(Text, nullable=False)

    role: Mapped[UserRole] = mapped_column(
        PGEnum(UserRole, name="user_role", create_type=False),
        nullable=False,
        default=UserRole.user,
    )
    status: Mapped[UserStatus] = mapped_column(
        PGEnum(UserStatus, name="user_status", create_type=False),
        nullable=False,
        default=UserStatus.active,
    )

    accepted_terms_at: Mapped[Optional[datetime]] = mapped_column(TIMESTAMP(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), server_default=func.now(), nullable=False)
    updated_at: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)

class AuditLog(Base):
    __tablename__ = "audit_log"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    occurred_at: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), server_default=func.now(), nullable=False)
    user_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    actor_ip_hash: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    action: Mapped[str] = mapped_column(Text, nullable=False)
    resource: Mapped[Optional[str]] = mapped_column(Text)
    success: Mapped[bool] = mapped_column(nullable=False)
    details: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON)

class Analysis(Base):
    __tablename__ = "analyses"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)

    analysis_type: Mapped[AnalysisType] = mapped_column(
        PGEnum(AnalysisType, name="analysis_type", create_type=False),
        nullable=False,
    )
    status: Mapped[AnalysisStatus] = mapped_column(
        PGEnum(AnalysisStatus, name="analysis_status", create_type=False),
        nullable=False,
        default=AnalysisStatus.pending,
    )
    label: Mapped[RiskLabel] = mapped_column(
        PGEnum(RiskLabel, name="risk_label", create_type=False),
        nullable=False,
        default=RiskLabel.unknown,
    )

    user_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    actor_ip_hash: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), server_default=func.now(), nullable=False)
    completed_at: Mapped[Optional[datetime]] = mapped_column(TIMESTAMP(timezone=True), nullable=True)
    ai_response_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), nullable=True)
    source_url: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

class UrlAnalysis(Base):
    __tablename__ = "url_analyses"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    user_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"), nullable=True, index=True)
    actor_ip_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    url_original: Mapped[str] = mapped_column(String(2048), nullable=False)
    url_normalized: Mapped[str] = mapped_column(String(512), nullable=False, index=True)
    tld_ok: Mapped[bool] = mapped_column(nullable=False, default=False)
    dns_ok: Mapped[bool] = mapped_column(nullable=False, default=False)
    ipqs_json: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    gsb_json: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    ai_json: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    risk_label: Mapped[str | None] = mapped_column(String(32), nullable=True)
    created_at: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), server_default=func.now(), nullable=False)

class ImageAnalysis(Base):
    __tablename__ = "image_analyses"
    analysis_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("analyses.id", ondelete="CASCADE"), primary_key=True)
    meta: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON)

class AIResponse(Base):
    __tablename__ = "ai_responses"
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    analysis_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("analyses.id", ondelete="CASCADE"), unique=True, nullable=False)
    provider: Mapped[str] = mapped_column(Text, nullable=False)
    model: Mapped[str] = mapped_column(Text, nullable=False)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), server_default=func.now(), nullable=False)

class PendingRegistration(Base):
    __tablename__ = "pending_registrations"
    id: Mapped[uuid.UUID] = mapped_column(primary_key=True, default=uuid.uuid4)
    name: Mapped[str] = mapped_column(String(30), nullable=False)
    email: Mapped[str] = mapped_column(String(60), nullable=False, index=True)
    password_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    code: Mapped[str] = mapped_column(String(6), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), nullable=False)
    attempts: Mapped[int] = mapped_column(default=0, nullable=False)
    accepted_terms_at: Mapped[datetime | None] = mapped_column(
        TIMESTAMP(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True), server_default=func.now(), nullable=False
    )