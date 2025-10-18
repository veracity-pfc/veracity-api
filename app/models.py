from sqlalchemy import String, Text, TIMESTAMP, func, ForeignKey, JSON, CHAR, Integer
from sqlalchemy.dialects.postgresql import UUID, ENUM as PGEnum
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
    link = "link"
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

class LinkAnalysis(Base):
    __tablename__ = "link_analyses"
    analysis_id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), ForeignKey("analyses.id", ondelete="CASCADE"), primary_key=True)
    url: Mapped[str] = mapped_column(Text, nullable=False)
    gsb_verdict: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON)
    ipqs_verdict: Mapped[Optional[Dict[str, Any]]] = mapped_column(JSON)
    reason: Mapped[Optional[str]] = mapped_column(Text)

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
    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    email: Mapped[str] = mapped_column(Text, nullable=False)
    name: Mapped[str] = mapped_column(Text, nullable=False)
    password_hash: Mapped[str] = mapped_column(Text, nullable=False)
    code: Mapped[str] = mapped_column(CHAR(6), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), nullable=False)
    last_sent_at: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), server_default=func.now(), nullable=False)
    attempts: Mapped[int] = mapped_column(Integer, server_default="0", nullable=False)
    created_at: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), server_default=func.now(), nullable=False)
