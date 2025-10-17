from sqlalchemy import String, Enum, Text, TIMESTAMP, func, ForeignKey, JSON
from sqlalchemy.dialects.postgresql import UUID
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
    role: Mapped[UserRole] = mapped_column(Enum(UserRole), default=UserRole.user, nullable=False)
    status: Mapped[UserStatus] = mapped_column(Enum(UserStatus), default=UserStatus.active, nullable=False)
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
    analysis_type: Mapped[AnalysisType] = mapped_column(Enum(AnalysisType), nullable=False)
    status: Mapped[AnalysisStatus] = mapped_column(Enum(AnalysisStatus), default=AnalysisStatus.pending, nullable=False)
    label: Mapped[RiskLabel] = mapped_column(Enum(RiskLabel), default=RiskLabel.unknown, nullable=False)
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
