from sqlalchemy import Text, TIMESTAMP, func, ForeignKey
from sqlalchemy.dialects.postgresql import UUID, ENUM as PGEnum
from sqlalchemy.orm import Mapped, mapped_column
from datetime import datetime
from typing import Optional
import uuid

from app.core.database import Base
from app.domain.enums import AnalysisType, AnalysisStatus, RiskLabel

class Analysis(Base):
    __tablename__ = "analyses"

    id: Mapped[uuid.UUID] = mapped_column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    analysis_type: Mapped[AnalysisType] = mapped_column(PGEnum(AnalysisType, name="analysis_type", create_type=False), nullable=False)
    status: Mapped[AnalysisStatus] = mapped_column(PGEnum(AnalysisStatus, name="analysis_status", create_type=False), nullable=False, default=AnalysisStatus.pending)
    label: Mapped[RiskLabel] = mapped_column(PGEnum(RiskLabel, name="risk_label", create_type=False), nullable=False, default=RiskLabel.unknown)
    user_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=True)
    actor_ip_hash: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(TIMESTAMP(timezone=True), server_default=func.now(), nullable=False)
    completed_at: Mapped[Optional[datetime]] = mapped_column(TIMESTAMP(timezone=True), nullable=True)
    ai_response_id: Mapped[Optional[uuid.UUID]] = mapped_column(UUID(as_uuid=True), nullable=True)
    source_url: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
