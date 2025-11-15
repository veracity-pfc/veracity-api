from __future__ import annotations

from datetime import datetime
from typing import Any, Dict
import uuid

from sqlalchemy import Text, TIMESTAMP, func, ForeignKey
from sqlalchemy.dialects.postgresql import UUID, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base


class ImageAnalysis(Base):
    __tablename__ = "image_analyses"

    analysis_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("analyses.id", ondelete="CASCADE"),
        primary_key=True,
    )
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("users.id"),
        nullable=True,
        index=True,
    )
    actor_ip_hash: Mapped[str | None] = mapped_column(Text, nullable=True)
    meta: Mapped[Dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    sightengine_json: Mapped[Dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    ai_json: Mapped[Dict[str, Any] | None] = mapped_column(JSONB, nullable=True)
    risk_label: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
