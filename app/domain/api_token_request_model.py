from __future__ import annotations

from sqlalchemy import (
    TIMESTAMP,
    Column,
    ForeignKey,
    Index,
    String,
    Text,
    text,
    func,
)
from sqlalchemy.dialects.postgresql import ENUM, UUID
from sqlalchemy.orm import relationship
from sqlalchemy import Integer, Column

from app.core.database import Base
from app.domain.api_token_model import ApiToken
from app.domain.enums import ApiTokenRequestStatus


class ApiTokenRequest(Base):
    __tablename__ = "api_token_requests"

    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
    )
    user_id = Column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=False,
    )
    email = Column(String(60), nullable=False)
    message = Column(Text, nullable=False)
    status = Column(
        ENUM(
            ApiTokenRequestStatus,
            name="api_token_request_status",
            create_type=False,
        ),
        nullable=False,
        server_default=ApiTokenRequestStatus.open,
    )
    created_at = Column(
        TIMESTAMP(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    decided_at = Column(TIMESTAMP(timezone=True))
    decided_by_admin_id = Column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    rejection_reason = Column(Text)
    related_token_id = Column(
        UUID(as_uuid=True),
        ForeignKey("api_tokens.id", ondelete="SET NULL"),
        nullable=True,
    )
    seq_id = Column(Integer, server_default=text("0"), nullable=False)

    user = relationship("User", foreign_keys=[user_id], lazy="joined")
    decided_by_admin = relationship(
        "User",
        foreign_keys=[decided_by_admin_id],
        lazy="joined",
    )
    related_token = relationship(
        ApiToken,
        foreign_keys=[related_token_id],
        lazy="joined",
    )

    __table_args__ = (
        Index("ix_api_token_requests_email", "email"),
        Index("ix_api_token_requests_status_created_at", "status", "created_at"),
        Index("ix_api_token_requests_user_id", "user_id"),
    )
