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

from app.core.database import Base
from app.domain.enums import ApiTokenStatus

class ApiToken(Base):
    __tablename__ = "api_tokens"

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
    token_hash = Column(Text, nullable=False, unique=True)
    token_prefix = Column(String(16), nullable=False)
    status = Column(
        ENUM(
            ApiTokenStatus,
            name="api_token_status",
            create_type=False,
        ),
        nullable=False,
        server_default=ApiTokenStatus.active,
    )
    created_at = Column(
        TIMESTAMP(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    expires_at = Column(TIMESTAMP(timezone=True), nullable=False)
    last_used_at = Column(TIMESTAMP(timezone=True))
    revoked_at = Column(TIMESTAMP(timezone=True))
    revoked_reason = Column(Text)
    revoked_by_admin_id = Column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )

    user = relationship("User", foreign_keys=[user_id], lazy="joined")
    revoked_by_admin = relationship(
        "User",
        foreign_keys=[revoked_by_admin_id],
        lazy="joined",
    )

    __table_args__ = (
        Index("ix_api_tokens_expires_at", "expires_at"),
        Index("ix_api_tokens_status_created_at", "status", "created_at"),
        Index("ix_api_tokens_user_id", "user_id"),
        Index("ix_api_tokens_token_hash", "token_hash"),
    )
