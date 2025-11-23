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
from app.domain.enums import ContactCategory, ContactStatus

class ContactRequest(Base):
    __tablename__ = "contact_requests"

    id = Column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
    )
    user_id = Column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="RESTRICT"),
        nullable=True,
    )
    email = Column(String(60), nullable=False)
    category = Column(
        ENUM(ContactCategory, name="contact_category", create_type=False),
        nullable=False,
    )
    subject = Column(String(100), nullable=False)
    message = Column(Text, nullable=False)
    status = Column(
        ENUM(ContactStatus, name="contact_status", create_type=False),
        nullable=False,
        server_default=ContactStatus.open,
    )
    
    admin_reply = Column(Text, nullable=True)
    replied_at = Column(TIMESTAMP(timezone=True), nullable=True)
    replied_by_admin_id = Column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
        nullable=True,
    )
    
    created_at = Column(
        TIMESTAMP(timezone=True),
        nullable=False,
        server_default=func.now(),
    )
    seq_id = Column(Integer, server_default=text("0"), nullable=False)

    user = relationship("User", foreign_keys=[user_id], lazy="joined")
    replied_by_admin = relationship("User", foreign_keys=[replied_by_admin_id], lazy="joined")

    __table_args__ = (
        Index("ix_contact_requests_user_id", "user_id"),
        Index("ix_contact_requests_status", "status"),
    )