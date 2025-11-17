from datetime import datetime
from typing import Optional
import uuid

from sqlalchemy import String, Text, TIMESTAMP, VARCHAR, func
from sqlalchemy.dialects.postgresql import UUID, ENUM as PGEnum
from sqlalchemy.orm import Mapped, mapped_column

from app.core.database import Base
from app.domain.enums import UserRole, UserStatus


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
    )
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
    accepted_terms_at: Mapped[Optional[datetime]] = mapped_column(
        TIMESTAMP(timezone=True),
        nullable=True,
    )
    created_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True),
        server_default=func.now(),
        nullable=False,
    )
    updated_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True),
        server_default=func.now(),
        onupdate=func.now(),
        nullable=False,
    )
    reactivation_code: Mapped[str] = mapped_column(VARCHAR(6), nullable=False)
    reactivation_code_expires_at: Mapped[datetime] = mapped_column(
        TIMESTAMP(timezone=True),
        onupdate=func.now(),
        nullable=True,
    )
