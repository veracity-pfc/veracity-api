from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from app.domain.user_model import User

class UserRepository:
    def __init__(self, session: AsyncSession):
        self.session = session

    async def get_by_email(self, email: str) -> User | None:
        q = await self.session.execute(select(User).where(func.lower(User.email) == email.lower()))
        return q.scalar_one_or_none()

    async def add(self, user: User) -> User:
        self.session.add(user)
        await self.session.flush()
        return user

    async def get_by_id(self, user_id: str) -> User | None:
        q = await self.session.execute(select(User).where(User.id == user_id))
        return q.scalar_one_or_none()
