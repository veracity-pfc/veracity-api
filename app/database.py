from sqlalchemy.ext.asyncio import create_async_engine, async_sessionmaker, AsyncSession
from sqlalchemy.orm import declarative_base
from collections.abc import AsyncGenerator
import ssl
from .config import settings

ssl_ctx = ssl.create_default_context()

engine = create_async_engine(
    settings.database_url,
    echo=False,
    pool_pre_ping=True,
    connect_args={"ssl": ssl_ctx},
    pool_size=5,         
    max_overflow=5,       
    pool_timeout=5,      
    pool_recycle=1800,    
)

AsyncSessionLocal = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)
Base = declarative_base()

async def get_session() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionLocal() as session:
        yield session
