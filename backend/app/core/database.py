"""Database connection management"""
from contextlib import asynccontextmanager
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine, AsyncSession, async_sessionmaker
from motor.motor_asyncio import AsyncIOMotorClient
import redis.asyncio as redis

from app.core.config import get_settings

settings = get_settings()

# PostgreSQL async engine (for FastAPI context)
pg_engine = create_async_engine(
    settings.postgres_url,
    echo=settings.debug,
    pool_size=10,
    max_overflow=20,
)

AsyncSessionLocal = async_sessionmaker(
    pg_engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


def create_celery_session():
    """Create a new session factory for Celery tasks (new event loop)"""
    engine = create_async_engine(
        settings.postgres_url,
        echo=settings.debug,
        pool_size=5,
        max_overflow=10,
    )
    session_factory = async_sessionmaker(
        engine,
        class_=AsyncSession,
        expire_on_commit=False,
    )
    return engine, session_factory

# MongoDB client
mongo_client: AsyncIOMotorClient | None = None

# Redis client
redis_client: redis.Redis | None = None


async def init_databases():
    """Initialize database connections"""
    global mongo_client, redis_client
    
    mongo_client = AsyncIOMotorClient(settings.mongodb_url)
    redis_client = redis.from_url(settings.redis_url, decode_responses=True)
    
    # Ensure PostgreSQL enum types are up-to-date before creating tables
    async with pg_engine.begin() as conn:
        # Add 'PAUSED' to scanstatus enum if it exists but doesn't have this value
        await conn.execute(
            text("""
                DO $$
                BEGIN
                    -- Check if enum type exists
                    IF EXISTS (SELECT 1 FROM pg_type WHERE typname = 'scanstatus') THEN
                        -- Check if 'PAUSED' value exists (uppercase to match existing values)
                        IF NOT EXISTS (
                            SELECT 1 FROM pg_enum 
                            WHERE enumtypid = (SELECT oid FROM pg_type WHERE typname = 'scanstatus')
                            AND enumlabel = 'PAUSED'
                        ) THEN
                            -- Add 'PAUSED' to enum
                            ALTER TYPE scanstatus ADD VALUE IF NOT EXISTS 'PAUSED';
                        END IF;
                    END IF;
                END $$;
            """)
        )
    
    # Create PostgreSQL tables
    from app.models.database import Base
    async with pg_engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def close_databases():
    """Close database connections"""
    global mongo_client, redis_client
    
    if mongo_client:
        mongo_client.close()
    if redis_client:
        await redis_client.close()
    await pg_engine.dispose()


async def get_db() -> AsyncSession:
    """FastAPI dependency for database session"""
    async with AsyncSessionLocal() as session:
        yield session


def get_mongo_db():
    """Get MongoDB database instance"""
    return mongo_client[settings.mongodb_db]


def get_redis():
    """Get Redis client"""
    return redis_client
