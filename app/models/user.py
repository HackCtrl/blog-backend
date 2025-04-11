from sqlalchemy import Column, Integer, String, Boolean
from app.database import Base

class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    username = Column(String)
    hashed_password = Column(String)
    is_active = Column(Boolean, default=True)

    @classmethod
    async def get_by_email(cls, db, email: str):
        from sqlalchemy import select
        result = await db.execute(select(cls).where(cls.email == email))
        return result.scalars().first()