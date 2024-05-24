from database import Base
from sqlalchemy import Column, Integer, String, Float, Date, ForeignKey, func, DateTime, Boolean,  Enum as SQLEnum, Enum
from sqlalchemy.orm import relationship


class TodoList(Base):
    __tablename__ = 'TodoList'
    id = Column(Integer, primary_key=True, index=True)
    newItem = Column(String(length=500))


class CompletedList(Base):
    __tablename__ = 'CompletedList'
    id = Column(Integer, primary_key=True, index=True)
    completedItem = Column(String(length=500))


class Users(Base):
    __tablename__ = 'users'

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(length=500))
    email = Column(String(length=500), unique=True)
    hashed_password = Column(String(length=500))
    refresh_tokens = relationship(
        "RefreshToken", back_populates="user", order_by="RefreshToken.expires_at.desc()")


class RefreshToken(Base):
    __tablename__ = "refresh_tokens"

    id = Column(Integer, primary_key=True, index=True)
    token = Column(String(length=7000), index=True, unique=True)
    user_id = Column(Integer, ForeignKey('users.id'))
    expires_at = Column(DateTime)

    user = relationship("Users", back_populates="refresh_tokens")
