from datetime import datetime
from sqlalchemy import (
    String,
    Integer,
    Boolean,
    text,
    ForeignKey,
    DateTime,
    func,
    LargeBinary,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from database import Base


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    login: Mapped[str] = mapped_column(String(31), unique=True, nullable=False)
    hashed_password: Mapped[str] = mapped_column(String(127), nullable=False)
    require_password_change: Mapped[bool] = mapped_column(
        Boolean, server_default=text("true")
    )

    messages: Mapped[list["Message"]] = relationship(back_populates="user")


class Message(Base):
    __tablename__ = "messages"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    text: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    user_id: Mapped[int] = mapped_column(
        ForeignKey("users.id", ondelete="RESTRICT"), nullable=False
    )
    sent_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, server_default=func.now()
    )

    user: Mapped["User"] = relationship(back_populates="messages")
