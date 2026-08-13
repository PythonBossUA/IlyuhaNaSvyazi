from sqlalchemy import String, Integer
from sqlalchemy.orm import Mapped, mapped_column

from database import Base


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, autoincrement=True, primary_key=True)
    login: Mapped[str] = mapped_column(String(31), unique=True, nullable=False)
    hashed_password: Mapped[str] = mapped_column(String(127), nullable=False)
