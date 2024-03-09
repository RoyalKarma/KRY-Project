from sqlalchemy.orm import Mapped, mapped_column
from sqlalchemy import String
from .base import Base
from ..definitions import api_key_length_bytes


class Keys(Base):
    __tablename__ = "keys"

    username: Mapped[str] = mapped_column(primary_key=True)
    key: Mapped[str] = mapped_column(String(length=api_key_length_bytes))

