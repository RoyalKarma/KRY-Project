import datetime
from typing import Optional

from sqlalchemy.orm import Mapped, mapped_column
from .base import Base


class Files(Base):
    __tablename__ = "files"
    idx: Mapped[int] = mapped_column(primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column()
    incoming: Mapped[bool] = mapped_column()
    timestamp: Mapped[datetime.datetime] = mapped_column()
    filename: Mapped[str] = mapped_column()
    encrypted_data: Mapped[bytes] = mapped_column()
    salt: Mapped[bytes] = mapped_column()
    override_address: Mapped[Optional[str]] = mapped_column()
