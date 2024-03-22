from sqlalchemy.orm import Mapped, mapped_column
from .base import Base


class Users(Base):
    __tablename__ = "users"
    # Storage of users and their cert files
    name: Mapped[str] = mapped_column(primary_key=True)
    cert_file: Mapped[bytes] = mapped_column()
    address: Mapped[str] = mapped_column()
    is_friend: Mapped[bool] = mapped_column()
