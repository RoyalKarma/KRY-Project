from sqlalchemy.orm import Mapped, mapped_column
from .base import Base


class Me(Base):
    __tablename__ = "me"
    username: Mapped[str] = mapped_column(primary_key=True)
    password_salt: Mapped[bytes] = mapped_column()
    token_hash: Mapped[bytes] = mapped_column()
