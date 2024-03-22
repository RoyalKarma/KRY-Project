from typing import Optional

from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from .base import Base
from .keys import Keys
from .users import Users
from ..definitions import debug
from ..definitions.dataclasses import Certificate


class Database:
    def __init__(self, filename: str = "sqlite.db"):
        self.engine = create_engine(f"sqlite:///{filename}")
        Base.metadata.create_all(self.engine)

    @property
    def session(self):
        return Session(self.engine)

    def add_user(
        self, cert: Certificate, address: Optional[str] = None, as_friend: bool = False
    ) -> bool:
        """
        If the username was not previously known, return True and save it to the DB.
        Fail and return False otherwise.
        """
        session = self.session
        known = session.query(Users).filter_by(name=cert.name).one_or_none()
        if known:
            return False
        user_specs = {"name": cert.name, "cert_file": cert.data, "is_friend": as_friend}
        if address:
            user_specs["address"] = address

        session.merge(Users(**user_specs))
        session.commit()
        return True

    def befriend(self, username: str) -> bool:
        """Return True if user is known and is not a friend already."""
        session = self.session
        known = session.query(Users).filter_by(name=username).one_or_none()
        if not known or known.is_friend:
            return False
        known.is_friend = True
        session.merge(known)
        session.commit()
        return True

    def get_user(
        self, username: str, only_friends: bool = not debug
    ) -> Optional[Users]:
        session = self.session
        params = {"name": username}
        if only_friends:
            params["is_friend"] = True
        user = (
            session.query(Users.name, Users.cert_file, Users.address, Users.is_friend)
            .filter_by(**params)
            .one_or_none()
        )
        session.commit()
        return user

    # Retrieval of user certificates
    def get_ca_data(self) -> str:
        """Works with PEM format only."""
        session = self.session
        rows = session.query(Users).filter_by(is_friend=True).all()
        session.commit()
        data = b""
        for row in rows:
            data += row.cert_file
            data += b"\n"
        return data.decode()

    # Functions for API keys management
    def pop_key(self, key: str) -> str:
        session = self.session
        row = session.query(Keys).filter_by(key=key).one_or_none()
        if not row:
            return ""
        value = row.username
        session.delete(row)
        session.commit()
        return value

    def add_key(self, username: str, key: str):
        session = self.session
        session.merge(Keys(username=username, key=key))
        session.commit()
