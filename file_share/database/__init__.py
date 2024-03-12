from pathlib import Path
from typing import Union
from cryptography import x509

from sqlalchemy import create_engine
from sqlalchemy.orm import Session
from .base import Base
from .keys import Keys
from .users import Users


class Database:
    def __init__(self, filename: str = "sqlite.db"):
        self.engine = create_engine(f"sqlite:///{filename}")
        Base.metadata.create_all(self.engine)
        self.session = Session(self.engine)

    def add_user(self, cert_file: Union[str, Path]):
        with open(cert_file, "rb") as file:
            data = file.read()
            cert = x509.load_pem_x509_certificate(data)
            name = ""
            for attr in cert.subject:
                if attr.rfc4514_attribute_name == "CN":
                    name = attr.value
            self.session.merge(Users(name=name, cert_file=data))
            self.session.commit()

    # Retrieval of user certificates
    def get_ca_data(self) -> str:
        """Works with PEM format only."""
        rows = self.session.query(Users).all()
        data = b""
        for row in rows:
            data += row.cert_file
            data += b"\n"
        return data.decode()

    # Functions for API keys management
    def pop_key(self, key: str) -> str:
        row = self.session.query(Keys).filter_by(key=key).one_or_none()
        if not row:
            return ""
        value = row.username
        self.session.delete(row)
        self.session.commit()
        return value

    def add_key(self, username: str, key: str):
        self.session.merge(Keys(username=username, key=key))
        self.session.commit()
