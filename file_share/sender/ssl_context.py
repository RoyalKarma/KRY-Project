import ssl
from ssl import SSLContext
from typing import Optional

from file_share.database import Database
from file_share.definitions import db

db_connection = Database(db)


def get_ssl_context(username: str) -> Optional[SSLContext]:
    row = db_connection.get_user(username)
    if not row:
        return None

    context = SSLContext()
    context.verify_mode = ssl.VerifyMode.CERT_REQUIRED
    if row.cert_file:
        context.load_verify_locations(cadata=row.cert_file.decode())
    return context


def get_promiscuous_context() -> SSLContext:
    context = SSLContext()
    context.verify_mode = ssl.VerifyMode.CERT_NONE
    return context


def get_user_address(username: str) -> Optional[str]:
    row = db_connection.get_user(username)
    if not row:
        return None
    return row.address
