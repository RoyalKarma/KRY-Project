import ssl
from ssl import SSLContext
from file_share.database import Database
from file_share.definitions import sender_db

db_connection = Database(sender_db)


def get_ssl_context() -> SSLContext:
    certs_data = db_connection.get_ca_data()
    context = SSLContext()
    context.verify_mode = ssl.VerifyMode.CERT_REQUIRED
    if certs_data:
        context.load_verify_locations(cadata=certs_data)
    return context
