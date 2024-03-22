import threading
from typing import Union
from pathlib import Path
from cryptography import x509


class Certificate:
    """
    Dataclass to store information about a certificate.
    If Path or string is passed, the constructor will
    interpret these as a path to a file containing
    the certificate to load.
    If bytes are passed instead, it is considered to be
    the content of the certificate file.

    Attributes:
        data: content of the certificate (Base64 encoded string)
            stored in bytes object
        cert: cryptography.x509.Certificate object
        name: username, read from the CN field
    """
    def __init__(self, cert: Union[str, Path, bytes]):
        self.data: bytes
        self.cert: x509.Certificate
        self.name: str = ""

        if not isinstance(cert, Union[str, Path, bytes]):
            raise TypeError("Unsupported type!")
        if isinstance(cert, str):
            cert = Path(cert)
        if isinstance(cert, Path):
            with open(cert, "rb") as cert_file:
                cert = cert_file.read()
        self.cert = x509.load_pem_x509_certificate(cert)
        self.data = cert
        for attr in self.cert.subject:
            if attr.rfc4514_attribute_name == "CN":
                self.name = attr.value
                break

class StoppableThread(threading.Thread):
    """Thread class with a stop() method. The thread itself has to check
    regularly for the stopped() condition."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._stop_event = threading.Event()

    def stop(self):
        self._stop_event.set()

    def stopped(self):
        return self._stop_event.is_set()
