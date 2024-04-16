import subprocess
from datetime import datetime
from pathlib import Path
from typing import Union, Optional

from cryptography.fernet import Fernet
from hashlib import sha256
import base64

from file_share.definitions.dataclasses import DecryptedFile
from file_share.definitions import hash_iterations


def _get_key(token: bytes, seed: bytes) -> bytes:
    key_gen = sha256()
    key_gen.update(token)
    key_gen.update(seed)
    return base64.b64encode(key_gen.digest()[-32:])


def encrypt(data: bytes, token: bytes, seed: bytes) -> bytes:
    """
    Encrypt data using token and seed.
    Args:
        data (bytes): data to be encrypted
        token (bytes): token used for encryption
        seed (bytes): seed used for encryption
    """
    encryption_factory = Fernet(_get_key(token, seed))
    return encryption_factory.encrypt(data)


def decrypt(data: bytes, token: bytes, seed: bytes) -> bytes:
    """
    Decrypt data using token and seed.
    Args:
        data (bytes): data to be decrypted
        token (bytes): token used for decryption
        seed (bytes): seed used for decryption
    """
    decryption_factory = Fernet(_get_key(token, seed))
    return decryption_factory.decrypt(data)


def load_file(
    path: Union[str, Path], send_to: str, override_address: Optional[str] = None
) -> DecryptedFile:
    """
    Load file from filesystem and prepare it for sending by
    wrapping it in DecryptedFile object.

    Args:
        path (Union[str, Path]): path to file that needs to be loaded
        send_to (str): peer to receive the file
        override_address (str): IP address if we want to specify it explicitly
            and not just count on the DB
    """
    if isinstance(path, str):
        path = Path(path)
    with open(path, "rb") as infile:
        data = infile.read()
    return DecryptedFile(
        username=send_to,
        incoming=False,
        timestamp=datetime.now(),
        filename=path.name,
        data=data,
        override_address=override_address,
    )


def compute_token(password: str, seed: bytes) -> bytes:
    token_factory = sha256()
    token_factory.update(seed)
    token_factory.update(password.encode())
    data = token_factory.digest()
    for _ in range(hash_iterations):
        token_factory.update(data)
        data = token_factory.digest()
    return data


def get_token_hash(token: bytes) -> bytes:
    hash_factory = sha256()
    hash_factory.update(token)
    return hash_factory.digest()


def des_password_from_token(token: bytes) -> str:
    """
    Use token to generate a password used for RSA key
    encryption.

    This function encodes the token before hashing.
    This is because the hash of unencoded token is
    stored in the database for password validation
    purposes. If the token was hashed unencoded,
    then the plaintext from database could be used
    for private key decryption.
    """
    b64_token = base64.b64encode(token)
    seed_factory = sha256()
    seed_factory.update(b64_token)
    return base64.b64encode(seed_factory.digest(), altchars=b"_=").decode()


def create_cert(name: str, location: Path, token: bytes):
    """Creates a certificate file."""
    Path(location).mkdir(exist_ok=True)
    subprocess.run(
        [
            "openssl",
            "req",
            "-x509",
            "-sha256",
            "-newkey",
            "rsa:4096",
            "-keyout",
            f"{location}/rsa.key",
            "-out",
            f"{location}/rsa.crt",
            "-days",
            "3650",
            "-passout",
            f"pass:{des_password_from_token(token)}",
            "-subj",
            f"/C=CZ/ST=JMK/L=Brno/O=VUT/OU=FEKT/CN={name}",
        ]
    )
