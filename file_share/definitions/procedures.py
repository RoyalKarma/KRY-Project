from datetime import datetime
from pathlib import Path
from typing import Union

from cryptography.fernet import Fernet
from hashlib import sha256
import base64

from file_share.definitions.dataclasses import DecryptedFile


def _get_key(token: bytes, seed: bytes) -> bytes:
    key_gen = sha256()
    key_gen.update(token)
    key_gen.update(seed)
    return base64.b64encode(key_gen.digest()[-32:])


def encrypt(data: bytes, token: bytes, seed: bytes) -> bytes:
    encryption_factory = Fernet(_get_key(token, seed))
    return encryption_factory.encrypt(data)


def decrypt(data: bytes, token: bytes, seed: bytes) -> bytes:
    decryption_factory = Fernet(_get_key(token, seed))
    return decryption_factory.decrypt(data)


def load_file(path: Union[str, Path], send_to: str) -> DecryptedFile:
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
    )
