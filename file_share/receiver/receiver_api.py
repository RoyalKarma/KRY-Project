import base64
from pathlib import Path

from starlette.requests import Request
from fastapi import FastAPI, UploadFile, Depends, HTTPException
from fastapi.security import APIKeyHeader
from file_share.database import Database
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15

from file_share.definitions.dataclasses import Certificate
from file_share.receiver.api_keys import generate_api_key
from file_share.definitions import dir_to_save, db

database = Database(db)
app = FastAPI(name="FileShare")
header_scheme = APIKeyHeader(name="x-key", auto_error=True)


@app.post("/file")
async def upload_file(file: UploadFile, api_key: str = Depends(header_scheme)):
    """Authentication of sender

    Args:
        request: ASGI request
        file (FastAPI UploadFile object): Transfered file
        api_key (str): Senders API key
    Returns:
        (str): Name of the save file
    """
    # Retrieval of API key from db, if key does not exist raise exception
    username = database.pop_key(api_key)
    if not username:
        raise HTTPException(401, "Invalid API key!")
    # Save the sent file to target directory
    with open(Path(dir_to_save) / file.filename, "wb") as out_file:
        out_file.write(file.file.read())
    file.file.close()
    return {"filename": file.filename}


@app.post("/auth")
async def auth(name: str):
    """Authentication of sender

    Args:
        name: name of the sender

    Returns:
        base64 encoded API key
    """
    # Check if the user is in database, if not raise an exception and terminate communication
    row = database.get_user(name)
    if not row:
        raise HTTPException(401, "Do not talk to me or my son ever again.")
    # Load certificate from memory and get senders public key
    certificate = x509.load_pem_x509_certificate(row.cert_file)
    pk = certificate.public_key()
    # API key generation and encryption with senders public key
    api_key = generate_api_key()
    database.add_key(name, api_key)
    encrypted = pk.encrypt(api_key.encode(), PKCS1v15())

    return base64.b64encode(encrypted)


@app.post("/friends")
async def friends(file: UploadFile, request: Request):
    try:
        data = await file.read()
        certificate = Certificate(data)
    except:
        raise HTTPException(400, "Send PEM-encoded certificate, not trash.")
    database.add_user(certificate, request.client.host)
    return "I will consider your request."
