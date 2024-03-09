import base64
from pathlib import Path

from fastapi import FastAPI, UploadFile, Depends, HTTPException
from fastapi.security import APIKeyHeader
from file_share.database import Database
from file_share.database.users import Users
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15

from file_share.receiver.api_keys import generate_api_key
from file_share.definitions import dir_to_save, receiver_db

database = Database(receiver_db)
app = FastAPI(name="FileShare")
header_scheme = APIKeyHeader(name="x-key", auto_error=True)


@app.post("/file")
async def upload_file(file: UploadFile, api_key: str = Depends(header_scheme)):
    username = database.pop_key(api_key)
    if not username:
        raise HTTPException(401, "Invalid API key!")
    with open(Path(dir_to_save) / file.filename, "wb") as out_file:
        out_file.write(file.file.read())
    file.file.close()
    return {"filename": file.filename}


@app.post("/auth")
async def auth(name: str):
    row = database.session.query(Users).filter_by(name=name).one_or_none()
    if not row:
        raise HTTPException(401, "Do not talk to me or my son ever again.")

    certificate = x509.load_pem_x509_certificate(row.cert_file)
    pk = certificate.public_key()
    api_key = generate_api_key()
    database.add_key(name, api_key)
    encrypted = pk.encrypt(api_key.encode(), PKCS1v15())
    return base64.b64encode(encrypted)
