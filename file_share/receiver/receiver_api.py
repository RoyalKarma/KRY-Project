import base64
import datetime
from pathlib import Path

from starlette.requests import Request
from fastapi import FastAPI, UploadFile, Depends, HTTPException, APIRouter
from fastapi.security import APIKeyHeader
from file_share.database import Database
from cryptography import x509
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15

from file_share.definitions.dataclasses import Certificate, DecryptedFile
from file_share.receiver.api_keys import generate_api_key

header_scheme: APIKeyHeader = APIKeyHeader(name="x-key", auto_error=True)


class API:
    def __init__(self, database: Database, token: bytes):
        self.router: APIRouter = APIRouter()
        self.database: Database = database
        self.token: bytes = token
        self.router.add_api_route("/file", self.upload_file, methods=["POST"])
        self.router.add_api_route("/auth", self.auth, methods=["POST"])
        self.router.add_api_route("/friends", self.friends, methods=["POST"])
        self.router.add_api_route("/ping", self.ping, methods=["POST"])
        self.app: FastAPI = FastAPI(name="FileShare")
        self.app.include_router(self.router)

    async def upload_file(
        self, file: UploadFile, api_key: str = Depends(header_scheme)
    ):
        """Authentication of sender

        Args:
            file (FastAPI UploadFile object): Transferred file
            api_key (str): Senders API key
        Returns:
            (str): Name of the save file
        """
        # Retrieval of API key from db, if key does not exist raise exception
        username = self.database.pop_key(api_key)
        if not username:
            raise HTTPException(401, "Invalid API key!")
        file_to_save = DecryptedFile(
            username, True, datetime.datetime.now(), file.filename, file.file.read()
        )
        self.database.store_file(file_to_save, self.token)
        file.file.close()
        return {"filename": file.filename}

    async def auth(self, name: str):
        """Authentication of sender

        Args:
            name: name of the sender

        Returns:
            base64 encoded API key
        """
        # Check if the user is in database, if not raise an exception and terminate communication
        row = self.database.get_user(name)
        if not row:
            raise HTTPException(401, "Do not talk to me or my son ever again.")
        # Load certificate from memory and get senders public key
        certificate = x509.load_pem_x509_certificate(row.cert_file)
        pk = certificate.public_key()
        # API key generation and encryption with senders public key
        api_key = generate_api_key()
        self.database.add_key(name, api_key)
        encrypted = pk.encrypt(api_key.encode(), PKCS1v15())

        return base64.b64encode(encrypted)

    async def friends(self, file: UploadFile, request: Request):
        """
        Add friend to the database
        Args:
            file (UploadFile): PEM-encoded certificate
            request (Request): Request object
        """
        try:
            data = await file.read()
            certificate = Certificate(data)
        except:
            raise HTTPException(400, "Send PEM-encoded certificate, not trash.")
        self.database.add_user(certificate, request.client.host)
        return "I will consider your request."

    async def ping(self):
        return "pong"
