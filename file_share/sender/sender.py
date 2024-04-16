import asyncio
from pathlib import Path
from typing import Optional

import aiohttp
import base64
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15

from file_share.definitions.dataclasses import DecryptedFile, StoppableThread
from file_share.definitions.enums import SendStatus
from file_share.definitions.procedures import des_password_from_token
from file_share.sender.ssl_context import (
    get_ssl_context,
    get_user_address,
    get_promiscuous_context,
)
from file_share.definitions import PORT, certs_dir
from file_share.database import Database


async def send_cert(address: str, database: Database):
    context = get_promiscuous_context()
    my_username = database.get_me().username
    async with aiohttp.ClientSession() as session:
        to_send = aiohttp.FormData()
        to_send.add_field(
            name="file",
            value=open(Path(certs_dir) / "rsa.crt", "rb"),
            filename=f"{my_username}.crt",
            content_type="application/data",
        )
        async with session.post(
            f"https://{address}:{PORT}/friends", ssl_context=context, data=to_send
        ) as response:
            return await response.text()


async def is_active(username: str, address: Optional[str] = None) -> bool:
    context = get_ssl_context(username)
    if not context:
        return False
    address = address or get_user_address(username)
    if not address:
        return False
    try:
        async with aiohttp.ClientSession() as session:
            async with session.post(
                # Sending for authentication
                f"https://{address}:{PORT}/ping",
                ssl_context=context,
            ) as response:
                return response.status == 200
    except:
        return False


async def send_all_from_queue(token: bytes, db_connection: Database):
    """
    Function that sends all files from the queue to the users if they are active.
    Args:
        token (bytes): Auth token of this app to decrypt private key
        db_connection (Database): Database object
    """
    queue = db_connection.get_all_files(False)
    for file in queue:
        username = file.username
        address = file.override_address or get_user_address(username)
        if not await is_active(username, address):
            continue
        file_to_send = db_connection.decrypt_file(file.idx, token)
        try:
            success = await send_file(file_to_send, token, db_connection)
            if success:
                db_connection.remove_file_from_queue(file.idx)
        except Exception as e:
            print("Uh oh", e)
            continue


async def send_file(file: DecryptedFile, token: bytes, db_connection: Database) -> bool:
    """File sending

    Args:
        file (DecryptedFile): The file which is to be sent
        token (bytes): Auth token of this app to decrypt private key
    Returns:
        None
    """
    my_username = db_connection.get_me().username

    username = file.username
    address = file.override_address or get_user_address(username)
    if not address:
        raise ValueError("I do not know a way to that person.")
    context = get_ssl_context(username)
    if not context:
        raise ValueError("That person is not my friend.")
    async with aiohttp.ClientSession() as session:
        async with session.post(
            # Sending for authentication
            f"https://{address}:{PORT}/auth?name={my_username}",
            ssl_context=context,
        ) as response:
            if response.status != 200:
                raise ValueError("Authentication failed!")
            text = await response.text()  # Received encoded API Key
        data = base64.b64decode(text)  # Decode API key
        with open(Path(certs_dir) / "rsa.key", "rb") as key_file:
            key = load_pem_private_key(
                key_file.read(), password=des_password_from_token(token).encode()
            )
        api_key = key.decrypt(
            data, PKCS1v15()
        ).decode()  # Decrypt with your private key
        # Prepare data for transfer
        to_send = aiohttp.FormData()
        to_send.add_field(
            name="file",
            value=file.data,
            filename=file.filename,
            content_type="application/data",
        )
        # Starting data transfer
        async with session.post(
            f"https://{address}:{PORT}/file",
            data=to_send,
            ssl_context=context,
            headers={"x-key": api_key},
        ) as response:
            return response.status == 200


async def send_or_store_file(
    token: bytes, file: DecryptedFile, db_connection: Database
) -> SendStatus:
    """
    Function that checks if the user is active and sends the file if they are, otherwise it stores it
    in queue.
    Args:
        token (bytes): Auth token of this app to decrypt private key
        file (DecryptedFile): The file which is to be sent
        db_connection (Database): Database object
    """
    # Retrieve user from db
    user = db_connection.get_user(file.username, only_friends=False)
    if not user:
        return SendStatus.UNKNOWN_USER
    if not user.is_friend:
        return SendStatus.NOT_FRIEND
    # Check if user is active if not store file to queue
    if not await is_active(file.username, file.override_address):
        db_connection.store_file(file, token)
        print("User inactive, storing file to queue.")
        return SendStatus.QUEUED
    try:
        await send_file(file, token, db_connection)
        return SendStatus.SUCCESS
    except Exception as e:
        print("Uh oh", e)
        db_connection.store_file(file, token)
        return SendStatus.REFUSED_QUEUED


class StoppableQueueSender(StoppableThread):
    """
    Definition of a thread that periodically checks the queue and sends files to users if they are active.
    """

    def __init__(self, token: bytes, *args, **kwargs):
        self.token = token
        self.database: Database = Database()
        super().__init__(*args, **kwargs)

    def run(self):
        asyncio.run(self._periodic_queue_search())

    async def _periodic_queue_search(self):
        while not self._stop_event.is_set():
            await asyncio.sleep(15)
            await send_all_from_queue(self.token, self.database)
