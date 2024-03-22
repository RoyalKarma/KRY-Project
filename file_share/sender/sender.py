import asyncio
from pathlib import Path
from typing import Optional

import aiohttp
import base64
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15

from file_share.sender.ssl_context import (
    get_ssl_context,
    get_user_address,
    get_promiscuous_context,
)
from file_share.definitions import username, PORT, certs_dir


async def send_cert(address: str):
    context = get_promiscuous_context()
    async with aiohttp.ClientSession() as session:
        to_send = aiohttp.FormData()
        to_send.add_field(
            name="file",
            value=open(Path(certs_dir) / "rsa.crt", "rb"),
            filename=f"{username}.crt",
            content_type="application/data",
        )
        async with session.post(
            f"https://{address}:{PORT}/friends", ssl_context=context, data=to_send
        ) as response:
            return await response.text()


async def send_file(username: str, filename: Path, ip_addr: Optional[str] = None):
    """File sending

    Args:
        username (str): username of the receiver
        filename (Path): Path to the file which is to be sent
        ip_addr (Optional[str]): Address of the reciever (override data  from db)

    Returns:
        None
    """
    address = ip_addr or get_user_address(username)
    if not address:
        raise ValueError("I do not know a way to that person.")
    context = get_ssl_context(username)
    if not context:
        raise ValueError("That person is not my friend.")
    async with aiohttp.ClientSession() as session:
        async with session.post(
            # Sending for authentication
            f"https://{address}:{PORT}/auth?name={username}",
            ssl_context=context,
        ) as response:
            if response.status != 200:
                raise ValueError("Authentication failed!")
            text = await response.text()  # Received encoded API Key
        data = base64.b64decode(text)  # Decode API key
        with open(Path(certs_dir) / "rsa.key", "rb") as file:
            key = load_pem_private_key(file.read(), password=None)
        api_key = key.decrypt(
            data, PKCS1v15()
        ).decode()  # Decrypt with your private key
        # Prepare data for transfer
        to_send = aiohttp.FormData()
        to_send.add_field(
            name="file",
            value=open(filename, "rb"),
            filename=filename.name,
            content_type="application/data",
        )
        # Starting data transfer
        async with session.post(
            f"https://{address}:{PORT}/file",
            data=to_send,
            ssl_context=context,
            headers={"x-key": api_key},
        ) as response:
            return await response.text()


if __name__ == "__main__":
    asyncio.run(send_file("alice", Path("testfile.txt")))
