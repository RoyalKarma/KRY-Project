import asyncio
from pathlib import Path

import aiohttp
import base64
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric.padding import PKCS1v15

from file_share.sender.ssl_context import get_ssl_context
from file_share.definitions import sender_name, PORT, sender_certs


async def send_file(address: str, filename: Path):
    """File sending

    Args:
        address (str): Address of the reciever
        filename (Path): Path to the file which is to be sent

    Returns:
        None
    """
    context = get_ssl_context()
    async with aiohttp.ClientSession() as session:
        async with session.post(
            # Sending for authentication 
            f"https://{address}:{PORT}/auth?name={sender_name}", ssl_context=context
        ) as response: 
            if response.status != 200:
                raise ValueError("Authentication failed!")
            text = await response.text() # Recieved encoded API Kkey
        data = base64.b64decode(text) # Decode API key
        with open(Path(sender_certs) / "rsa.key", "rb") as file:
            key = load_pem_private_key(file.read(), password=None)
        api_key = key.decrypt(data, PKCS1v15()).decode() # Decrypt with your private key
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
            print(
                f"Data sent. Response message: {await response.text()}, Response status: {response.status}"
            )


if __name__ == "__main__":
    asyncio.run(send_file("localhost", Path("testfile.txt")))
