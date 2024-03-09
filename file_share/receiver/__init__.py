import os
import uvicorn

from file_share.definitions import receiver_certs
from .receiver_api import app
from ..definitions import PORT


def run_server(port: int = PORT) -> None:
    uvicorn.run(
        app,
        port=port,
        ssl_keyfile=f"{receiver_certs}/rsa.key",
        ssl_certfile=f"{receiver_certs}/rsa.crt",
    )


__all__ = "app"
