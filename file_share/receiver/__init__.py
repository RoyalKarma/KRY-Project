import os
import signal

import uvicorn

from file_share.database import Database
from file_share.definitions import certs_dir
from file_share.definitions.procedures import des_password_from_token
from file_share.receiver.receiver_api import API
from file_share.receiver.get_ip import get_local_ip
from file_share.definitions import PORT
from file_share.definitions.dataclasses import StoppableThread


class StoppableUvicorn(StoppableThread):
    def __init__(self, token: bytes, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.token: bytes = token

    def stop(self):
        os.kill(os.getpid(), signal.SIGINT)

    def run(self) -> None:
        uvicorn.run(
            API(Database(), self.token).app,
            port=PORT,
            ssl_keyfile=f"{certs_dir}/rsa.key",
            ssl_certfile=f"{certs_dir}/rsa.crt",
            ssl_keyfile_password=des_password_from_token(self.token),
            host=get_local_ip(),
        )


__all__ = "app"
