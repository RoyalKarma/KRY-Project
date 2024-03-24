import asyncio
import ssl
from pathlib import Path
from typing import Any, Union, Optional

from file_share.database import Database, Files
from file_share.definitions import PORT
from file_share.friend_finder.ping_em import StoppablePingClient, StoppableUDPServer
from file_share.definitions.dataclasses import (
    StoppableThread,
    DecryptedFile,
    Certificate,
)
from file_share.receiver import StoppableUvicorn
from file_share.sender.sender import StoppableQueueSender, send_or_store_file, send_cert


class FileShareApp:
    def __init__(self, token: bytes, config: dict[str, Any]):
        """
        Initialize the application.
        Config currently supports these keys:
            'visible': if True, app will respond to pings
            'audible': if True, app will send pings
        """
        self.token: bytes = token
        self.config: dict[str, Any] = config
        self.threads: list[StoppableThread] = []
        self.database = Database()

    def start(self):
        """Start the application."""
        thread = StoppableUvicorn(self.token, daemon=True)
        self.threads.append(thread)
        thread.start()
        thread = StoppableQueueSender(self.token, daemon=True)
        self.threads.append(thread)
        thread.start()
        if self.config.get("visible", False):
            thread = StoppableUDPServer(self.database, daemon=True)
            self.threads.append(thread)
            thread.start()
        if self.config.get("audible", False):
            thread = StoppablePingClient(daemon=True)
            self.threads.append(thread)
            thread.start()

    def stop(self):
        for thread in self.threads:
            thread.stop()

    async def send(self, file: DecryptedFile) -> bool:
        """Asynchronous send method."""
        return await send_or_store_file(self.token, file, self.database)

    def send_sync(self, file: DecryptedFile) -> bool:
        """Same as method send, but is synchronous."""
        return asyncio.run(self.send(file))

    def list_incoming_queue(self) -> list[Files]:
        """List all files that are waiting in the incoming queue."""
        return self.database.get_all_files(True)

    def list_outgoing_queue(self) -> list[Files]:
        """List all files that are waiting in the outgoing queue."""
        return self.database.get_all_files(False)

    def save_file_from_queue(self, file: Files, path: Union[str, Path]):
        """Save an incoming file."""
        try:
            decrypted_file = self.database.decrypt_file(file.idx, self.token)
            decrypted_file.save(path)
            self.database.remove_file_from_queue(file.idx)
        except OSError as e:
            print(f"File {file.filename} could not be saved.", e)

    def save_all_files_from_queue(self, path: Union[str, Path]):
        """Save all files in the queue to the specified location."""
        if isinstance(path, str):
            path = Path(path)
        if not path.is_dir():
            path = path.parent
        for file in self.database.get_all_files(True):
            self.save_file_from_queue(file, path)

    def ignore_incoming_file(self, file: Files) -> bool:
        """Ignore a file that is incoming and remove it from the database."""
        if not file.incoming:
            return False
        self.database.remove_file_from_queue(idx=file.idx)
        return True

    def list_friends(self) -> list[str]:
        """Returns a list of all known friends' usernames."""
        return self.database.get_all_users()

    def list_non_friends(self) -> list[str]:
        """Returns all users that are known but are not our friends."""
        return self.database.get_all_users(False)

    def befriend(self, username: str) -> bool:
        """Make a friend out of the user. Returns False if the user was already our friend."""
        return self.database.befriend(username)

    def check_ip(self, ip_address: str) -> Optional[str]:
        """
        Check if the user with this IP uses this protocol.
        This person will be added to the known users (not friends yet).

        returns username on success, None otherwise
        """
        try:
            asyncio.run(send_cert(ip_address))
            cert = Certificate(ssl.get_server_certificate((ip_address, PORT)).encode())
            self.database.add_user(cert)
            return cert.name
        except:
            return None
