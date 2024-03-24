from typing import Any

from file_share.database import Database
from file_share.friend_finder.ping_em import StoppablePingClient, StoppableUDPServer
from file_share.definitions.dataclasses import StoppableThread
from file_share.receiver import StoppableUvicorn
from file_share.sender.sender import StoppableQueueSender


class FileShareApp:
    def __init__(self, token: bytes, config: dict[str, Any]):
        self.token: bytes = token
        self.config: dict[str, Any] = config
        self.threads: list[StoppableThread] = []
        self.database = Database()

    def start(self):
        thread = StoppableUvicorn(daemon=True)
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