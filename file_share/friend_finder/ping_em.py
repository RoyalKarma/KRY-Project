import asyncio
import json
import socket
import ssl

from file_share.database import Database
from file_share.definitions import PORT, debug
from file_share.definitions.dataclasses import Certificate, StoppableThread
from file_share.sender.sender import send_cert
from file_share.receiver.get_ip import get_local_ip, get_broadcast_addr


class StoppableUDPServer(StoppableThread):
    def __init__(self, database: Database, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.database = database

    async def _udp_server(self):
        """Function to run the UDP listener that stores friend requests."""
        soc = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        soc.bind(("", PORT))
        while not self._stop_event.is_set():
            message, address = soc.recvfrom(1024)
            try:
                address = address[0]  # get only IP, ignore port
                json_message = json.loads(message.decode())
                if json_message["proto"] != "file_share":
                    continue
                peer_username = json_message["username"]
                if self.database.get_user(peer_username, only_friends=False):
                    # Already know user
                    continue
                if not debug and self.database.get_me().username == peer_username:
                    # that me lol
                    continue
                await send_cert(address, self.database)
                self.database.add_user(
                    Certificate(ssl.get_server_certificate((address, PORT)).encode()),
                    address,
                )
            except Exception as e:
                print(e)
                continue

    def run(self):
        asyncio.run(self._udp_server())


class StoppablePingClient(StoppableThread):
    def __init__(self, *args, **kwargs):
        self.db_instance: Database = Database()
        super().__init__(*args, **kwargs)

    async def _send_ping(self) -> None:
        my_username = self.db_instance.get_me().username
        msg = json.dumps({"proto": "file_share", "username": my_username}).encode()
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.bind((get_local_ip(), 0))
        address = "127.0.0.1" if debug else get_broadcast_addr()

        sock.sendto(msg, (address, PORT))
        sock.close()

    async def periodic_ping(self):
        while not self._stop_event.is_set():
            await asyncio.sleep(10)
            await self._send_ping()

    def run(self):
        asyncio.run(self.periodic_ping())


if __name__ == "__main__":
    threads = [StoppableUDPServer(Database()), StoppablePingClient()]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
