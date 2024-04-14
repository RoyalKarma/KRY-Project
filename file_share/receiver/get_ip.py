import socket

from file_share.definitions import debug


def get_local_ip() -> str:
    """Return this station's IP used for internet connections."""
    if debug:
        return "127.0.0.1"
    # Create UDP socket for internet connection
    soc = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    soc.connect(("8.8.8.8", 1))  # connect() for UDP doesn't send packets
    return soc.getsockname()[0]


def get_broadcast_addr() -> str:
    return "255.255.255.255"
