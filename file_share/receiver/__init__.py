import uvicorn

from .receiver_api import app
from ..definitions import PORT


def run_server(port: int = PORT) -> None:
    uvicorn.run(app, port=port)


__all__ = "app"
