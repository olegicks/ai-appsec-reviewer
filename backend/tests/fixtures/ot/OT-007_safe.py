import os
import socket


def open_link():
    host = os.environ["PLC_HOST"]
    port = int(os.environ.get("PLC_PORT", "802"))
    return socket.create_connection((host, port), timeout=3)
