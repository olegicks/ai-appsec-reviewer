import socket

PLC_IP = "192.168.10.20"
MODBUS_PORT = 502


def open_link():
    return socket.create_connection((PLC_IP, MODBUS_PORT), timeout=3)
