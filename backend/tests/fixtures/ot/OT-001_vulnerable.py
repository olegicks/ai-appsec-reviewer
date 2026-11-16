from pymodbus.client import ModbusTcpClient

PLC_HOST = "plc.local"


def read_level():
    client = ModbusTcpClient(PLC_HOST, port=502, timeout=3)
    client.connect()
    return client.read_holding_registers(0, count=2)
