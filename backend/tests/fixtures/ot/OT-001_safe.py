from pymodbus.client import ModbusTlsClient


def read_level(sslctx):
    client = ModbusTlsClient("plc.local", port=802, sslctx=sslctx, timeout=3)
    client.connect()
    return client.read_holding_registers(0, count=2)
