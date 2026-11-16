from pymodbus.client import ModbusTlsClient


def poll(host, sslctx):
    client = ModbusTlsClient(host, port=802, sslctx=sslctx)
    client.connect()
    return client.read_input_registers(0, count=4)
