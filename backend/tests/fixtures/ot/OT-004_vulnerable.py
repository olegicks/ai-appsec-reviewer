from asyncua import Client


async def read_temperature():
    client = Client(url="opc.tcp://scada.local:4840/freeopcua/server/", timeout=4)
    async with client:
        node = client.get_node("ns=2;i=2")
        return await node.read_value()
