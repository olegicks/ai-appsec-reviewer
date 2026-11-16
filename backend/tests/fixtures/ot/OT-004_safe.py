from asyncua import Client
from asyncua.crypto.security_policies import SecurityPolicyBasic256Sha256


async def read_temperature():
    client = Client(url="opc.tcp://scada.local:4840/freeopcua/server/", timeout=4)
    await client.set_security(
        SecurityPolicyBasic256Sha256,
        certificate="client.der",
        private_key="client.pem",
        server_certificate="server.der",
    )
    async with client:
        node = client.get_node("ns=2;i=2")
        return await node.read_value()
