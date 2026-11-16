def apply_setpoint(client, request):
    value = int(request.json["setpoint"])
    client.write_register(40001, value, slave=1)
