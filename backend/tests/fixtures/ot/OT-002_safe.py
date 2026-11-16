MAX_SETPOINT = 1200


def apply_setpoint(client, request):
    value = int(request.json["setpoint"])
    if not 0 <= value <= MAX_SETPOINT:
        raise ValueError("setpoint out of range")
    client.write_register(40001, value, slave=1)
