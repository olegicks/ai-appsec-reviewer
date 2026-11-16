import c104


def start_rtu():
    server = c104.Server(ip="0.0.0.0", port=2404)
    server.add_station(common_address=47)
    server.start()
