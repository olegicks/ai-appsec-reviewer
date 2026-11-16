import c104


def start_rtu(tls_config):
    server = c104.Server(ip="0.0.0.0", port=19998, transport_security=tls_config)
    server.add_station(common_address=47)
    server.start()
