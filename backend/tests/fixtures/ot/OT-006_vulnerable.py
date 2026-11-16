import telnetlib


def reboot_rtu(host):
    session = telnetlib.Telnet(host, 23, 5)
    session.write(b"reboot\n")
