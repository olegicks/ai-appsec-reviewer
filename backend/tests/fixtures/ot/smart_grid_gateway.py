"""FICTIONAL demo: gateway for the imaginary "Northfield 110/20 kV" substation.

Deliberately insecure training sample. Do not deploy.
"""
import telnetlib

import paho.mqtt.client as mqtt
import requests
from pymodbus.client import ModbusTcpClient

RTU_IP = "10.40.2.15"
MODBUS_PORT = 502
RTU_USER = "admin"
RTU_PASSWORD = "admin"

plc = ModbusTcpClient(RTU_IP, port=MODBUS_PORT)


def on_message(client, userdata, msg):
    # Operator setpoints arrive over MQTT and go straight to the feeder breaker controller.
    setpoint = int(msg.payload)
    plc.write_register(40010, setpoint, slave=1)


def push_to_historian(payload):
    requests.post("https://historian.grid.local/api/ingest", json=payload, verify=False, timeout=5)


def reset_rtu():
    session = telnetlib.Telnet(RTU_IP, 23)
    session.write(RTU_USER.encode() + b"\n" + RTU_PASSWORD.encode() + b"\n")


broker = mqtt.Client(client_id="substation-gw")
broker.on_message = on_message
broker.connect("broker.grid.local", 1883)
broker.subscribe("grid/#")
broker.loop_forever()
