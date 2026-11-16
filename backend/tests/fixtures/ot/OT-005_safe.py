import os
import ssl

import paho.mqtt.client as mqtt

client = mqtt.Client(client_id="feeder-7")
client.tls_set(ca_certs="ca.pem", cert_reqs=ssl.CERT_REQUIRED)
client.username_pw_set("feeder-7", password=os.environ["MQTT_PASSWORD"])
client.connect("broker.grid.local", 8883, keepalive=30)
client.subscribe("substation/feeder-7/telemetry")
client.loop_forever()
