import paho.mqtt.client as mqtt

client = mqtt.Client(client_id="feeder-7")
client.connect("broker.grid.local", 1883, keepalive=30)
client.subscribe("substation/#")
client.loop_forever()
