import paho.mqtt.client as mqtt
import paho.mqtt

mqtt_client_id= "1"

def on_connect(client, userdata, flags, reason_code, properties):
    print("Connecté au broker MQTT avec le code de retour:", reason_code)

USE_VERSION2_CALLBACKS = not paho.mqtt.__version__.startswith("1.")

if USE_VERSION2_CALLBACKS:
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=mqtt_client_id)
else:
    client = mqtt.Client(client_id=mqtt_client_id)

client.on_connect = on_connect
if client.connect("194.57.103.203",1883,60) != 0:
    print("Problème de connexion avec le broker")
client.publish("vehicule/JH", "test1")
print("envoie message test 1")

client.loop_forever()
