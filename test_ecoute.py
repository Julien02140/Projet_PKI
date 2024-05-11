#utiliser mqtts, utilise tls
import paho.mqtt.client as mqtt
import paho.mqtt

mqtt_client_id= "2"

USE_VERSION2_CALLBACKS = not paho.mqtt.__version__.startswith("1.")

if USE_VERSION2_CALLBACKS:
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, client_id=mqtt_client_id)
else:
    client = mqtt.Client(client_id=mqtt_client_id)

if client.connect("194.57.103.203",1883,60) != 0:
    print("Problème de connexion avec le broker")

# Définition de la fonction de rappel pour la réception de messages
def on_message(client, userdata, msg):
    print("Message reçu sur le sujet/topic "+msg.topic+": "+str(msg.payload.decode()))

def on_connect(client, userdata, flags, reason_code, properties):
    print("Connecté au broker MQTT avec le code de retour:", reason_code)
    client.subscribe("vehicule/JH")

#client.subscribe("vehicule/JH")

client.on_message = on_message
client.on_connect = on_connect

print("commence à écouter")

client.loop_forever()
