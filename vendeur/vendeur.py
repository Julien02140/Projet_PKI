import paho.mqtt.client as mqtt
import paho.mqtt
import sys

numero_vendeur = sys.argv[1]
mqtt_broker_address = "194.57.103.203"
mqtt_broker_port = 1883
mqtt_client_id = "veudeur_client_julien_hugo"
topic = f"vehicule/JH/vendeur{numero_vendeur}" # ajouter le numéro de client en argument
topic_ca = "vehicule/JH/ca"

USE_VERSION2_CALLBACKS = not paho.mqtt.__version__.startswith("1.")

if USE_VERSION2_CALLBACKS:
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, mqtt_client_id)
else:
    client = mqtt.Client(mqtt_client_id)

def on_message(client, userdata, msg):
    print("Message reçu sur le sujet/topic "+msg.topic)
    with open(f'cert_vendeur{numero_vendeur}.crt', 'wb') as c:
        c.write(msg.payload)

def on_connect(client, userdata, flags, reason_code, properties):
    print("Connecté au broker MQTT avec le code de retour:", reason_code)
    client.subscribe(topic)

client.on_connect = on_connect
client.on_message = on_message
if client.connect("194.57.103.203",1883,60) != 0:
    print("Problème de connexion avec le broker")
client.publish(topic_ca,numero_vendeur)
client.loop_forever()