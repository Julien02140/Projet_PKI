import paho.mqtt.client as mqtt

#informations du serveur MQTT
broker_address = "194.57.103.203"
port = 1883
topic = "vehicule"

# Création d'un client MQTT
client = mqtt.Client()

# Connexion au broker MQTT
client.connect(broker_address, port)

# Publication de messages sur le sujet/topic "vehicule"
# Vous pouvez adapter cette partie pour publier les détails des véhicules
# Par exemple, publier le modèle, l'année, le prix, etc.
client.publish(topic, "Nouveau véhicule en vente: Modèle X, Année 2023, Prix: 25000€")

# Déconnexion du broker MQTT
client.disconnect()