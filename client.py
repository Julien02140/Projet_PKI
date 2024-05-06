import paho.mqtt.client as mqtt
import paho.mqtt
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

client_name = "client1"

# Générer une paire de clés RSA pour le client
key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
)

name = x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, client_name)
])

# Créer une demande de signature de certificat (CSR)
csr = (
    x509.CertificateSigningRequestBuilder()
        .subject_name(name).sign(key, hashes.SHA256())
)

# Exporter le CSR au format PEM
csr_pem = csr.public_bytes(serialization.Encoding.PEM)

# Enregistrer le CSR dans un fichier
with open("csr.pem", "wb") as f:
    f.write(csr_pem)

# Paramètres MQTT
mqtt_broker_address = "194.57.103.203"
mqtt_broker_port = 1883
mqtt_client_id = "ca_client_julien_hugo"
topic = "vehicule/JH"

USE_VERSION2_CALLBACKS = not paho.mqtt.__version__.startswith("1.")

if USE_VERSION2_CALLBACKS:
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, mqtt_client_id)
else:
    client = mqtt.Client(mqtt_client_id)

print("connecting to broker")

if client.connect("194.57.103.203",1883,60) != 0:
    print("Problème de connexion avec le broker")

client.publish(topic, "test1")
print("envoie message test 1")
client.loop_forever()
