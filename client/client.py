import paho.mqtt.client as mqtt
import paho.mqtt
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from datetime import datetime, timezone, timedelta
import sys

client_name = "client1"


def validate_certificate(cert_pem, ca_cert_pem):
    pass
# Générer une paire de clés RSA pour le client
# key = rsa.generate_private_key(
#     public_exponent=65537,
#     key_size=2048,
# )

# name = x509.Name([
#     x509.NameAttribute(NameOID.COMMON_NAME, client_name)
# ])

# # Créer une demande de signature de certificat (CSR)
# csr = (
#     x509.CertificateSigningRequestBuilder()
#         .subject_name(name).sign(key, hashes.SHA256())
# )

# # Exporter le CSR au format PEM
# csr_pem = csr.public_bytes(serialization.Encoding.PEM)

# # Enregistrer le CSR dans un fichier
# with open("csr.pem", "wb") as f:
#     f.write(csr_pem)
def verify_certificate(cert_pem):
    # Charger le certificat à valider
    cert = x509.load_pem_x509_certificate(cert_pem, default_backend())
    
    # Vérifier si le certificat est encore valide
    now = datetime.now(timezone.utc)
    if now < cert.not_valid_before or now > cert.not_valid_after:
        return False, "Le certificat n'est pas dans sa période de validité."

    # Vérifier la signature du certificat en utilisant la clé publique du certificat
    try:
        # Obtenez la clé publique du certificat
        public_key = cert.public_key()

        # Vérifiez la signature du certificat
        public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm,
        )
    except Exception as e:
        return False, f"La signature du certificat n'est pas valide : {e}"
    return True, "Le certificat est valide."

# Paramètres MQTT
numero_client = sys.argv[1]
mqtt_broker_address = "194.57.103.203"
mqtt_broker_port = 1883
mqtt_client_id = "ca_client_julien_hugo"
topic = f"vehicule/JH/client{numero_client}" # ajouter le numéro de client en argument

USE_VERSION2_CALLBACKS = not paho.mqtt.__version__.startswith("1.")

if USE_VERSION2_CALLBACKS:
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, mqtt_client_id)
else:
    client = mqtt.Client(mqtt_client_id)

def on_message(client, userdata, msg):
    received_data = msg.payload.decode().split(',')
    type_demande = received_data[0]
    contenu = received_data[1]
    if type_demande == 'retour_certificat':
        print("Message reçu sur le sujet/topic "+msg.topic)
        print(verify_certificate(contenu))

def on_connect(client, userdata, flags, reason_code, properties):
    print("Connecté au broker MQTT avec le code de retour:", reason_code)
    client.subscribe(topic)

client.on_connect = on_connect
client.on_message = on_message
if client.connect("194.57.103.203",1883,60) != 0:
    print("Problème de connexion avec le broker")
client.publish("vehicule/JH/vendeur1", ','.join(map(str, ['demande_certificat',numero_client])))

client.loop_forever()