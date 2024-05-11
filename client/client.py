import paho.mqtt.client as mqtt
import paho.mqtt
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from datetime import datetime, timezone, timedelta
import sys,os,json
import base64

client_name = "client1"

# Paramètres MQTT
numero_client = sys.argv[1]
mqtt_broker_address = "194.57.103.203"
mqtt_broker_port = 1883
mqtt_client_id = "ca_client_julien_hugo"
topic = f"vehicule/JH/client{numero_client}" # ajouter le numéro de client en argument
topic_vendeur1 = "vehicule/JH/vendeur1"
topic_ca = "vehicule/JH/ca"

USE_VERSION2_CALLBACKS = not paho.mqtt.__version__.startswith("1.")

if USE_VERSION2_CALLBACKS:
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, mqtt_client_id)
else:
    client = mqtt.Client(mqtt_client_id)

if client.connect("194.57.103.203",1883,60) != 0:
    print("Problème de connexion avec le broker")

def on_message(client, userdata, msg):
    json_data = msg.payload.decode('utf-8')
    message = json.loads(json_data)
    if message['type'] == 'retour_cle_publique_ca':
        print("cle publique de la CA reçu")
        public_key = message.get('public_key', None)
        public_key = public_key.encode('utf-8')
        with open(f"public_key_ca.pem", "wb") as f:
            f.write(public_key)
        reponse = {
            'type': 'test_public_key',
            'id': f'client{numero_client}'
        }
        json_data = json.dumps(reponse)
        client.publish(topic_ca,json_data)
    if message['type'] == 'retour_test_public_key':
        print("message chiffre pour test reçu \n")
        msg = message['content']
        print(f"message reçu : {message['content']} \n")
        signature = message['signature']
        signature = base64.b64decode(signature)

        with open("public_key_ca.pem", "rb") as f:
            ca_public_key = f.read()
        
        ca_public_key = serialization.load_pem_public_key(ca_public_key, backend=default_backend())
        
        try:
            ca_public_key.verify(
                signature,
                msg.encode('utf-8'),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            print("La signature est valide.")
        except:
            print("La signature est invalide.")     

    if message['type'] == 'retour_demande_de_certificat':
        print(f"certificat reçu de la part du {message['id']}")
        cert = message.get('certificat',None)
        cert = cert.encode('utf-8')
        with open(f'cert_{message["id"]}.pem', 'wb') as c:
            c.write(cert)

        bool = verify_certificate(cert)
        if bool == True:
            print("certificat valide")
        else:
            print("certificat non valide")

def on_connect(client, userdata, flags, reason_code, properties):
    print("Connecté au broker MQTT avec le code de retour:", reason_code)
    client.subscribe(topic)


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
    # now = datetime.now(timezone.utc)
    # if now < cert.not_valid_before_utc or now > cert.not_valid_after_utc:
    #     return False, "Le certificat n'est pas dans sa période de validité."
    
    with open("public_key_ca.pem", "rb") as f:
            ca_public_key = f.read()
        
    ca_public_key = serialization.load_pem_public_key(ca_public_key, backend=default_backend())

    # Vérifier la signature du certificat en utilisant la clé publique du certificat
    try:
        # Obtenez la clé publique du certificat
        # public_key = cert.public_key()

        # Vérifiez la signature du certificat
        ca_public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm,
        )
    except Exception as e:
        return False, f"La signature du certificat n'est pas valide : {e}"
    return True, "Le certificat est valide."

client.on_connect = on_connect
client.on_message = on_message

#création d'un dossier confiance, cela stocke les certificats de confiance.
if not os.path.exists("trusted"):
    os.makedirs("trusted")

#création d'un dossier pour les certificats rejetés.
if not os.path.exists("rejected"):
    os.makedirs("rejected")


#demande de la clé publique de la CA, le client en a besoin poour vérfifier la signature des certificats
# message_ca = {
#     'type': 'demande_cle_publique_ca',
#     'id': f'client{numero_client}' 
# }

# json_data = json.dumps(message_ca)
# client.publish(topic_ca,json_data)

message_vendeur = {
    'type': 'demande_certificat_vendeur',
    'id': f'client{numero_client}'
}
json_data_vendeur = json.dumps(message_vendeur)
client.publish(topic_vendeur1,json_data_vendeur)

client.loop_forever()