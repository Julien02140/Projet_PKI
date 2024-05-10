import paho.mqtt.client as mqtt
import paho.mqtt
import sys, json
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
from cryptography.x509.oid import NameOID

numero_vendeur = sys.argv[1]
mqtt_broker_address = "194.57.103.203"
mqtt_broker_port = 1883
mqtt_client_id = "veudeur_client_julien_hugo"
topic = f"vehicule/JH/vendeur{numero_vendeur}" # ajouter le numéro de client en argument
topic_ca = "vehicule/JH/ca"
topic_client = "vehicule/JH/client"

def generate_csr():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, f"vendeur{numero_vendeur}"),
    ])

    csr = x509.CertificateSigningRequestBuilder().subject_name(
        name
    ).sign(private_key, hashes.SHA256())

    csr_pem = csr.public_bytes(serialization.Encoding.PEM)

    with open(f"csr_vendeur{numero_vendeur}.pem", "wb") as f:
        f.write(csr_pem)

    public_key = private_key.public_key()

    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_key_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    with open(f"private_key_vendeur{numero_vendeur}.pem", "wb") as f:
        f.write(private_key_pem)

    with open(f"public_key_vendeur{numero_vendeur}.pem", "wb") as f:
        f.write(public_key_pem)

USE_VERSION2_CALLBACKS = not paho.mqtt.__version__.startswith("1.")

if USE_VERSION2_CALLBACKS:
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, mqtt_client_id)
else:
    client = mqtt.Client(mqtt_client_id)

def on_message(client, userdata, msg):
    json_data = msg.payload.decode('utf-8')
    message = json.loads(json_data)
    if message['type'] == 'connexion_acceptee':
        print("common\n")
        generate_csr()
        with open(f"csr_vendeur{numero_vendeur}.pem", "rb") as f:
            contenu = str(f.read())
        reponse = {
            'type': 'demande_certificat',
            'id': f'vendeur{numero_vendeur}',
            'csr': contenu
        }
        json_data = json.dumps(reponse)
        client.publish(topic_ca,json_data)
    if message['type'] == 'envoi_certificat':
        print("common\n")
        cert = message.get('certificat', None)
        cert = eval(cert.encode('utf-8'))
        with open(f"cert_vendeur{numero_vendeur}.pem", "wb") as f:
            f.write(cert)

    # received_data = msg.payload.decode().split(',')
    # type_demande = received_data[0]
    # contenu = received_data[1]

    # if type_demande == 'retour_certificat':
    #     print("Message reçu sur le sujet/topic "+msg.topic)
    #     with open(f'cert_vendeur{numero_vendeur}.crt', 'wb') as c:
    #         c.write(contenu)
    # elif type_demande == 'demande_certificat':
    #     with open(f'cert_vendeur{numero_vendeur}.crt', 'r') as f:
    #         certificat = f.read()
    #         client.publish(topic_client+contenu, ','.join(map(str, ['retour_certificat',certificat])))


    

def on_connect(client, userdata, flags, reason_code, properties):
    print("Connecté au broker MQTT avec le code de retour:", reason_code)
    client.subscribe(topic)

client.on_connect = on_connect
client.on_message = on_message
if client.connect("194.57.103.203",1883,60) != 0:
    print("Problème de connexion avec le broker")

# client.publish(topic_ca, ','.join(map(str, ['demande_certificat',numero_vendeur])))
message = {
    'type': 'demande_connexion',
    'id': f'vendeur{numero_vendeur}'
}
json_data = json.dumps(message)
client.publish(topic_ca,json_data)
client.loop_forever()