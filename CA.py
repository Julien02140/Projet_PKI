#utiliser pyOpenSSL
#https://www.youtube.com/watch?v=QhQFEmbRmsY
#pour les communication, en https on peut creer une api flask
#mais pour le projet, on utilise des fils mqtt
import paho.mqtt.client as mqtt
import paho.mqtt
import ssl, time, inspect, os
from datetime import datetime, timezone, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

#server_IP = '18.224.18.157'
server_name = 'ca_server_julien_hugo'

key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend,
)

name = x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, server_name)
])

alt_names = [x509.DNSName(server_name)]
#alt_names.append(x509.DNSName(server_IP))

#elle peut émettre des certificats, si on met path_length=0, elle ne peut pas
#emettre de certificat, il faut laisser à None
basic_contraints = x509.BasicConstraints(ca=True, path_length=None)
now = datetime.now(timezone.utc)

cert = (
    x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1000)
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=355)) #valide pendant un ans
        .add_extension(basic_contraints,True)
        .add_extension(x509.SubjectAlternativeName(alt_names), False)
        .sign(key, hashes.SHA256(), default_backend)
)

my_cert_pem = cert.public_bytes(encoding=serialization.Encoding.PEM)
my_key_pem = key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption(),
)

with open('ca_cert.crt', 'wb') as c:
    c.write(my_cert_pem)

with open('ca_key.key', 'wb') as c:
    c.write(my_key_pem)

#on doit aussi creer un fichier pem
#ce fichier contient le certificat et la clé privée
with open('ca_cert.pem','wb') as c:
    c.write(my_cert_pem)
    c.write(my_key_pem)

# nb_message_recu = 0


# Paramètres MQTT
mqtt_broker_address = "194.57.103.203"
mqtt_broker_port = 1883
mqtt_client_id = "ca_server_julien_hugo"
topic = "vehicule/JH"


USE_VERSION2_CALLBACKS = not paho.mqtt.__version__.startswith("1.")

if USE_VERSION2_CALLBACKS:
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, mqtt_client_id)
else:
    client = mqtt.Client(mqtt_client_id)  

# Connexion au broker MQTT avec TLS/SSL
print("connecting to broker")
#client.tls_set(ca_certs="ca_cert.crt", certfile="ca_cert.pem", keyfile="ca_key.key")
#client.tls_insecure_set(True)
if client.connect("194.57.103.203",1883,60) != 0:
    print("Problème de connexion avec le broker")

def on_message(client, userdata, msg):
    print("Message reçu sur le sujet/topic "+msg.topic+": "+str(msg.payload.decode()))
    # nb_message_recu = nb_message_recu + 1
    # print("nb message recu = ", nb_message_recu)

print( "Subscribing to topic",topic)
client.subscribe("vehicule/JH")

client.on_message=on_message

print("commence à écouter")

client.loop_forever()