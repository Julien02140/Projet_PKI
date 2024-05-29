import paho.mqtt.client as mqtt
import paho.mqtt
import sys, json
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import sys,os,json

numero_vendeur = sys.argv[1]
mqtt_broker_address = "194.57.103.203"
mqtt_broker_port = 1883
mqtt_client_id = "veudeur_client_julien_hugo"
topic = f"vehicule/JH/vendeur{numero_vendeur}" # ajouter le numéro de client en argument
topic_ca = "vehicule/JH/ca"
topic_client = "vehicule/JH/client"

USE_VERSION2_CALLBACKS = not paho.mqtt.__version__.startswith("1.")

if USE_VERSION2_CALLBACKS:
    client = mqtt.Client(mqtt.CallbackAPIVersion.VERSION2, mqtt_client_id)
else:
    client = mqtt.Client(mqtt_client_id)

if client.connect(mqtt_broker_address,mqtt_broker_port,60) != 0:
    print("Problème de connexion avec le broker")

def on_message(client, userdata, msg):
    json_data = msg.payload.decode('utf-8')
    message = json.loads(json_data)
    if message['type'] == 'connexion_acceptee':
        print("connexion accepté reçu\n")
        print("génération du csr et envoie du csr à la CA")
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
        print("certificat recu de la part de la CA \n")
        cert = message.get('certificat', None)
        cert = eval(cert.encode('utf-8'))
        with open(f"cert_vendeur{numero_vendeur}.pem", "wb") as f:
            f.write(cert)

    if message['type'] == 'demande_certificat_vendeur':
        #premier message recu de la part du client
        #donc le le client donne sa clé publique pour ensuite communiquer de façon sécurisé

        #obtention de la clé publique du client
        print("cle publique du client recu")
        public_key = message.get('public_key_client', None)
        public_key = public_key.encode('utf-8')

        with open(f"key/public_key_{message['id']}.pem", "wb") as f:
            f.write(public_key)
        
        print(f"demande de certificat recu de la part du {message['id']}")

        with open(f'cert_vendeur{numero_vendeur}.pem', 'rb') as f:
            certificat = f.read()

        reponse = {
            'type': 'retour_demande_de_certificat',
            'id': f'vendeur{numero_vendeur}',
            'certificat': certificat.decode('utf-8')
        }

        json_data = json.dumps(reponse)
        print("envoie du certificat au client \n")
        client.publish(f"vehicule/JH/{message['id']}",json_data)

    if message['type'] == 'envoie_cle_AES':
        #Le vendeur recoit la clé AES du client
        #déchiffrer en utilisant la cle publique du vendeur

        id = message['id']
        AES_key = dechiffre_message(message['AES_key'])
        AES_iv = dechiffre_message(message['AES_iv'])

        with open(f'key/AES_key_{id}') as AES_key_file:
            AES_key_file.write(AES_key)

        with open(f'key/AES_iv_{id}') as AES_iv_file:
            AES_iv_file.write(AES_iv)

        print(f'cle AES recu de la part du {id}')

        message_client = {
            'type': 'AES_recu',
            'id': f'vendeur{numero_vendeur}',
        }

        json_data = json.dumps(message_client)
        print("envoie de la réponse au client, AES bien recu \n")
        client.publish(f"vehicule/JH/{id}",json_data)

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

def generate_csr():
    
    #charger la clé privée
    with open(f'key/private_key_vendeur{numero_vendeur}.pem', 'rb') as private_key_pem:
        private_key_pem.read()

    private_key = serialization.load_pem_private_key(private_key_pem, password=None)

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

def generate_key():
    #creation des clés publique et privé du client
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    # Écrire les clés dans des fichiers
    with open(f'key/private_key_vendeur{numero_vendeur}.pem', 'wb') as f:
        f.write(private_pem)

    with open(f'key/public_key_vendeur{numero_vendeur}.pem', 'wb') as f:
        f.write(public_pem)

def chiffrer_message(id_client,message):
    with open(f'key/public_key_{id_client}', 'rb') as f:
        public_key_pem = f.read()

    public_key = serialization.load_pem_public_key(
        public_key_pem,
        password=None,
    )

    #chiffrer le message
    message_chiffrer = public_key.encrypt(
            message,
            padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return message_chiffrer

def dechiffre_message(message):
    with open(f'key/private_key_vendeur_{numero_vendeur}', 'rb') as f:
        public_key_pem = f.read()
    
    private_key = serialization.load_pem_public_key(
        public_key_pem,
        password=None,
    )

    #dechiffrer le message
    message_dechiffrer = private_key.decrypt(
            message,
            padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return message_dechiffrer

def chiffre_message_AES(id_receveur,message):
    #le message doit être en byte pour âtre chiffré
    #ne fonctionne pas avec les strings
    with open(f'key/AES_key_{id_receveur}.bin', 'rb') as AES_key_file:
        AES_key_file.read()

    with open(f'key/AES_iv_{id_receveur}.bin', 'rb') as AES_iv_file:
        AES_iv_file.read()

    cipher = Cipher(algorithms.AES(AES_key_file), modes.CBC(AES_iv_file))
    encryptor = cipher.encryptor()
    ct = encryptor.update(message) + encryptor.finalize()

    return ct

def dechiffre_message_AES(id_envoyeur,message):
    with open(f'key/AES_key_{id_envoyeur}.bin', 'rb') as AES_key_file:
        AES_key_file.read()

    with open(f'key/AES_iv_{id_envoyeur}.bin', 'rb') as AES_iv_file:
        AES_iv_file.read()

    cipher = Cipher(algorithms.AES(AES_key_file), modes.CBC(AES_iv_file))

    decryptor = cipher.decryptor()
    message_dechiffre = decryptor.update(message) + decryptor.finalize()

    return message_dechiffre

client.on_message = on_message
client.on_connect = on_connect

#générer clé publique et privée
generate_key()

#générer clé AES pour la Ca
AES_key_ca = os.urandom(32)
AES_iv_ca = os.urandom(16) 

with open(f'key/AES_key_vendeur{numero_vendeur}_ca') as f:
    f.write(AES_key_ca)

with open(f'key/AES_iv_vendeur{numero_vendeur}_ca') as f:
    f.write(AES_iv_ca)


# client.publish(topic_ca, ','.join(map(str, ['demande_certificat',numero_vendeur])))
message = {
    'type': 'demande_connexion',
    'id': f'vendeur{numero_vendeur}',
    
}
json_data = json.dumps(message)
client.publish(topic_ca,json_data)

print(f"démarrage vendeur {numero_vendeur}")

client.loop_forever()