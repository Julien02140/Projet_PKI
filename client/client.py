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
import time

# Paramètres MQTT
numero_client = sys.argv[1]
mqtt_broker_address = "194.57.103.203"
mqtt_broker_port = 1883
mqtt_client_id = "ca_client_julien_hugo"
topic = f"vehicule/JH/client{numero_client}"
#le client1 va communiqué avec le vendeur1
#c'est pour les différent scénarios
#scénario 1 : client1, vendeur1 : vérification du certificat (signature et date)
#scénario 2 : client2, vendeur2 : vérifier le certificat + vérifier si il est non révoqué (certificat non révoqué)
#scénario 3 : client3, vendeur3 : pareil que scénario 2 mais le certificat est révoqué
topic_vendeur = f"vehicule/JH/vendeur{numero_client}"
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

    if message['type'] == 'envoie_crl':
        #seul le client 1 et 2 arrive dans cet boucle
        #crl de la CA reu
        print("j'ai recu la crl \n")
        crl = message.get('crl', None)

        if crl != None:
        
            crl = crl.encode('utf-8')

            with open("crl.pem", "wb") as f:
                f.write(crl)
        
            #charger le certificat
            with open(f"cert_vendeur{numero_client}.pem", "rb") as f:
                cert_vendeur = f.read()

            cert_vendeur = x509.load_pem_x509_certificate(cert_vendeur, default_backend())

            #Le client vérifie si le certificat n'est pas dans la crl
            verifier_crl(cert_vendeur)
        
        else:
            #la crl est vide, aucun certificat n'a été révoqué par la CA pour le moment
            print("CRL vide \n")
            print("Certificat non révoqué \n")

    if message['type'] == 'retour_cle_publique_ca':
        print("cle publique de la CA reçu")
        public_key = message.get('public_key', None)
        public_key = public_key.encode('utf-8')
        with open(f"public_key_ca.pem", "wb") as f:
            f.write(public_key)

        #le client et la ca ont échangés leurs clés publiques
        #pour pouvoir échanger des messages sécurisés plus long
        #ou des fichiers, le client va aussi donné sa clé AES


        #le client chiffre les informations avec la clé publique de la CA
        id_chiffre = chiffre_message('ca',f'client{numero_client}')
        AES_key_chiffre = chiffre_message('ca',AES_key)
        AES_iv_chiffre = chiffre_message('ca',AES_iv)

        message_ca = {
            'type': 'envoie_cle_AES',
            'id': id_chiffre,
            'AES_key': AES_key_chiffre,
            'AES_iv': AES_iv_chiffre
        }

        json_data_ca = json.dumps(message_ca)
        client.publish(topic_vendeur,json_data_ca)

        #le client a recu la clé publique de la CA, il peut maintenant
        #vérifier les certificats signés par celle-ci
        #il peut maintenant demander au vendeur son certificat

        message_vendeur = {
            'type': 'demande_certificat_vendeur',
            'id': f'client{numero_client}',
            'public_key_client': public_key_pem.decode('utf-8')
        }

        json_data_vendeur = json.dumps(message_vendeur)
        client.publish(topic_vendeur,json_data_vendeur)

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
        #le client a recu le certificat
        print(f"certificat reçu de la part du {message['id']}")
        cert_str = message.get('certificat',None)
        cert_encode = cert_str.encode('utf-8')
        with open(f'cert_{message["id"]}.pem', 'wb') as c:
            c.write(cert_encode)
        
        cert = x509.load_pem_x509_certificate(cert_encode, default_backend())

        bool = verify_certificate(cert)

        if bool == True:
            print("certificat valide")
        else:
            print("certificat non valide")

        
        if(numero_client == "1"):
            print("fin du scénario 1")
        else:
            #le scénario 2 et 3 continue
            #le client demande la crl à la CA

            message_crl = {
                'type': 'demande_crl',
                'id': f'client{numero_client}' 
            }

            json_data = json.dumps(message_crl)
            client.publish(topic_ca, json_data)


def on_connect(client, userdata, flags, reason_code, properties):
    print("Connecté au broker MQTT avec le code de retour:", reason_code)
    client.subscribe(topic)

def verify_certificate(cert):
    # Vérifier si le certificat est encore valide
    now = datetime.now(timezone.utc)

    if now < cert.not_valid_before_utc or now > cert.not_valid_after_utc:
        return False, "Le certificat n'est pas dans sa période de validité."
    
    print("date du certificat valide")

    with open("public_key_ca.pem", "rb") as f:
        ca_public_key = f.read()
        
    ca_public_key = serialization.load_pem_public_key(ca_public_key, backend=default_backend())

    #On verifie la signature du certificat en utilisant la clé publique de la CA
    try:
        # Vérifiez la signature du certificat
        ca_public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm,
        )
        print("signature valide")
        return True
    except Exception as e:
        print(f"Erreur lors de la vérification de la signature : {e}")
        return False  # La signature est invalide 

client.on_connect = on_connect
client.on_message = on_message

#création d'un dossier confiance, cela stocke les certificats de confiance.
if not os.path.exists("trusted"):
    os.makedirs("trusted")

#création d'un dossier pour les certificats rejetés.
if not os.path.exists("rejected"):
    os.makedirs("rejected")

#consulte la crl et regarde si le certificat est révoqué
def verifier_crl(cert):
    #charger la clé publique de la CA
    with open("public_key_ca.pem", "rb") as f:
        ca_public_key = f.read()
    
    ca_public_key = serialization.load_pem_public_key(ca_public_key, backend=default_backend())

    #charge le fichier crl
    with open("crl.pem", "rb") as f:
        crl = f.read()

    crl = x509.load_pem_x509_crl(crl, default_backend())

    # Vérifier la signature de la CRL
    try:
        ca_public_key.verify(
            crl.signature,
            crl.tbs_certlist_bytes,
            padding.PKCS1v15(),
            crl.signature_hash_algorithm,
        )
        print("Signature de la CRL valide.")
    except Exception as e:
        print(f"Erreur lors de la vérification de la signature de la CRL : {e}")

    # Vérifier la validité de la CRL
    # now = datetime.now()
    # if now < crl.next_update or now > crl.last_update:
    #     print("La CRL est valide.")
    # else:
    #     print("La CRL a expiré ou n'est pas encore valide.")

    for revoked_cert in crl:
        if revoked_cert.serial_number == cert.serial_number:
            print("Le certificat est révoqué.")
            return True
    print("Le certificat n'est pas révoqué.")
    return False

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
    with open(f'key/private_key_client{numero_client}.pem', 'wb') as f:
        f.write(private_pem)

    with open(f'key/public_key_client{numero_client}.pem', 'wb') as f:
        f.write(public_pem)

def chiffre_message(id_receveur,message):
    with open(f'key/public_key_{id_receveur}.pem', 'rb') as f:
        public_key_pem = f.read()

    public_key = serialization.load_pem_public_key(
        public_key_pem,
        password=None,
    )

    #chiffrer le message
    message_chiffre = public_key.encrypt(
            message,
            padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return message_chiffre

def dechiffre_message(message):
    with open(f'key/private_key_client{numero_client}.pem', 'rb') as f:
        public_key_pem = f.read()
    
    private_key = serialization.load_pem_public_key(
        public_key_pem,
        password=None,
    )

    #dechiffrer le message
    message_dechiffre = private_key.decrypt(
            message,
            padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return message_dechiffre

    
#demande de la clé publique de la CA, le client en a besoin poour vérfifier la signature des certificats
# message_ca = {
#     'type': 'demande_cle_publique_ca',
#     'id': f'client{numero_client}' 
# }

# json_data = json.dumps(message_ca)
# client.publish(topic_ca,json_data)

print(f"client numero : {numero_client} démarre")

# client.loop_start()

generate_key()

#générer la clé AES
AES_key = os.urandom(32)
AES_iv = os.urandom(16) 

#après avoir générer ses clés, le client commence par demander
#à la CA sa clé pblique pour pouvoir vérifier les certificats
#le clien envoie aussi sa clé publique pour des communications sécurisés
with open(f'key/public_key_client{numero_client}.pem', 'rb') as f:
    public_key_pem = f.read()

message_ca = {
    'type': 'demande_cle_publique_ca',
    'id': f'client{numero_client}',
    'public_key_client': public_key_pem.decode('utf-8')
}

json_data_crl = json.dumps(message_ca)
client.publish(topic_ca, json_data_crl)

#envoyer_messages()

# client.loop_stop()
# client.publish(topic_vendeur1,json_data_vendeur)
client.loop_forever()