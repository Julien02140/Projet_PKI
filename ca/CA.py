#utiliser pyOpenSSL
#https://www.youtube.com/watch?v=QhQFEmbRmsY
#pour les communication, en https on peut creer une api flask
#mais pour le projet, on utilise des fils mqtt
import paho.mqtt.client as mqtt
import paho.mqtt
import ssl, time, inspect, os, json
from datetime import datetime, timezone, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa,padding
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
from cryptography.x509 import load_pem_x509_certificate
import base64

# Paramètres MQTT
mqtt_broker_address = "194.57.103.203"
mqtt_broker_port = 1883
mqtt_client_id = "ca_server_julien_hugo"
topic = "vehicule/JH/ca"

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
    if message['type'] == 'test_public_key':
        print("demande de test de la cle de la part du client \n")
        
        with open("key/key_ca.key", "rb") as f:
            ca_key = f.read()

        private_key = serialization.load_pem_private_key(ca_key, password=None)

        msg = "hello world, voici un message signé avec ma cle"
        signature = private_key.sign(
            msg.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )

        reponse = {
            'type': 'retour_test_public_key',
            'content': msg,
            'signature': base64.b64encode(signature).decode('utf-8')
        }
        json_data = json.dumps(reponse)
        client.publish(f"vehicule/JH/{message['id']}",json_data)

    if message['type'] == 'demande_cle_publique_ca':
        print(f"demande de la clé publique de la part du {message['id']}")
        with open("pem/cert_ca.pem", "rb") as f:
            ca_cert = f.read()
        cert = x509.load_pem_x509_certificate(ca_cert, default_backend())
        public_key = cert.public_key()
        public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        reponse = {
            'type': 'retour_cle_publique_ca',
            'public_key': public_key_pem.decode('utf-8') #convertir en str 
        }
        json_data = json.dumps(reponse)
        client.publish(f"vehicule/JH/{message['id']}",json_data)
    if message['type'] == 'demande_connexion':
        print(f"demande de connexion reçu de la part du {message['id']}\n")
        reponse = {'type': 'connexion_acceptee'}
        json_data = json.dumps(reponse)
        client.publish(f"vehicule/JH/{message['id']}",json_data)
        print("envoie connexion actepte à vendeur")
    elif message['type'] == 'demande_certificat':
        print(f"demande de certificat de la part du {message['id']} \n")
        csr = message.get('csr', None)
        csr = eval(csr.encode('utf-8'))
        print("verification de la signature du csr")
        if verify_signature(csr):
            cert = str(emit_certificate(csr,message['id']))
            reponse = {
                'type': 'envoi_certificat',
                'certificat': cert
            }
            json_data = json.dumps(reponse)
            print("signature du csr correct")
            client.publish(f"vehicule/JH/{message['id']}",json_data)
        else: 
            print('Erreur avec la signature')
    # received_data = msg.payload.decode().split(',')
    # type_demande = received_data[0]
    # contenu = received_data[1]
    # if type_demande == 'demande_certificat':
    #     print(f"Message reçu de {contenu}")
    #     contenu = f'vendeur{contenu}'
    #     my_cert_pem = generate_certif(contenu)
    #     client.publish(f"vehicule/JH/{contenu}", ','.join(map(str, ['retour_certificat',my_cert_pem])))


def on_connect(client, userdata, flags, reason_code, properties):
    print("Connecté au broker MQTT avec le code de retour:", reason_code)
    client.subscribe(topic)

#server_IP = '18.224.18.157'
server_name = 'ca_server_julien_hugo'

# nb_message_recu = 0
def generate_certif_ca():
    key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend,
    )

    name = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, 'ca')
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
            .not_valid_after(now + timedelta(days=365))
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
    if not os.path.exists("certificat"):
        os.makedirs("certificat")
    if not os.path.exists("key"):
        os.makedirs("key")
    if not os.path.exists("pem"):
        os.makedirs("pem")

    with open(f'certificat/cert_ca.crt', 'wb') as c:
        c.write(my_cert_pem)

    with open(f'key/key_ca.key', 'wb') as c:
        c.write(my_key_pem)

    #on doit aussi creer un fichier pem
    #ce fichier contient le certificat et la clé privée
    with open(f'pem/cert_ca.pem','wb') as c:
        c.write(my_cert_pem)
        c.write(my_key_pem) 

def verify_signature(csr_file):
    csr = x509.load_pem_x509_csr(csr_file, default_backend())
    # Obtenir la signature et les informations de la demande de certificat
    signature = csr.signature
    tbs_certificate_bytes = csr.tbs_certrequest_bytes

    # Vérifier la signature
    try:
        csr.public_key().verify(
            signature,
            tbs_certificate_bytes,
            padding.PKCS1v15(),  # Utiliser le même padding que lors de la signature
            csr.signature_hash_algorithm,
        )
        return True  # La signature est valide
    except InvalidSignature:
        return False  # La signature est invalide

def add_certificat_crl(cert):
    with open("crl.pem", "rb") as f:
        crl = f.read()
    crl = x509.load_pem_x509_crl(crl, default_backend())
    builder = x509.CertificateRevocationListBuilder(crl)
    
    builder = builder.add_revoked_certificate(cert)

    with open("key_ca.key", "rb") as f:
        ca_key_pem = f.read()
    
    ca_private_key = serialization.load_pem_private_key(
        ca_key_pem,
        password=None,
        backend=default_backend()
    )

    crl = builder.sign(private_key=ca_private_key, algorithm=hashes.SHA256(), backend=default_backend())

    crl_serialize = crl.public_bytes(serialization.Encoding.PEM)

    with open("crl.pem", "wb") as f:
        f.write(crl_serialize)

def emit_certificate(csr_bytes,id):
    # Charger la clé privée de la CA
    with open("pem/cert_ca.pem", "rb") as f:
        ca_cert_pem = f.read()
    # with open("key/key_ca.key", "rb") as f:
    #     ca_key_pem = f.read()
    # ca_private_key = serialization.load_pem_private_key(
    #     ca_key_pem,
    #     password=None,
    #     backend=default_backend()
    # )

    # Générer une nouvelle clé RSA, pour simuler une signature falsifié
    private_key_false = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )

    # Sérialiser la clé privée au format PEM
    private_key_pem_false = private_key_false.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption(),
    )

    # Enregistrer la clé privée dans un fichier
    with open("private_key_false.pem", "wb") as f:
        f.write(private_key_pem_false)
    
    with open("private_key_false.pem", "rb") as f:
        false_key = f.read()

    private_key_false = serialization.load_pem_private_key(false_key, password=None)


    with open("key/key_ca.key", "rb") as f:
        ca_key = f.read()

    private_key = serialization.load_pem_private_key(ca_key, password=None)


    # Charger le CSR
    csr = x509.load_pem_x509_csr(csr_bytes, default_backend())

    # Charger le certificat de la CA
    ca_cert = x509.load_pem_x509_certificate(ca_cert_pem, default_backend())
    alt_names = [x509.DNSName(server_name)]
    basic_contraints = x509.BasicConstraints(ca=True, path_length=None)
    now = datetime.now(timezone.utc)
    # Signer le CSR avec la clé privée de la CA pour émettre le certificat
    cert_build = (
        x509.CertificateBuilder()
            .subject_name(csr.subject)
            .issuer_name(ca_cert.subject)
            .public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + timedelta(days=365))
            .add_extension(basic_contraints,True)
            .add_extension(x509.SubjectAlternativeName(alt_names), False)
            #.sign(private_key, hashes.SHA256(), default_backend())
    )

    cert = cert_build.sign(private_key, hashes.SHA256(), default_backend())

      
    # with open("key/key_ca.key", "rb") as f:
    #     ca_key = f.read()

    # private_key = serialization.load_pem_private_key(ca_key, password=None)
    # signature = private_key.sign(
    #     cert.encode('utf-8'),
    #     padding.PSS(
    #         mgf=padding.MGF1(hashes.SHA256()),
    #         salt_length=padding.PSS.MAX_LENGTH
    #     ),
    #     hashes.SHA256()
    # )


    # Retourner le certificat émis
    cert_bytes = cert.public_bytes(serialization.Encoding.PEM)
    with open(f'pem/cert_{id}.key', 'wb') as c:
        c.write(cert_bytes)
    return cert_bytes
    
generate_certif_ca()

#generer un dossier crl et un fichier vide pour la crl
if not os.path.exists("crl"):
    os.makedirs("crl")

with open("crl/crl.pem", "wb") as f:
    pass
# Connexion au broker MQTT avec TLS/SSL
#client.tls_set(ca_certs="ca_cert.crt", certfile="ca_cert.pem", keyfile="ca_key.key")
#client.tls_set("ca_cert.pem", tls_version=ssl.PROTOCOL_TLSv1_2, cert_reqs=ssl.CERT_NONE)
#client.tls_insecure_set(True)

client.on_message = on_message
client.on_connect = on_connect

print("démarrage CA")
    
client.loop_forever()