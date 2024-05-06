from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

client_IP = '18.224.18.158'
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
