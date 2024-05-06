#utiliser pyOpenSSL
#https://www.youtube.com/watch?v=QhQFEmbRmsY

from datetime import datetime, timezone, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

server_IP = '18.224.18.157'
server_name = 'ca_server'

key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend,
)

name = x509.Name([
    x509.NameAttribute(NameOID.COMMON_NAME, server_name)
])

alt_names = [x509.DNSName(server_name)]
alt_names.append(x509.DNSName(server_IP))

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

with open('test_window_new.crt', 'wb') as c:
    c.write(my_cert_pem)

with open('test_window_new.key', 'wb') as c:
    c.write(my_key_pem)

