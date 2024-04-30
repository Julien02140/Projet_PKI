#communication ssl entre les noeuds, creer des sockets qui utilisent le protocole tls
1

from OpenSSL import crypto

def create_ca():
    # Générer une clé privée
    ca_key = crypto.PKey()
    ca_key.generate_key(crypto.TYPE_RSA, 2048)

    # Créer un certificat d'autorité de certification (CA)
    ca_cert = crypto.X509()
    ca_cert.set_version(2)  # version X.509v3
    ca_cert.set_serial_number(1)
    ca_cert.get_subject().CN = "Mon Autorité de Certification"
    ca_cert.set_issuer(ca_cert.get_subject())  # Auto-signé
    ca_cert.set_pubkey(ca_key)
    ca_cert.add_extensions([
        crypto.X509Extension(b"basicConstraints", True, b"CA:TRUE"),
        crypto.X509Extension(b"keyUsage", True, b"keyCertSign, cRLSign"),
        crypto.X509Extension(b"subjectKeyIdentifier", False, b"hash", subject=ca_cert),
    ])
    ca_cert.gmtime_adj_notBefore(0)
    ca_cert.gmtime_adj_notAfter(10 * 365 * 24 * 60 * 60)  # Valide pendant 10 ans
    ca_cert.sign(ca_key, 'sha256')

    # Écrire la clé privée et le certificat dans des fichiers PEM
    with open("ca_key.pem", "wb") as key_file:
        key_file.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, ca_key))
    with open("ca_cert.pem", "wb") as cert_file:
        cert_file.write(crypto.dump_certificate(crypto.FILETYPE_PEM, ca_cert))

if __name__ == "__main__":
    create_ca()
