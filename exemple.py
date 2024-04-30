from OpenSSL import crypto
import base64

RSA = crypto.TYPE_RSA
key_size = 3072

def getKeySet():
    key = crypto.PKey()
    cert = crypto.X509()
    crypto.PKey.generate_key(key,RSA,key_size)
    cert.set_pubkey(key)
    return key, cert

def sender(message, key):
    MAC = crypto.sign(key, message.encode(), "sha256")
    print(len(MAC))
    outbound = message.encode() + MAC
    return outbound

private_key, public_key = getKeySet()
message = "Hello alice"
outbound = sender(message, private_key)
print(outbound)