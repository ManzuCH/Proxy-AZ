import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def generate_shared_secret():
    """Generates a 16-byte shared secret for AES."""
    return os.urandom(16)

def encrypt_secret(public_key_bytes, secret):
    """
    Encrypts the shared secret using the server's public key (RSA).
    The public_key_bytes usually come in X.509 format (ASN.1 DER).
    """
    public_key = serialization.load_der_public_key(
        public_key_bytes,
        backend=default_backend()
    )
    encrypted = public_key.encrypt(
        secret,
        padding.PKCS1v15()
    )
    return encrypted

def make_digest(server_id, shared_secret, public_key):
    """
    Computes the server hash for Yggdrasil authentication.
    MessageDigest.getInstance("SHA-1").update(...)
    """
    sha1 = hashes.Hash(hashes.SHA1(), backend=default_backend())
    sha1.update(server_id.encode('utf-8'))
    sha1.update(shared_secret)
    sha1.update(public_key)
    digest = sha1.finalize()
    return digest

def java_hex_digest(digest):
    """
    Converts a Python SHA-1 digest to the format Minecraft expects (Java BigInteger style).
    """
    d = int.from_bytes(digest, byteorder='big', signed=True)
    if d < 0:
        return '-{:x}'.format(-d)
    else:
        return '{:x}'.format(d)

class AESCipher:
    """
    Handles CFB8 encryption/decryption state.
    """
    def __init__(self, key):
        self.key = key
        # Minecraft uses AES/CFB8/NoPadding with IV=Key
        self.cipher = Cipher(algorithms.AES(key), modes.CFB8(key), backend=default_backend())
        self.encryptor = self.cipher.encryptor()
        self.decryptor = self.cipher.decryptor()

    def encrypt(self, data):
        return self.encryptor.update(data)

    def decrypt(self, data):
        return self.decryptor.update(data)
