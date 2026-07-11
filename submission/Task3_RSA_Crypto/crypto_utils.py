# src/crypto_utils.py
# RSA signature functions (sign / verify).
# Same PyCryptodome library style as our class files,
# but using pkcs1_15 for SIGNING instead of PKCS1_OAEP for encryption.

from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256


def load_private_key(path: str):
    with open(path, "rb") as f:
        return RSA.import_key(f.read())


def load_public_key(path: str):
    with open(path, "rb") as f:
        return RSA.import_key(f.read())


def sign_data(data: bytes, private_key) -> bytes:
    # Hash with SHA-256, then sign the hash with the PRIVATE key
    h = SHA256.new(data)
    return pkcs1_15.new(private_key).sign(h)


def verify_signature(data: bytes, signature: bytes, public_key) -> bool:
    # Recompute hash and check against signature with the PUBLIC key
    h = SHA256.new(data)
    try:
        pkcs1_15.new(public_key).verify(h, signature)
        return True
    except (ValueError, TypeError):
        return False
