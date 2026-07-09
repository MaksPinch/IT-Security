# src/generate_keys.py
# Based on generate_rsa_keys() from our class file RSA_AES.py.
# Extended to save keys to files for Customer A and Customer B.

from Crypto.PublicKey import RSA
import os

os.makedirs("keys", exist_ok=True)


def generate_rsa_keys():
    # Same as in RSA_AES.py from class
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    return private_key, public_key


def save_keys_for(name: str):
    private_key, public_key = generate_rsa_keys()

    with open(f"keys/{name}_private.pem", "wb") as f:
        f.write(private_key)   # private key -> used for SIGNING

    with open(f"keys/{name}_public.pem", "wb") as f:
        f.write(public_key)    # public key -> used for VERIFYING

    print(f"[+] Keys saved for {name}")


if __name__ == "__main__":
    save_keys_for("customerA")
    save_keys_for("customerB")
    print("[+] All keys generated in keys/ folder")
