# src/test_crypto.py
# Proves signing and verification work.

from crypto_utils import (
    load_private_key, load_public_key,
    sign_data, verify_signature,
)

a_private = load_private_key("keys/customerA_private.pem")
a_public = load_public_key("keys/customerA_public.pem")
b_public = load_public_key("keys/customerB_public.pem")

message = b"customer_id=A;order_id=1001;item_id=55;quantity=2"

signature = sign_data(message, a_private)
print("[+] Message signed by Customer A")

# Test 1: valid signature, correct key
print("Test 1 (valid, A's key):     ",
      verify_signature(message, signature, a_public), "  (expected True)")

# Test 2: tampered data
tampered = b"customer_id=A;order_id=1001;item_id=55;quantity=999"
print("Test 2 (tampered data):      ",
      verify_signature(tampered, signature, a_public), "  (expected False)")

# Test 3: wrong public key
print("Test 3 (wrong key, B's key): ",
      verify_signature(message, signature, b_public), "  (expected False)")
