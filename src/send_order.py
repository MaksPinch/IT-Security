# src/send_order.py
# Task 4 (Blue Team) - build a legitimate, signed OrderPacket and send it to 127.0.0.1.
# Reuses the RSA sign/verify functions from Task 3 (crypto_utils.py).

import time
from scapy.all import IP, UDP, send

from crypto_utils import load_private_key, load_public_key, sign_data, verify_signature
from order_packet import (
    OrderPacket, ORDER_PORT, build_signed_data, signed_data_from_packet,
)


def build_legit_order():
    # --- 1. A legitimate order from Customer A ---
    customer_id = "customerA"
    order_id    = "1001"
    item_id     = "55"
    quantity    = "2"
    timestamp   = str(int(time.time()))   # current unix time

    # --- 2. Sign the order fields with Customer A's PRIVATE key ---
    signed_data = build_signed_data(customer_id, order_id, item_id, quantity, timestamp)
    a_private = load_private_key("keys/customerA_private.pem")
    signature = sign_data(signed_data, a_private)   # 256-byte RSA signature

    # --- 3. Build the custom OrderPacket layer ---
    order = OrderPacket(
        customer_id=customer_id.encode(),
        order_id=order_id.encode(),
        item_id=item_id.encode(),
        quantity=quantity.encode(),
        timestamp=timestamp.encode(),
        signature=signature,
    )

    # --- 4. Wrap in IP/UDP so it travels over the loopback interface ---
    packet = IP(dst="127.0.0.1") / UDP(sport=44444, dport=ORDER_PORT) / order
    return packet, signed_data


def main():
    packet, signed_data = build_legit_order()
    order = packet[OrderPacket]

    print("[+] Signed data:      ", signed_data.decode())
    print("[+] Signature length: ", len(order.signature), "bytes")

    # Blue Team self-check: the packet verifies against Customer A's PUBLIC key.
    # (full verify_order_packet() defence comes in Task 7)
    a_public = load_public_key("keys/customerA_public.pem")
    ok = verify_signature(signed_data_from_packet(order), order.signature, a_public)
    print("[+] Signature valid:  ", ok, "(expected True)")

    # Send it (start the Wireshark loopback capture with filter: udp.port == 9999)
    send(packet)
    print(f"[+] Legitimate signed OrderPacket sent to 127.0.0.1:{ORDER_PORT}")


if __name__ == "__main__":
    main()
