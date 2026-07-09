# src/order_packet.py
# Task 4 - Custom Scapy layer for the secure order protocol (OrderPacket).
# Fields follow our Task 2 design (IT Security Threat Modelling report).
#
# Signed data (from Task 2):
#     customer_id | order_id | item_id | quantity | timestamp
# The signature field itself is NOT signed - it is created AFTER signing.

from scapy.all import Packet, StrFixedLenField, bind_layers, UDP

# Port used for order traffic on the loopback interface (same as the Task 1 test).
ORDER_PORT = 9999

# RSA-2048 + pkcs1_15 signatures are always exactly 256 bytes.
SIG_LEN = 256


class OrderPacket(Packet):
    name = "OrderPacket"
    # Fixed-length fields keep the layout unambiguous on the wire, so signing
    # and verifying always operate on exactly the same bytes.
    fields_desc = [
        StrFixedLenField("customer_id", b"", 16),
        StrFixedLenField("order_id",    b"", 12),
        StrFixedLenField("item_id",     b"", 12),
        StrFixedLenField("quantity",    b"", 8),
        StrFixedLenField("timestamp",   b"", 20),
        StrFixedLenField("signature",   b"", SIG_LEN),
    ]


# Let Scapy automatically dissect our custom layer on the order port.
bind_layers(UDP, OrderPacket, dport=ORDER_PORT)


def build_signed_data(customer_id, order_id, item_id, quantity, timestamp) -> bytes:
    """Canonical byte string that gets signed / verified.

    This MUST be built the exact same way on the signing side (Task 4) and the
    verifying side (Task 7), otherwise even a valid packet fails verification.
    Matches the "customer_id | order_id | item_id | quantity | timestamp"
    definition from our Task 2 report.
    """
    return f"{customer_id}|{order_id}|{item_id}|{quantity}|{timestamp}".encode()


def _clean(value) -> str:
    """Strip the null padding that StrFixedLenField adds and return a str."""
    if isinstance(value, bytes):
        return value.rstrip(b"\x00").decode()
    return str(value)


def signed_data_from_packet(pkt) -> bytes:
    """Rebuild the canonical signed data from a received OrderPacket."""
    return build_signed_data(
        _clean(pkt.customer_id),
        _clean(pkt.order_id),
        _clean(pkt.item_id),
        _clean(pkt.quantity),
        _clean(pkt.timestamp),
    )
