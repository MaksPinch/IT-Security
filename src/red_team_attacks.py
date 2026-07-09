# src/red_team_attacks.py
# Task 4 (Red Team) - modifiable-field analysis + PREPARED attack scaffolds.
#
# The actual execution, Wireshark captures and screenshots are done in Task 6.
# Here we only identify what an attacker can change and prepare the scripts.
#
# Modifiable fields on the wire (everything except a forgeable signature):
#   customer_id -> SPOOFING   (pretend to be another customer)
#   item_id     -> TAMPERING  (swap the ordered item)
#   quantity    -> TAMPERING  (change amount / price impact)
#   order_id    -> TAMPERING  (duplicate / confuse order handling)
#   timestamp   -> REPLAY     (resend an old, still-signed packet)
#
# The signature field cannot be forged: any change to a SIGNED field makes
# verify_signature() fail (proven by the Task 3 tests). REPLAY is the exception -
# the packet is unchanged so the signature still verifies, which is exactly why a
# timestamp/nonce freshness check is needed in Task 7.

from order_packet import OrderPacket


def spoof_customer(packet, new_customer_id):
    """SPOOFING: change customer_id. Signature no longer matches -> Blue Team rejects."""
    p = packet.copy()
    p[OrderPacket].customer_id = new_customer_id.encode()
    return p


def tamper_order(packet, new_item_id=None, new_quantity=None):
    """TAMPERING: swap the item or change the quantity. Breaks the signature."""
    p = packet.copy()
    if new_item_id is not None:
        p[OrderPacket].item_id = new_item_id.encode()
    if new_quantity is not None:
        p[OrderPacket].quantity = new_quantity.encode()
    return p


def replay(packet):
    """REPLAY: resend an unchanged packet. Signature stays valid -> needs a freshness check."""
    return packet.copy()


def flood(packet, count):
    """FLOODING: prepare many copies to send quickly (DoS-style). Sending loop is Task 6."""
    return [packet.copy() for _ in range(count)]
