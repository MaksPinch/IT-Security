# src/blue_defense.py
# Task 6 (Blue Team) - detection logic for incoming OrderPackets.
# This first version gives the "detection evidence" for each attack in Task 6.
# In Task 7 we extend it with file logging and rate limiting.

import time

from crypto_utils import load_public_key, verify_signature
from order_packet import signed_data_from_packet


def _clean(value) -> str:
    if isinstance(value, bytes):
        return value.rstrip(b"\x00").decode()
    return str(value)


class OrderMonitor:
    """Checks each OrderPacket and returns (accepted: bool, reason: str)."""

    def __init__(self, fresh_window=120, flood_threshold=20, flood_window=5.0):
        self.fresh_window = fresh_window          # max packet age (seconds)
        self.flood_threshold = flood_threshold    # packets allowed per window
        self.flood_window = flood_window          # sliding window (seconds)
        self.seen_signatures = set()              # for replay detection
        self.arrivals = []                        # arrival times for rate detection

    def check(self, order, now=None):
        if now is None:
            now = time.time()

        # --- FLOODING: too many packets in the sliding window ---
        self.arrivals.append(now)
        self.arrivals = [t for t in self.arrivals if now - t <= self.flood_window]
        if len(self.arrivals) > self.flood_threshold:
            return False, "FLOODING - packet rate exceeded"

        # --- Identity binding: use the public key of the claimed customer ---
        customer_id = _clean(order.customer_id)
        try:
            public_key = load_public_key(f"keys/{customer_id}_public.pem")
        except FileNotFoundError:
            return False, f"SPOOFING - unknown customer '{customer_id}'"

        # --- Integrity / authenticity: the RSA signature must verify ---
        data = signed_data_from_packet(order)
        if not verify_signature(data, order.signature, public_key):
            return False, "TAMPERING/SPOOFING - signature does not match"

        # --- REPLAY: the same signature was seen before ---
        signature = bytes(order.signature)
        if signature in self.seen_signatures:
            return False, "REPLAY - duplicate packet"
        self.seen_signatures.add(signature)

        # --- Freshness: reject packets that are too old ---
        try:
            ts = int(_clean(order.timestamp))
        except ValueError:
            return False, "REPLAY - invalid timestamp"
        if now - ts > self.fresh_window:
            return False, "REPLAY - stale timestamp"

        return True, "ACCEPTED - legitimate order"
