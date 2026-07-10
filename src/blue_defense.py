# src/blue_defense.py
# Blue Team defence for the order protocol.
# Task 6: detection logic (OrderMonitor).
# Task 7: security controls - verify_order_packet() + file logging.
#
# Controls implemented (Task 7 requirements):
#   - Signature verification  (integrity + authenticity)
#   - Identity binding         (customer_id must match its own public key)
#   - Replay detection         (duplicate signatures rejected)
#   - Timestamp freshness      (old packets rejected)
#   - Rate limiting            (flood flagged)

import time
import os
import logging

from crypto_utils import load_public_key, verify_signature
from order_packet import OrderPacket, signed_data_from_packet


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


# ---------------------------------------------------------------------------
# Task 7 - security controls: verify_order_packet() + logging
# ---------------------------------------------------------------------------

def setup_logging(path="logs/blue_team.log", name="blue_team"):
    """Configure a logger that writes both to a file and to the console."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    logger.handlers.clear()               # avoid duplicate handlers on re-run
    fmt = logging.Formatter("%(asctime)s  %(levelname)-6s  %(message)s", "%H:%M:%S")
    file_handler = logging.FileHandler(path, mode="w", encoding="utf-8")
    file_handler.setFormatter(fmt)
    stream_handler = logging.StreamHandler()
    stream_handler.setFormatter(fmt)
    logger.addHandler(file_handler)
    logger.addHandler(stream_handler)
    return logger


def verify_order_packet(pkt, monitor, scenario="", logger_name="blue_team"):
    """Blue Team control: verify one packet, log the result, return (ok, reason).

    Accepts either a full IP/UDP/OrderPacket or a bare OrderPacket.
    """
    order = pkt[OrderPacket] if pkt.haslayer(OrderPacket) else pkt
    accepted, reason = monitor.check(order)

    logger = logging.getLogger(logger_name)
    tag = "ACCEPT" if accepted else "REJECT"
    label = f"[{scenario}] " if scenario else ""
    logger.info(f"{tag}  {label}{reason}")
    return accepted, reason
