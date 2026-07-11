# src/attack_tamper.py
# Task 6 - Attack 2: TAMPERING.
# The attacker changes the order contents (quantity 2 -> 999). Any change to a
# signed field breaks the signature -> Blue Team rejects it.

import time
from scapy.all import send

from send_order import build_legit_order
from order_packet import OrderPacket
from red_team_attacks import tamper_order
from blue_defense import OrderMonitor


def build():
    base, _ = build_legit_order()
    return tamper_order(base, new_quantity="999")


def main():
    attack = build()
    print("[RED] TAMPERING: quantity 2 -> 999 (signature NOT re-signed)")
    send(attack)
    print("[RED] Tampered packet sent to 127.0.0.1:9999")

    accepted, reason = OrderMonitor().check(attack[OrderPacket], now=int(time.time()))
    print(f"[BLUE] {reason}")


if __name__ == "__main__":
    main()
