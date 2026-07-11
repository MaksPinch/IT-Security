# src/attack_spoof.py
# Task 6 - Attack 1: SPOOFING.
# The attacker takes a legitimate packet and changes customer_id, pretending to
# be another customer. They cannot re-sign (no private key), so the signature no
# longer matches -> Blue Team rejects it.

import time
from scapy.all import send

from send_order import build_legit_order
from order_packet import OrderPacket
from red_team_attacks import spoof_customer
from blue_defense import OrderMonitor


def build():
    base, _ = build_legit_order()
    return spoof_customer(base, "customerB")


def main():
    attack = build()
    print("[RED] SPOOFING: customer_id customerA -> customerB (signature NOT re-signed)")
    send(attack)
    print("[RED] Spoofed packet sent to 127.0.0.1:9999")

    accepted, reason = OrderMonitor().check(attack[OrderPacket], now=int(time.time()))
    print(f"[BLUE] {reason}")


if __name__ == "__main__":
    main()
