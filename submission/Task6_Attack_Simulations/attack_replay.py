# src/attack_replay.py
# Task 6 - Attack 3: REPLAY.
# The attacker resends an unchanged, legitimately signed packet. The signature
# is still valid, so only duplicate/timestamp detection stops it -> Blue Team
# accepts it the first time and rejects the identical resend.

import time
from scapy.all import send

from send_order import build_legit_order
from order_packet import OrderPacket
from blue_defense import OrderMonitor


def main():
    base, _ = build_legit_order()   # a real, validly signed packet
    monitor = OrderMonitor()
    now = int(time.time())

    print("[RED] REPLAY: capturing one legitimate packet and sending it twice")

    send(base)                                              # original
    _, reason1 = monitor.check(base[OrderPacket], now=now)
    print(f"[BLUE] 1st packet: {reason1}")

    time.sleep(1)

    send(base)                                              # replay (identical bytes)
    _, reason2 = monitor.check(base[OrderPacket], now=now + 1)
    print(f"[BLUE] 2nd packet: {reason2}")


if __name__ == "__main__":
    main()
