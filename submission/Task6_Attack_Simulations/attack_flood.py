# src/attack_flood.py
# Task 6 - Attack 4: FLOODING.
# The attacker sends many packets as fast as possible (denial-of-service style).
# Blue Team flags the abnormal packet rate.

import time
from scapy.all import send

from send_order import build_legit_order
from order_packet import OrderPacket
from blue_defense import OrderMonitor

N = 100   # number of packets to flood


def main():
    base, _ = build_legit_order()

    print(f"[RED] FLOODING: sending {N} packets to 127.0.0.1:9999 as fast as possible")
    send(base, count=N, inter=0)
    print(f"[RED] Sent {N} packets")

    # Blue Team: feed the same burst through the monitor to show the rate alarm
    monitor = OrderMonitor()
    now = time.time()
    flagged_at = None
    for i in range(N):
        accepted, reason = monitor.check(base[OrderPacket], now=now)
        if not accepted and reason.startswith("FLOODING"):
            flagged_at = i + 1
            break
    print(f"[BLUE] FLOODING detected after {flagged_at} packets in the time window")


if __name__ == "__main__":
    main()
