# src/security_controls.py
# Task 7 (Blue Team) - run every scenario through verify_order_packet() and log
# the result. Produces logs/blue_team.log showing:
#   - legitimate packets accepted
#   - spoofed / tampered / replayed packets rejected
#   - flooding flagged

import logging

from blue_defense import OrderMonitor, verify_order_packet, setup_logging
from order_packet import OrderPacket
from send_order import build_legit_order
from red_team_attacks import spoof_customer, tamper_order


def main():
    setup_logging("logs/blue_team.log")
    log = logging.getLogger("blue_team")
    log.info("=== Blue Team security controls - verifying all scenarios ===")

    # 1. Legitimate order -> ACCEPTED
    legit, _ = build_legit_order()
    verify_order_packet(legit, OrderMonitor(), "legitimate")

    # 2. Spoofing (customer_id changed) -> REJECTED (signature mismatch)
    base, _ = build_legit_order()
    verify_order_packet(spoof_customer(base, "customerB"), OrderMonitor(), "spoofing")

    # 3. Tampering (quantity changed) -> REJECTED (signature mismatch)
    base, _ = build_legit_order()
    verify_order_packet(tamper_order(base, new_quantity="999"), OrderMonitor(), "tampering")

    # 4. Replay (same packet twice through one monitor) -> 1st ACCEPT, 2nd REJECT
    base, _ = build_legit_order()
    replay_monitor = OrderMonitor()
    verify_order_packet(base, replay_monitor, "replay original")
    verify_order_packet(base, replay_monitor, "replay resend")

    # 5. Flooding (burst of packets) -> flagged once the rate is exceeded
    flood_pkt, _ = build_legit_order()
    order = flood_pkt[OrderPacket]
    flood_monitor = OrderMonitor()
    flagged_at, reason = None, ""
    for i in range(1, 101):
        accepted, reason = flood_monitor.check(order)
        if not accepted and reason.startswith("FLOODING"):
            flagged_at = i
            break
    log.info(f"REJECT  [flooding] {reason} (after {flagged_at} packets)")

    log.info("=== Done - full log saved to logs/blue_team.log ===")


if __name__ == "__main__":
    main()
