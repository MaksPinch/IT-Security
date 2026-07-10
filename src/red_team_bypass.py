# src/red_team_bypass.py
# Task 7 (Red Team) - attempts to BYPASS the Blue Team controls.
# Each attempt is verified with verify_order_packet(); the log shows whether the
# control held (REJECT = bypass blocked).

import time
import logging

from blue_defense import OrderMonitor, verify_order_packet, setup_logging
from crypto_utils import load_private_key, sign_data
from order_packet import OrderPacket, build_signed_data
from send_order import build_legit_order


def main():
    setup_logging("logs/red_team_bypass.log", name="red_team")
    log = logging.getLogger("red_team")
    log.info("=== Red Team - attempts to bypass the Blue Team controls ===")

    # -- Bypass 1: forge a signature with the ATTACKER's own key --------------
    # Attacker (customerB) tries to order AS customerA, signing with B's key.
    log.info("Attempt 1: sign a customerA order with the attacker's (customerB) key")
    ts = str(int(time.time()))
    data = build_signed_data("customerA", "1001", "55", "2", ts)
    b_private = load_private_key("keys/customerB_private.pem")   # attacker's own key
    forged_sig = sign_data(data, b_private)
    forged = OrderPacket(
        customer_id=b"customerA", order_id=b"1001", item_id=b"55",
        quantity=b"2", timestamp=ts.encode(), signature=forged_sig,
    )
    verify_order_packet(forged, OrderMonitor(), "bypass-1 forged signature", "red_team")
    log.info("  -> identity binding uses customerA's PUBLIC key, so B's signature fails")

    # -- Bypass 2: refresh the timestamp on a captured packet ----------------
    # Attacker has an old (validly signed) packet and bumps the timestamp to now
    # to defeat the freshness check.
    log.info("Attempt 2: change the timestamp of a captured packet to look fresh")
    old_ts = str(int(time.time()) - 7200)                       # signed 2h ago
    old_data = build_signed_data("customerA", "1001", "55", "2", old_ts)
    a_private = load_private_key("keys/customerA_private.pem")
    valid_old_sig = sign_data(old_data, a_private)              # legit signature over OLD ts
    refreshed = OrderPacket(
        customer_id=b"customerA", order_id=b"1001", item_id=b"55",
        quantity=b"2", timestamp=str(int(time.time())).encode(),  # bumped to now
        signature=valid_old_sig,                                  # signature still over OLD ts
    )
    verify_order_packet(refreshed, OrderMonitor(), "bypass-2 refreshed timestamp", "red_team")
    log.info("  -> timestamp is a SIGNED field, so changing it breaks the signature")

    # -- Bypass 3: replay an exact, still-valid packet -----------------------
    log.info("Attempt 3: replay an exact, validly signed packet within the fresh window")
    base, _ = build_legit_order()
    monitor = OrderMonitor()
    verify_order_packet(base, monitor, "bypass-3 first send", "red_team")
    verify_order_packet(base, monitor, "bypass-3 replay", "red_team")
    log.info("  -> duplicate-signature detection rejects the resend")

    # -- Honest limitation ---------------------------------------------------
    log.info("Note: a SLOW attacker (under the rate threshold) evades flood detection,")
    log.info("      but every packet is still subject to signature/replay/freshness checks.")

    log.info("=== Done - full log saved to logs/red_team_bypass.log ===")


if __name__ == "__main__":
    main()
