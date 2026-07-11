# Task 8 — Evidence Collection

Wireshark evidence for all five scenarios (one legitimate order + four attacks).
For each packet the key field is annotated and a short explanation is given from
both the Red Team (attack) and Blue Team (detection) perspective. Matching capture
files (`.pcapng`) are in the `captures/` folder of the project.

## 1. Legitimate Order — `Task4_wireshark_legit_packet.png`
**Key fields:** customer_id, order_id, item_id, quantity, timestamp + 256-byte signature.
A valid order from Customer A. The payload shows the fields in clear text
(`customerA | 1001 | 55 | 2 | timestamp`) followed by the RSA signature, which verifies
against Customer A's public key. This is the baseline for comparison.

## 2. Spoofing — `Task6_spoof_wireshark.png`
**Key field:** customer_id.
The attacker changed customer_id from `customerA` to `customerB` (byte 41 -> 42) without
being able to re-sign. Identity binding verifies with the claimed customer's public key,
so the mismatched signature is detected and the packet is rejected.

## 3. Tampering — `Task6_tamper_wireshark.png`
**Key field:** quantity.
The attacker changed quantity from `2` to `999` (bytes 39 39 39). Because quantity is a
signed field, the change breaks the RSA signature and the packet is rejected.

## 4. Replay — `Task6_replay_wireshark.png`
**Key evidence:** two identical Len=324 packets ~1 second apart.
The attacker re-sent an unchanged, validly signed packet. The signature is still valid,
so replay is detected by duplicate-signature tracking and the timestamp freshness check:
the first packet is accepted, the identical resend is rejected.

## 5. Flooding — `Task6_flood_wireshark.png`
**Key evidence:** a burst of ~100 packets in a fraction of a second.
The attacker sent many packets as fast as possible (DoS style). A rate-limiting control
counts packets in a sliding window and flags the abnormal rate (triggered after 21 packets).

## Summary
Tampering and spoofing are stopped by the RSA signature, replay by duplicate/timestamp
detection, and flooding by rate limiting. Matching terminal screenshots (`Task6_*_terminal.png`)
and the log files (`logs/blue_team.log`) provide the Blue Team detection evidence.
