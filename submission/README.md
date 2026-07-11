# Submission — organised by task

This folder contains **copies** of the deliverables, grouped per task, for hand-in.

> The runnable source of truth is the project's `src/` folder. The `.py` files here
> are copies for reading/grading — to actually run the code, use `src/` (the scripts
> import each other and expect to be run from the project root, e.g. `python src\send_order.py`).
> If you change code in `src/`, re-copy it here before submitting.

## Layout
- `Task1_Environment_Setup/` — scapy test script + setup/loopback screenshots
- `Task2_Protocol_Design/` — design write-up (no code)
- `Task3_RSA_Crypto/` — key generation, sign/verify functions + screenshots
- `Task4_Scapy_Implementation/` — OrderPacket class, sender, legit capture + screenshots
- `Task5_Wireshark_Analysis/` — legit capture + annotated packet-fields screenshot
- `Task6_Attack_Simulations/` — 4 attack scripts, monitor, 4 captures + 8 screenshots
- `Task7_Security_Controls/` — verify_order_packet + logging, bypass script, logs + screenshots
- `Task8_Evidence_Collection/` — 5 scenario screenshots + explanations.md
- `Task9_Final_Report/` — final report goes here

Note: RSA private keys are intentionally NOT included (they are secret and git-ignored).
They can be regenerated with `python src\generate_keys.py`.
