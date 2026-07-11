# Task 2 — Protocol Design

This is a design-only task (no code). The full protocol design is written up in
the final report (Task 9).

## OrderPacket fields
- `customer_id` — identifies the customer
- `order_id` — identifies the order
- `item_id` — identifies the selected item
- `quantity` — how many items were ordered
- `timestamp` — when the order was created
- `signature` — the RSA digital signature

## Signed data
The signed fields are:

    customer_id | order_id | item_id | quantity | timestamp

The `signature` field is not signed because it is produced after signing the data.
If any signed field is changed, signature verification fails.

## Weaknesses (Red Team view)
Possible attacks: spoofing (change customer_id), tampering (change item_id/quantity),
replay (resend an old packet) and flooding (send many packets quickly). These are the
reason the protocol needs signatures, timestamp checks and rate limiting.
