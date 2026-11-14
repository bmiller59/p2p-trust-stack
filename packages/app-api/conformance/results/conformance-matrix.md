# Capability matrix

Cell = roll-up of the family's vectors at the selected tier (FAIL > KNOWN-FAIL > PASS > CLARIFY > SKIP); counts are pass/fail/skip/known-fail/clarify.

| Implementation | Tier | framework | vrc-issue | vrc-propose | vrc-witness-share |
|---|---|---|---|---|---|
| truststackers-agent-didkey-attested | 1 | PASS (95/0/25/0/4) | PASS (16/0/3/0/6) | PASS (19/0/4/0/3) | FAIL (24/1/2/0/1) |
| truststackers-agent-didkey-attested | 2 | PASS (102/0/18/0/4) | PASS (19/0/0/0/6) | PASS (22/0/1/0/3) | FAIL (26/1/0/0/1) |
| truststackers-agent-scidvh-attested | 1 | PASS (95/0/25/0/4) | PASS (16/0/3/0/6) | PASS (19/0/4/0/3) | FAIL (24/1/2/0/1) |
| truststackers-agent-scidvh-attested | 2 | PASS (102/0/18/0/4) | PASS (19/0/0/0/6) | PASS (22/0/1/0/3) | FAIL (26/1/0/0/1) |
| truststackers-agent-didkey-tier1 | 1 | PASS (109/0/11/0/4) | PASS (16/0/3/0/6) | PASS (20/0/3/0/3) | FAIL (24/1/2/0/1) |
| truststackers-agent-scidvh-tier1 | 1 | PASS (109/0/11/0/4) | PASS (16/0/3/0/6) | PASS (20/0/3/0/3) | FAIL (24/1/2/0/1) |

Not covered by truststackers-agent-didkey-attested at tier 1: 15 vectors run only against a non-attested server at Tier 1 (PRF-108, DUP-101, DUP-102, DUP-103, DUP-104, DUP-105, DUP-106, DUP-107, DUP-108, DUP-109, DUP-110, DUP-111, DUP-112, DUP-113, VRC-PRO-011). Run the implementation a second time without `attested` and read both matrices.
Not covered by truststackers-agent-didkey-attested at tier 2: 15 vectors run only against a non-attested server at Tier 1 (PRF-108, DUP-101, DUP-102, DUP-103, DUP-104, DUP-105, DUP-106, DUP-107, DUP-108, DUP-109, DUP-110, DUP-111, DUP-112, DUP-113, VRC-PRO-011). Run the implementation a second time without `attested` and read both matrices.
Not covered by truststackers-agent-scidvh-attested at tier 1: 15 vectors run only against a non-attested server at Tier 1 (PRF-108, DUP-101, DUP-102, DUP-103, DUP-104, DUP-105, DUP-106, DUP-107, DUP-108, DUP-109, DUP-110, DUP-111, DUP-112, DUP-113, VRC-PRO-011). Run the implementation a second time without `attested` and read both matrices.
Not covered by truststackers-agent-scidvh-attested at tier 2: 15 vectors run only against a non-attested server at Tier 1 (PRF-108, DUP-101, DUP-102, DUP-103, DUP-104, DUP-105, DUP-106, DUP-107, DUP-108, DUP-109, DUP-110, DUP-111, DUP-112, DUP-113, VRC-PRO-011). Run the implementation a second time without `attested` and read both matrices.
