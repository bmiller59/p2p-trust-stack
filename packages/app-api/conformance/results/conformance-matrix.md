# Capability matrix

Cell = roll-up of the family's vectors at the selected tier (FAIL > KNOWN-FAIL > PASS > CLARIFY > SKIP); counts are pass/fail/skip/known-fail/clarify.

| Implementation | Tier | framework | https-binding | trust-task-discovery | two-phase-commit | vrc-issue | vrc-propose | vrc-witness-share |
|---|---|---|---|---|---|---|---|---|
| truststackers-agent-didkey-attested | 1+2 | PASS (102/0/18/0/4) | SKIP (0/0/6/0/0) | SKIP (0/0/17/0/0) | CLARIFY (0/0/4/0/1) | PASS (19/0/0/0/6) | PASS (22/0/1/0/3) | PASS (27/0/0/0/2) |
| truststackers-agent-scidvh-attested | 1+2 | PASS (102/0/18/0/4) | SKIP (0/0/6/0/0) | SKIP (0/0/17/0/0) | CLARIFY (0/0/4/0/1) | PASS (19/0/0/0/6) | PASS (22/0/1/0/3) | PASS (27/0/0/0/2) |
| truststackers-agent-didkey-tier1 | 1 | PASS (109/0/11/0/4) | SKIP (0/0/6/0/0) | SKIP (0/0/17/0/0) | CLARIFY (0/0/4/0/1) | PASS (16/0/3/0/6) | PASS (20/0/3/0/3) | PASS (25/0/2/0/2) |
| truststackers-agent-scidvh-tier1 | 1 | PASS (109/0/11/0/4) | SKIP (0/0/6/0/0) | SKIP (0/0/17/0/0) | CLARIFY (0/0/4/0/1) | PASS (16/0/3/0/6) | PASS (20/0/3/0/3) | PASS (25/0/2/0/2) |

Not covered by truststackers-agent-didkey-attested at tier 2: 16 vectors run only against a non-attested server at Tier 1 (PRF-108, DUP-101, DUP-102, DUP-103, DUP-104, DUP-105, DUP-106, DUP-107, DUP-108, DUP-109, DUP-110, DUP-111, DUP-112, DUP-113, DIS-015, VRC-PRO-011). Run the implementation a second time without `attested`; a merged row (several runs of one implementation) already counts that run.
Not covered by truststackers-agent-scidvh-attested at tier 2: 16 vectors run only against a non-attested server at Tier 1 (PRF-108, DUP-101, DUP-102, DUP-103, DUP-104, DUP-105, DUP-106, DUP-107, DUP-108, DUP-109, DUP-110, DUP-111, DUP-112, DUP-113, DIS-015, VRC-PRO-011). Run the implementation a second time without `attested`; a merged row (several runs of one implementation) already counts that run.
