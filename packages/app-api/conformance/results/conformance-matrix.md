# Capability matrix

Cell = roll-up of the family's vectors at the selected tier (FAIL > KNOWN-FAIL > PASS > CLARIFY > SKIP); counts are pass/fail/skip/known-fail/clarify. A cell is green only when its anchor positive vectors pass: `*` marks a PASS roll-up that is not (its passing negative vectors may be vacuous; see the notes under the table).

| Implementation | Tier | ceremony-doc | dtg-credential-exchange | dtg-task-consent | framework | https-binding | trust-task-discovery | two-phase-commit | vrc-issue | vrc-propose | vrc-witness-share |
|---|---|---|---|---|---|---|---|---|---|---|---|
| truststackers-agent-didkey | 1+2 | PASS (9/0/1/0/6) | PASS (12/0/0/0/6) | PASS (14/0/0/0/4) | PASS (119/0/4/0/4) | PASS (6/0/0/0/0) | PASS (15/0/0/0/2) | PASS (6/0/0/0/2) | PASS (19/0/0/0/6) | PASS (23/0/0/0/3) | PASS (27/0/0/0/2) |
| truststackers-agent-scidvh | 1+2 | PASS (9/0/1/0/6) | PASS (12/0/0/0/6) | PASS (14/0/0/0/4) | PASS (119/0/4/0/4) | PASS (6/0/0/0/0) | PASS (15/0/0/0/2) | PASS (6/0/0/0/2) | PASS (19/0/0/0/6) | PASS (23/0/0/0/3) | PASS (27/0/0/0/2) |

