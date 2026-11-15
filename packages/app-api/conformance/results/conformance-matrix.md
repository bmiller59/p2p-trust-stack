# Capability matrix

Cell = roll-up of the family's vectors at the selected tier (FAIL > KNOWN-FAIL > PASS > CLARIFY > SKIP); counts are pass/fail/skip/known-fail/clarify. A cell is green only when its anchor positive vectors pass: `*` marks a PASS roll-up that is not (its passing negative vectors may be vacuous; see the notes under the table).

| Implementation | Tier | ceremony-doc | ceremony-receipt | dtg-credential-exchange | dtg-task-consent | framework | https-binding | trust-task-discovery | two-phase-commit | vrc-issue | vrc-propose | vrc-witness-share |
|---|---|---|---|---|---|---|---|---|---|---|---|---|
| truststackers-agent-didkey | 1+2 | PASS (8/0/1/0/7) | PASS (58/0/0/0/12) | PASS (12/0/0/0/6) | PASS (14/0/0/0/4) | PASS (111/0/7/0/12) | PASS (7/0/0/0/0) | PASS (15/0/0/0/2) | PASS (6/0/0/0/2) | PASS (19/0/0/0/6) | PASS (20/0/0/0/6) | PASS (27/0/0/0/2) |
| truststackers-agent-scidvh | 1+2 | PASS (8/0/1/0/7) | PASS (58/0/0/0/12) | PASS (12/0/0/0/6) | PASS (14/0/0/0/4) | PASS (111/0/7/0/12) | PASS (7/0/0/0/0) | PASS (15/0/0/0/2) | PASS (6/0/0/0/2) | PASS (19/0/0/0/6) | PASS (20/0/0/0/6) | PASS (27/0/0/0/2) |

Window, truststackers-agent-didkey: maxAgeSeconds 300, clockSkewSeconds 60, expiryHorizonSeconds 2592000 (equal to the profile pins; the pins are a profile choice, not framework text).
Tier 2 sub-groups, truststackers-agent-didkey (pass/fail/skip/known-fail/clarify): profile-witness-share 8/0/0/0/0; attested 23/0/1/0/0; profile-p384 0/0/2/0/0; profile-window 20/0/0/0/0; profile-ceremony 8/0/0/0/0.
Advisories, truststackers-agent-didkey: 0 SHOULD mismatch(es) in 0 vector(s); never a Tier 1 failure.
Window, truststackers-agent-scidvh: maxAgeSeconds 300, clockSkewSeconds 60, expiryHorizonSeconds 2592000 (equal to the profile pins; the pins are a profile choice, not framework text).
Tier 2 sub-groups, truststackers-agent-scidvh (pass/fail/skip/known-fail/clarify): profile-witness-share 8/0/0/0/0; attested 23/0/1/0/0; profile-p384 0/0/2/0/0; profile-window 20/0/0/0/0; profile-ceremony 8/0/0/0/0.
Advisories, truststackers-agent-scidvh: 0 SHOULD mismatch(es) in 0 vector(s); never a Tier 1 failure.
Not covered by truststackers-agent-didkey at tier 2: 1 vectors run only against a non-attested server at Tier 1 (DUP-103). Run the implementation a second time without `attested`; a merged row (several runs of one implementation) already counts that run.
Not covered by truststackers-agent-scidvh at tier 2: 1 vectors run only against a non-attested server at Tier 1 (DUP-103). Run the implementation a second time without `attested`; a merged row (several runs of one implementation) already counts that run.
