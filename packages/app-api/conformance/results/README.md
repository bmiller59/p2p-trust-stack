# Conformance results (first run, conformance phase P8)

`conformance-matrix.md` / `.json` and `results.json` come from the suite's own command line against
the JSON-RPC adapter in `../` (see `../server.ts` for the command and options):

    node <suite>/src/runner/cli.ts --adapter "stdio:<server command> --attested --identity key --name truststackers-agent-didkey-attested" \
      --adapter "stdio:<server command> --attested --name truststackers-agent-scidvh-attested" \
      --adapter "stdio:<server command> --identity key --name truststackers-agent-didkey-tier1" --out conformance/results

Reading the matrix:

- `didkey-attested`: the agent boundary with a `did:key` connection identifier, Tier 1 and Tier 2.
- `scidvh-attested`: the same with the connection identifier the agent really has, a `did:scid:vh`.
  Tier 2 shows FAIL for every vector that judges a signed reply, and only for that reason: the suite's
  harness verifies reply proofs for `did:key` signers only ("unsupported verification method"), so it
  cannot check a `did:scid:vh` signature. The same replies verify against the document `provision`
  publishes (`test/conformance/rpc-server.test.ts`). This is a suite limitation, not an implementation
  gap, so there is deliberately no KNOWN-FAIL entry; the cell stays FAIL until the suite resolves the
  provisioned document.
- `didkey-tier1`: a server that does not claim Tier 2; the vectors that only run for such an
  implementation (DUP-101..113, PRF-108, VRC-PRO-011) run here.
- The carrier of the framework groups is the suite's conformance widget task, served by a fixture
  handler behind the real pipeline (the agent has no consequential task of its own other than the VRC
  tasks, whose request shapes the generic vectors cannot use).
