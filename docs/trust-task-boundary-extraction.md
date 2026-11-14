# Extracting the Trust Task boundary from p2p-trust-stack

Reference guide for a maintainer. Status of the decision: the boundary stays in p2p-trust-stack as a clearly labelled, opt-in package of the repository (option B). This guide documents how to move it later, first into its own workspace package (option C) and then, only if wanted, into a separate repository (option D). Nothing in this guide has been executed. Paths, counts and test numbers are as observed in the working tree at the time of writing and should be re-checked before starting. Effort figures are estimates.

Naming: this guide says "Trust Task boundary" (package name `trust-task-boundary`). The word "bridge" is avoided because the unrelated openvti-bridges repository uses it for out-of-process relays between rooms; the boundary is an in-process protocol front door. "Bridge" is only a synonym used informally.

## 1. Purpose and current contents

### 1.1 What the boundary is

An opt-in HTTPS document surface (Trust Task documents) in front of the existing Trust Spanning Protocol two-phase-commit machinery. It verifies, records, signs and answers Trust Task documents; the internal TSP ceremony is unchanged. It is off by default: the listener starts only when enabled by configuration (section 1.4), and the default tier is 2 (proof on every request, signed replies).

### 1.2 Inventory, by location

Paths are relative to `packages/`. The "Depends on core internals" column lists the main deep-path imports (all `@p2p-trust-stack/core/<path>.js`), because those define the API that must be curated before extraction (section 4.1).

| Location | Contents | Depends on core internals |
|---|---|---|
| `core/src/services/trust-tasks/boundary/` | `pipeline.ts`, `handlers.ts`, `errors.ts`, `lifecycle.ts`, `accepted-store.ts`, `recorder.ts`, `discovery.ts`, `next-step.ts`, `urn-codec.ts`, `payload-validator.ts`, `pins.ts`, `datetime.ts`, `ceremony-spec.ts`, `witness-share-spec.ts`, `ceremony-outcome.ts`, `legacy-evaluate.ts`, `runtime.ts` (the single import site for the pinned `@openvtc/trust-tasks` runtime) | `db/data-source`, `db/repositories/{trust-tasks,identities}-repo`, `tx/ceremony-store`, `tx/governance-change-store`, `did/*` (resolver, scid-vh method, rotation types/log source), `crypto/primitives`, `services/policy-engine`, `services/policy-gate` |
| `core/src/services/trust-tasks/boundary/proof/` | `verify.ts`, `signer.ts`, `resolver.ts`, `time-pinned.ts`, `key-config.ts`, `install.ts`, `data-integrity.ts`, `digest.ts`, `purposes.ts` | `did/*`, `crypto/primitives`, identities repo |
| `core/src/relationship/` | `exchange-dids.ts`, `exchange-vrc.ts`, `vrc-mint.ts`, `witness-share.ts` | DID manager, keystore, credentials stores |
| `core/src/db/repositories/` | `vrc-exchange-dids-repo.ts`, `witness-shares-repo.ts`, `trust-tasks-repo.ts` | `DataSource` |
| `core/migrations/` and `core/SCHEMA_VERSION` | `0021_trust_task_boundary.sql` (ten nullable columns on `trust_tasks`; tables `trust_task_accepted` and `vrc_exchange_relationship_dids`), `0022_witness_shares.sql` (`witnessed_credentials`, `witness_share_evidence`); version file at 27 on the integration branch after `0023_credential_presentations.sql`; re-read it before relying on this figure | not code; owned by core |
| `app-api/src/runtime/trust-tasks-boundary/` | `vrc-propose.ts`, `vrc-issue.ts`, `witness-share.ts`, `ceremony-doc.ts`, `settle.ts`, `retained.ts`, `listener.ts`, `agent-boundary.ts`, `shared.ts`, `index.ts` | the largest set of deep imports: `db/data-source`, `tx/types`, `tx/ceremony-guard`, `tx/index`, `tx/ceremony-store`, `tx/manager`, `boundary/{errors,handlers,runtime,pipeline,accepted-store,recorder,next-step,lifecycle,discovery,pins,...}`, `boundary/proof/{resolver,signer,verify,digest,install}`, `relationship/{exchange-vrc,exchange-dids,vrc-mint,witness-share,types}`, `db/repositories/*`, `vtc/store`, `services/identity-resolver`, `util/logger` |
| `app-api/src/runtime/tx/` | participants the handlers drive: `vrc-ceremony-participant.ts`, `vrc-receive-participant.ts`, `witness-share-participant.ts`, `ceremony-doc-participant.ts`, `ceremony-event-receive-participant.ts`, `ceremony-poll.ts`, `bootstrap.ts` and others | `tx/*`, DataSource. These are agent runtime and stay with the agent (section 4.3) |
| `app-api/src/runtime/base-agent.ts` | imports `startAgentBoundary` and `resolveListenerConfig` (around line 119); starts and stops the listener; holds `_boundaryVerifier` and installs the boundary signer (`installBoundarySigner`, `DidProofVerifier`, `createLocalKeyResolver`, lines ~150, 4160-4500); exposes `listHeldVrcProposals` and `decideVrcProposal` (~1150); reads `AgentConfig.trustTasksListener` (`runtime/types.ts`) | the coupling that makes the boundary non-optional structurally today |
| `app-api/conformance/` | `adapter.ts` (JSON-RPC adapter, ~670 lines), `rpc.ts`, `server.ts` (CLI flags: `--attested`, `--identity key|scid-vh`, `--carrier widget|issue|none`, `--no-issue`, `--no-witness-share`, `--no-ceremony`, `--proposer-approves`, `--no-https`, `--name`, `--implementation`, `--http`), `contract.ts` (hand copy of the suite's adapter contract types), `http-binding.ts`, `two-phase.ts`, `results/` (generated matrix, results.json, README) | pipeline, store, signer, participants, temp SQLite, migrations dir |
| Tests | core: `core/test/services/trust-tasks/boundary/` (pipeline, accepted store, errors, lifecycle, freshness, digest, ceremony outcome, layer 3b handlers, evaluate-unrecorded, boundary-key switch, conformance fixtures), `core/test/relationship/{exchange-dids,check-vrc}.test.ts`; app-api: `app-api/test/trust-tasks-boundary/` (listener, vrc-propose, vrc-issue, witness-share, ceremony-doc, two-agents, suite-runner helper, vectors copy), `app-api/test/conformance/` (rpc-server, suite-run, two-phase), `app-api/test/tx/` | test support: `suite-runner.ts`, `vrc-adapter.ts`, `witness-bundle.ts`, `layer3b-support.ts`, `helpers.ts`, `e2e-harness.ts`, temp-DB and injected-clock helpers |
| utility-server (separate repo) | its own copy of migration 0021 (AGPL header, Postgres-compatible) and its own `SCHEMA_VERSION` (check its relationship to core's before relying on any arithmetic); a Trust Task route using `AcceptedIdStore` over its application database | core pipeline and store through the published core package |

### 1.3 What must stay in core in every variant

Migrations and `SCHEMA_VERSION`; `DataSource` and the repositories; `DidManager`, DID methods and the keystore; `TransactionManager`, `TransactionCoordinator` and `tx/` stores; the relationship, VRC and witness-share services that own tables in the replicated schema. The default variant (section 3) also leaves the pipeline, proof verifier/signer and accepted-id store in core, because utility-server consumes them directly from the published core package.

### 1.4 Opt-in switches (keep working unchanged after any move)

- `TRUST_TASKS_LISTENER=1` (or `AgentConfig.trustTasksListener.enabled`), with a mandatory port `TRUST_TASKS_LISTENER_PORT`; there is no default port.
- `TRUST_TASKS_LISTENER_HOST` (default `127.0.0.1`), `TRUST_TASKS_TIER` (`1` selects tier 1, otherwise tier 2), `TRUST_TASKS_PROPOSE_POLICY` (`decline`, otherwise `hold`).
- `trustTasksListener.forbiddenPorts` guard.
- The dedicated boundary key (`#key-boundary`) is behind a default-off gate (`installBoundarySigner({dedicated})`).
- Conformance-only flags (`--proposer-approves`, `--no-https`) must never become production defaults; the native `proposerApproves` is false.

## 2. When to extract (preconditions)

Do not start until all hold:

1. Phase P10 of the conformance plan is complete (see the suite repository's `docs/06-truststackers-conformance-plan.md`, and `docs/08-design-notes.md` section 14 for the P10 order and release order).
2. The stacked conformance branches (p0 through p11, p8f, and the decisions branch above them) are merged to the main line, so extraction does not rebase thirteen stacked branches.
3. A curated core API exists and has been released (section 4.1) with a version number the boundary can depend on.
4. Written legal confirmation of the licence stance (section 3.3), if option D (separate repository) is chosen. Option C (same repository) needs no new confirmation.
5. The matrix baseline is green and recorded (section 5.1) so any regression is attributable.
6. No open work on files being moved (`ceremony-doc.ts`, `vrc-propose.ts`, `witness-share.ts`, `conformance/adapter.ts` change often).

Reasons to go to option D (rather than stop at C): a separate release cadence is wanted, or a separate maintainer group owns the boundary. Otherwise C is sufficient and cheaper.

## 3. Target shapes

### 3.1 Option C: workspace package (first)

New package `packages/trust-task-boundary` in the same repository, same licence, CLA, CI and release train. Package name `@p2p-trust-stack/trust-task-boundary`.

```
packages/trust-task-boundary/
  package.json          license (GPL-3.0-only OR LicenseRef-TrustStackers-Commercial); peerDependencies on core and app-api
  README.md             what it is, how to opt in, the switches in section 1.4
  LICENSE, NOTICE       same as the other packages
  src/
    index.ts            public exports (handlers, listener, registerBoundary)
    handlers/           vrc-propose, vrc-issue, witness-share, ceremony-doc, settle, retained
    listener.ts, agent-boundary.ts, shared.ts
  test/                 moved app-api/test/trust-tasks-boundary and conformance tests
  conformance/          moved adapter, rpc, server, http-binding, two-phase, results/
  docs/ARCHITECTURE.md decision record, threat model, pins, boundaries of the package
```

Dependencies point one way: trust-task-boundary depends on core and app-api; core never imports it. Add an isolation check (a script run in CI that fails if any file under `core/` or `app-api/src` imports the package) in place of the Rust-style `cargo tree` check used elsewhere.

### 3.2 Option D: separate repository (later, optional)

Same layout as 3.1 as an npm workspace in a new repository (suggested name `trust-task-boundary`, under the same organisation as core):

```
trust-task-boundary/
  packages/boundary/             the code of 3.1 src/ and test/
  packages/conformance-adapter/  private; the conformance directory
  docs/ARCHITECTURE.md
  contributor guides (root and per package), CONTRIBUTING.md, CLA.md, OWNERSHIP.md, COMMERCIAL-LICENSE.md, NOTICE, LICENSE
  scripts/               SPDX header check, dependency-licence check (copy core's), isolation check
  .github/workflows/ci.yml
```

### 3.3 Licence

Must match core: `GPL-3.0-only OR LicenseRef-TrustStackers-Commercial`, contributions under the same CLA, per-file SPDX headers (core's `license:headers` and `license:check` scripts). A package that imports core is a combined work under GPL-3.0; permissive licensing (for example Apache-2.0, as in the openvti-bridges and conformance-suite repositories) does not work for it and would break the dual-licensing model, which depends on owning all copyright. Legal confirmation is required before creating a separate repository; until it is given, treat option D as blocked. The conformance suite stays Apache-2.0 and independent, talking to the adapter across a process boundary.

### 3.4 CI

Option C: the existing workspace CI plus a job for the new package (typecheck, test, SPDX and dependency-licence check, isolation check, `smoke:pack` if present). Option D: the same jobs, plus a matrix over the supported core versions (minimum and latest), plus a job that runs the suite against the adapter when the suite checkout is available (skipped with a message when absent, as the in-tree tests do today).

### 3.5 Versioning and release order

- Core publishes a curated API (section 4.1) and documents it as stable-with-exceptions; mark it unstable until after the production cutover decisions (dedicated key custody and its follow-ups).
- The boundary declares a core peer range and a minimum core `SCHEMA_VERSION` it needs (checked at start-up, section 4.4).
- Pin `@openvtc/trust-tasks` (currently 0.29.0) in both core and the boundary and keep the pin in lockstep; the single import site stays `runtime.ts`.
- Release order, always: (1) core, (2) trust-task-boundary, (3) app-api, (4) utility-server dependency bump. In option C steps 1 to 3 are one workspace release but keep the order for publish. Releasing a dependent first pins a version that does not exist yet.

## 4. Extraction procedure

Work on one branch per checkpoint. After each checkpoint run section 5. Run heavy commands under `nice -n 10` and check memory and load first (shared machine); use `umask 002` and a `TMPDIR` under `/var/tmp`.

### 4.0 Baseline

Record, on the commit you start from: full core and app-api test counts, the six-configuration suite run (section 5.1) with per-configuration PASS/FAIL/SKIP/CLARIFY, the discovery answer (supported types list) of each configuration, and `SCHEMA_VERSION`. These are the numbers to match afterwards.

### 4.1 Define and export the minimal core API surface

Today core's `exports` is a wildcard (`./*` to `dist/*.js`), so everything is importable and nothing is promised. Replace deep-path use by a small curated entry (suggested subpath `@p2p-trust-stack/core/boundary-api`, re-exporting from the internal paths below) and add it to `exports` while keeping the wildcard during the transition. The eight groups, with the current internal path of each:

1. Data access and migrations: `db/data-source.js` (`DataSource`), `db/sqlite-data-source.js`, `db/repositories/{identities-repo,trust-tasks-repo,vrc-exchange-dids-repo,witness-shares-repo,did-documents-repo}.js`, `db/migrate.js`, `db/migrations-dir.js` (`getMigrationsDir`; the migration runner is read-only for the boundary, section 4.4).
2. Pipeline and storage: `services/trust-tasks/boundary/{pipeline,handlers,errors,lifecycle,accepted-store,recorder,next-step,discovery,pins,ceremony-spec,witness-share-spec,ceremony-outcome}.js` (`Pipeline`, handler and registry types, error builders, lifecycle mapping, `AcceptedIdStore`, recorder), and `services/trust-tasks/{type-uris,catalog,driver}.js`.
3. Proof: `services/trust-tasks/boundary/proof/{verify,signer,resolver,install,digest,time-pinned,key-config}.js` (`DidProofVerifier`, `BoundarySigner`, key and time-pinned resolvers, `installBoundarySigner`).
4. Transactions: `tx/{manager,types,index,ceremony-guard,ceremony-store,vrc-ceremony-store,governance-change-store,vtc-receive-participant}.js`: `TransactionManager`, `TransactionCoordinator`, participant base types and the stores the handlers read.
5. DID and keys: `did/{scid-vh-method,did-resolution-service,types}.js`, `crypto/primitives.js`, `services/identity-resolver.js`, `platform/p2pts-home.js`, keystore access used for per-exchange relationship keys.
6. Relationship code: `relationship/{exchange-dids,exchange-vrc,vrc-mint,witness-share,types}.js` (`checkVrc`, `InnerProofVerifier`, minting, witness-share verification), plus `services/credential-factory/verify-policy.js`, `services/governance-change.js`, `vtc/store.js`.
7. `BaseAgent` extension points: new, section 4.2. Lives in app-api, not core.
8. Runtime re-export: `services/trust-tasks/boundary/runtime.js`, the single import site of the pinned `@openvtc/trust-tasks`.

Also export a test-support entry (temp SQLite helper, injected clock, two-agent fixtures: currently `helpers.ts`, `layer3b-support.ts`, `e2e-harness.ts`, `suite-runner.ts`) or move those helpers into a shared private test package, so moved tests do not import core test files by path.

Not part of the promised API (internal; consumers must not couple to them): table columns beyond those the repositories expose, the shape of `trust_tasks` rows, the transaction log format.

Checkpoint 4.1: app-api and the boundary directory compile importing only from the curated entry (add a lint rule or script that rejects `@p2p-trust-stack/core/` deep paths outside the entry); core tests unchanged and green. Release core with this entry before any move.

### 4.2 Add the BaseAgent extension hook

Goal: `base-agent.ts` no longer imports the boundary. Add to app-api a small registry, for example `registerExtension({ name, config, start(agentContext), stop() })`, where the agent context exposes the DataSource, identity, signer, verifier, transaction manager and the held-proposal methods the boundary needs. Move out of `base-agent.ts`: the `startAgentBoundary` and `resolveListenerConfig` imports and the listener start/stop code (~1115-1145), `_trustTasksListenerOptions`, and the held-proposal API (`listHeldVrcProposals`, `decideVrcProposal`), which become methods of the boundary extension (or thin delegations kept for compatibility, deprecated). `AgentConfig.trustTasksListener` becomes an extension config entry; keep the old key as an alias for one release. The boundary signer installation (`ensureBoundarySigner`, `_boundaryVerifier`) either stays in the agent as generic proof support (preferred: utility-server needs the signer too) or moves with the extension; decide once and record it.

Checkpoint 4.2: with no extension registered nothing listens and no boundary code is loaded (add a test); with the extension registered behaviour is identical (listener tests unchanged). Release app-api.

### 4.3 Move code in dependency order (option C, then D)

Order, leaf first, so every intermediate commit compiles:

1. `shared.ts`, `retained.ts`, `settle.ts` (few dependencies).
2. `vrc-issue.ts`, `witness-share.ts`, `ceremony-doc.ts`, `vrc-propose.ts` (handlers).
3. `listener.ts`, `agent-boundary.ts`, `index.ts`, plus the registration entry from 4.2.
4. Tests in step with each file (section 4.5).
5. `conformance/` (section 4.6).

Stay where they are: the participants in `app-api/src/runtime/tx/` (they belong to the agent runtime and are used by the internal TSP ceremony too; the handlers receive them through the dependency objects they already define, `IssueTransactions`, `WitnessShareTransactions`, `CeremonyTransactions`); and all of core (section 1.3). If a later decision also moves core's `boundary/` directory (pipeline, proof), do that as a separate, second extraction after utility-server has been moved to the curated entry, because utility-server consumes those files today.

For each file in option C use `git mv` (history follows by rename detection; commit the pure move first with no content change, then a commit rewriting imports) and update `package.json` workspaces, `tsconfig` references and the `exports` of app-api (drop the moved paths).

Checkpoint 4.3 after each numbered step: typecheck of core, app-api and the new package; the tests of the moved files; app-api tests.

### 4.4 Migrations stay in core

The boundary does not own or ship any migration. Tables `trust_task_accepted`, `vrc_exchange_relationship_dids`, `witnessed_credentials`, `witness_share_evidence` and the added `trust_tasks` columns remain defined by `core/migrations/0021` and `0022` and applied by core's migrator (`db/migrate.js`), which owns the single integer `SCHEMA_VERSION`. Rules:

- Any schema change the boundary needs is a core change: new migration in core, `SCHEMA_VERSION` bump, core release, then the boundary release that uses it. The boundary never writes the version.
- The boundary declares `minCoreSchemaVersion` (the value in core's `SCHEMA_VERSION` when the boundary last changed what it reads or writes) and checks at start-up that the database's recorded version is at least that, failing closed with a clear message otherwise.
- Core exposes the table access through repositories (group 1); the boundary uses the repositories and does not issue raw SQL against these tables.
- utility-server carries its own Postgres-compatible copies of the migrations and its own `SCHEMA_VERSION` (not necessarily core's value plus a fixed offset: it carries migrations of its own, so check both files). Keep the two in lockstep: the body of each shared migration must be byte-identical apart from the licence header; when core adds a migration that the boundary needs, utility-server adds the same file and bumps its own version in the same release round. Add a check (script comparing migration bodies between the trees) to the release checklist. Extraction itself changes neither tree.
- Known pre-existing weakness to keep in mind: the SQLite migrator records versions as `__schema_version__:<n>` while its lookup uses the bare name, so a bumped version does not reliably make an older binary refuse the database. Do not rely on that as a rollback guard (section 5.3).
- Migrations are additive and nullable; keep them so, because rollback relies on it.

### 4.5 Move the tests

- Moved with their handler: `app-api/test/trust-tasks-boundary/*` (listener, vrc-propose, vrc-issue, witness-share, ceremony-doc, two-agents, helpers, vector copies and their `PROVENANCE.json`).
- Stay in core: `core/test/services/trust-tasks/boundary/*` and `core/test/relationship/*` (they test code that stays in core).
- `app-api/test/tx/*` stays with the participants.
- Moved tests must use only the curated entry and the test-support entry. Update the test scripts (`node --conditions=development --experimental-strip-types --loader ./test-loader.mjs --test ...`); the new package needs its own `test-loader.mjs` or a shared one.
- The suite-run tests spawn the suite CLI and skip with a message when the suite folder is absent; keep that behaviour.

### 4.6 Move the conformance adapter; the suite stays outside

The suite stays in its own repository (`dtgwg-trust-conformance`). The adapter (`conformance/*`) moves with the boundary package because it wires the pipeline, store, signer and participants. The suite finds the adapter by configuration only: the `--adapter "stdio:<command>"` argument of the suite CLI (the command is the adapter server started in the new package's directory), and the suite location is found by the tests through the `TRUST_CONFORMANCE_SUITE` environment variable (default is the developer-machine path; change the default to a documented relative or configured path). Update `conformance/results/README.md` commands and `contract.ts` (hand copy of the suite's adapter contract types; re-copy it from the suite at the suite revision in use and record that revision, since the suite folder was not under version control when vectors were first copied). The generated results are regenerated by running the suite, never edited by hand.

### 4.7 Rewire app-api and utility-server

- app-api: remove `runtime/trust-tasks-boundary` and its `index.ts` exports; `base-agent.ts` uses only the extension hook (4.2); document how an application registers the boundary. Keep a compatibility re-export for one release if external code imported the old paths.
- utility-server: it uses core's pipeline and `AcceptedIdStore` (route `src/routes/layer3-tasks/trust-tasks.ts`), not the app-api handlers. In option C nothing changes for it except that deep paths are replaced by the curated entry. If core's `boundary/` is ever moved (4.3), change its imports to the new package in its own branch and bump after the releases (section 3.5).
- Search for stragglers in the whole tree and in dependents: `grep -rn "trust-tasks-boundary\|services/trust-tasks/boundary" --include=*.ts --include=*.json --include=*.md` and check agent-app, utility-server and keyring-style consumers.

### 4.8 Option C to option D: history-preserving move

Preferred: `git filter-repo` on a fresh clone (never on the working repository), no interactive rebase.

```
git clone <p2p-trust-stack> /var/tmp/ttb-extract && cd /var/tmp/ttb-extract
git filter-repo --path packages/trust-task-boundary/ --path-rename packages/trust-task-boundary/:
```

Then add the repository scaffolding (3.2) in new commits, set the new remote, and push there. Alternative that leaves the source repository history intact and needs no clone rewrite: `git subtree split --prefix=packages/trust-task-boundary -b ttb-split`, then push that branch to the new repository. Both keep every commit that touched the files, with original author dates; verify signatures and sign-off trailers survive (rewritten commits lose their signatures under filter-repo, so re-sign or accept an unsigned import commit boundary, and document the choice; project policy requires signed commits and sign-off on all new commits).

Files that moved from elsewhere keep earlier history only if they were moved by rename in the source repository; check with `git log --follow` for a sample of files before choosing a method.

Then in the source repository: delete the package in one commit, depend on the published package instead, update workspaces and CI. Keep a pointer README in the old location for one release.

## 5. Verification checklist

### 5.1 At every checkpoint

- Resources first: check memory and load; run builds and test suites under `nice -n 10`.
- Typecheck core, app-api and the boundary package (app-api typecheck needs core built or `--customConditions development`).
- Full test suites: core, app-api, the boundary package; utility-server suite against the local core (conditions `development`). Compare counts with the baseline (at the time of writing: core 1309 tests with 1 skipped, app-api 383; utility-server 286 on its own branch). A smaller count means a lost test.
- SPDX and dependency-licence checks (`license:check`).
- The suite run, one invocation, six configurations, all with FAIL 0 and KNOWN-FAIL 0 and the same PASS/CLARIFY/SKIP counts as the baseline (at the time of writing: attested tier 1: 191/24/37; attested tier 2 and non-attested tier 1: 207/24/21; for each of did:key and did:scid:vh):

  ```
  S="stdio:NODE_NO_WARNINGS=1 node --conditions=development --experimental-strip-types --loader ./test-loader.mjs <path-to>/conformance/server.ts"
  node <suite>/src/runner/cli.ts --timeout 60000 --out <scratch> \
    --adapter "$S --attested --identity key --name ..." --adapter "$S --identity key ..." \
    --adapter "$S --attested ..." --adapter "$S ..."
  ```
  Write results to a scratch directory, not over the committed results, unless regenerating deliberately.
- Discovery lists the same Type URIs in every configuration as in the baseline (diff the sorted lists).
- Opt-in check: with no listener flag, nothing binds a port; with `TRUST_TASKS_LISTENER=1` and no port, start fails with the documented message.

### 5.2 Migrations on populated databases (specific to 4.1, 4.4, 4.8)

- Take a copy of a populated agent database (and a populated utility-server database) from before the extraction; open it with the post-extraction build; confirm migrations apply or are already applied, the recorded version is what core's `SCHEMA_VERSION` says, and rows in `trust_tasks`, `trust_task_accepted`, `vrc_exchange_relationship_dids`, `witnessed_credentials`, `witness_share_evidence` read back unchanged.
- Start the boundary against a database below `minCoreSchemaVersion`; it must refuse with the clear message.
- Run the same on the Postgres dialect path for utility-server (the in-repo emulation checks dialect syntax only; a real engine run is a separate open item).

### 5.3 Rollback

- Before any push: each checkpoint is its own branch from the previous one; abandon by resetting the working branch to the previous checkpoint (local branches; no shared history is rewritten).
- After publishing: do not unpublish; publish a patch release of core and the boundary that restores the previous behaviour (the compatibility re-exports from 4.2 and 4.7 exist for this reason), then fix forward.
- Database: the boundary adds no schema, so reverting code leaves the columns and tables in place and harmless (they are additive and nullable). Do not assume a downgraded binary refuses a newer database (see 4.4).
- Option D: until the old package directory is deleted from the source repository, rollback is "keep using the in-repo package"; delete it only after one clean release cycle.

## 6. Risks and known pitfalls

- Deep-path imports. The boundary code imports core files directly (for example `.../boundary/pipeline.js`). A rename inside core breaks it only at build time, and a wildcard `exports` hides which files are relied on. Fix: curated entry plus a lint rule; run the deep-path grep (4.7) before each release.
- Release order. Core first, then the boundary, then app-api, then the utility-server bump. A dependent commit builds against npm only after core is released; in local development utility-server uses core through a symlink with `--conditions=development`, which hides missing releases. Test against packed tarballs (`npm pack`) before releasing.
- Dual migrations. utility-server keeps copies of the migrations with its own version number; a migration added in core and forgotten in utility-server, or a body that drifts, only shows up on populated databases. Use the body-comparison check (4.4).
- DataSource dialect differences. The agent uses SQLite; utility-server uses Postgres-style semantics. Known traps already met: time columns are `BIGINT` epoch milliseconds (a 32-bit `INTEGER` overflows; BIGINT returns as strings on that dialect), key violations surface as error code 23505, SQLite-only syntax is rejected. The boundary must go through `DataSource` and the repositories, never SQLite-specific calls, and its tests should keep the Postgres-dialect emulation case for the accepted-id store.
- Listener opt-in flags. The listener must stay off by default: no default port, tier 2 default, hold policy default. The adapter declares an in-process binding; the listener has no clock injection, so the time and duplicate vectors cannot be run through the listener as it is. Conformance-only flags must not leak into production defaults (`proposerApproves` stays false).
- Pinned runtime. `@openvtc/trust-tasks` is pinned and imported only in `boundary/runtime.ts`. Two copies at different versions (core and a separate boundary repository) produce subtle verification differences; keep one pin and test it in CI.
- Hand-copied contract. `conformance/contract.ts` copies the suite's adapter types and vectors under `app-api/test/trust-tasks-boundary/vectors` are byte copies with provenance; they drift silently from the suite. Re-copy and re-record on each suite revision.
- Held proposals and lapse: behaviour added late (seven-day lapse, new `expired` exchange state, free-text state column, no migration). Consumers listing exchange states must accept it; keep it in the moved handlers' tests.
- Identifier checks added late (the genesis-hash check for `did:scid:vh` resolution) live in core; databases holding a forged or legacy-format scid log stop resolving from the log. Scan deployed identifiers before releasing, independent of extraction.
- Unfinished pieces that a move must not accidentally make worse: custody of the dedicated boundary key and the verifier policy/time-pinned resolvers are not yet wired into the agent start-up; the downgrade guard weakness (4.4).
- Test support. Moved tests need core's helpers; if they are not exported, the boundary tests silently depend on core's source layout.
- Branch churn. Moving files while other branches edit them creates rename conflicts; extract only when the precondition list (section 2) holds.
- Licence. A separate repository under a permissive licence is not allowed; see 3.3.
- Naming confusion with openvti-bridges. Do not file the boundary there (language, licence, in-process versus relay all differ).

## 7. Effort (estimates only; not measured)

| Work | Estimate |
|---|---|
| Curated core API entry, test-support entry, deep-path lint (4.1) | 2 to 3 weeks |
| BaseAgent extension hook (4.2) | about 1 week |
| Option C: move code, tests, conformance adapter, rewire (4.3 to 4.7), docs and README | 1 to 2 weeks |
| Option C total, including the API work | about 3 to 5 weeks |
| Option D on top of C: scaffolding, CI, licence check, filter-repo move, release plumbing | 1 to 2 weeks, plus waiting time for legal confirmation |
| Ongoing cost of D: a second repository, a three-step release chain, pin alignment | not estimated; plan for extra release effort per boundary change |

Estimates assume a maintainer who knows the repository and no stacked branches left open.

Status: done.
