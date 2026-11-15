# Dedicated boundary key (`#key-boundary`): operator runbook

Scope: the Ed25519 key that signs Trust Task documents as `<did>#key-boundary`, for the agent runtime (did:scid:vh agents) and the utility server. Default is off: with `TRUST_TASKS_BOUNDARY_KEY` unset every process signs with `#key-1` and verifies as before.

## Switches

| Variable | Meaning |
|---|---|
| `TRUST_TASKS_BOUNDARY_KEY` | Unset, empty or `key-1`: default. `dedicated`: dedicated mode. Any other value is refused at start-up. |
| `BOUNDARY_KEY_CUTOVER_AT` | Required with `dedicated`: RFC 3339 time with a zone. Documents created before it are signed with `#key-1`, from it on with `#key-boundary`. |
| `BOUNDARY_KEY_GENERATION` | Positive integer, default 1: which stored key generation the process uses. |
| `BOUNDARY_KEY_MAX_PROOF_AGE_SECONDS` | Verifier freshness bound, default 600. |
| `BOUNDARY_KEYSTORE_PATH` | Utility server only: key store file, default `data/boundary-keystore.db`. |
| `TRUST_TASKS_LISTENER`, `TRUST_TASKS_LISTENER_PORT`, `TRUST_TASKS_LISTENER_HOST`, `TRUST_TASKS_TIER`, `TRUST_TASKS_PROPOSE_POLICY` | The opt-in listener (no default port, loopback host, Tier 2, hold). |

## Custody

- Generation N is stored in the process's existing encrypted key store under key type `boundary-ed25519-gN` for the identifier's DID (Argon2id and AES-256-GCM). Agent: its keystore, agent passphrase. Utility server: `SqliteKeyStore` file, `TSP_SEED_PASSPHRASE`. There is no default passphrase.
- The key is random (not derived from another key) and is never overwritten.
- Backed-up state: the key store file and the passphrase. The identifier's rotation log and DID document are public and live in the normal database.

## Failure behaviour (dedicated mode on)

The process refuses instead of signing with `#key-1`: the agent starts no listener and installs no signer; the utility server exits at start-up. Causes, as logged in `{"event":"listener.refused"|"startup.refused","reason":...}`: `config` (bad gate value, missing cutover, no passphrase), `missing` (no key for the generation), `corrupt` (wrong passphrase, damaged or mismatched record), `notPublished` (the identifier's own document does not publish the held key at `#key-boundary` under `authentication`). A did:peer:4 identifier cannot gain the key in place and is refused as `missing` or `notPublished`.

## Operator CLIs

Both CLIs run the same six commands and follow the same rules. There is no network or UI route to any of them.

| Command | Effect |
|---|---|
| `provision --generation N` | Generate generation N into the encrypted key store. Refuses an existing generation (never overwritten). |
| `publish --generation N` | First publication: appends a metadata-only log entry that adds `#key-boundary` under `authentication` and changes nothing else. Refuses when `#key-boundary` is already published or when generation N is already the published key. |
| `rotate --generation N` | Replaces the key of the published `#key-boundary` with a NEW generation N (a metadata-only entry). Refuses when nothing is published yet or N is already published. |
| `retire` | Appends an entry that removes `#key-boundary` and its `authentication` entry. Refuses when nothing is published. |
| `destroy --generation N` | Deletes the stored secret of generation N. Refuses the generation the document currently publishes. |
| `status` | Read-only: what is published and which generations are held. |

Rules common to both:

- Mutating commands are a dry run unless `--execute` is given. A dry run loads the key and builds and chain-validates the log entry, and stores, appends, pushes and provisions nothing.
- The key store passphrase comes only from an environment variable (never an argument), and every command refuses without it. There is no default.
- Output is one JSON line with generation, fingerprint (hash prefix of the public key), log version and a note. It never carries a key, seed or passphrase. A refusal prints `refused: <reason>` to stderr and exits 1; nothing was written.
- Any problem is a refusal before anything is written: missing or damaged key, wrong passphrase, key not published, generation conflicts, an entry that fails chain validation.

### Utility server

```
cd utility-server
TSP_SEED_PASSPHRASE=... npm run boundary-key -- <command> [--generation N] [--execute]
```

Reads `config.json` (`identity.didSeedHex`, decrypted with the passphrase) to locate the key that signs the server's own rotation log, and the database through the same `YB_*` variables as the server. Environment: `TSP_SEED_PASSPHRASE` (required), `BOUNDARY_KEYSTORE_PATH`, `UTILITY_DATA_DIR`, `NODE_NAME`, `YB_HOST`, `YB_PORT`, `YB_DATABASE`, `YB_USER`, `YB_PASSWORD`. The key store file is created only by an executed `provision`. The publication entry is appended to the server's own rotation log in the database; its signed `createdAt` is stored verbatim, so the entry resolves from the log. The server must have been started once (it creates its identity) and its `identity.didSeedHex` must be present.

### Agent (did:scid:vh)

```
P2PTS_AGENT_PASSPHRASE=... node --conditions=development --experimental-strip-types packages/app-api/src/cli/boundary-key.ts <command> --agent NAME [--generation N] [--execute]
```

Wraps the `ScidVhAgent` operations (`provisionBoundaryKey`, `publishBoundaryKey`, `retireBoundaryKey`, `destroyBoundaryKeySecret`). Environment: `P2PTS_AGENT_PASSPHRASE` (required), `P2PTS_HOME`. The agent is started for the operation with the Trust Task listener forced off and stopped afterwards. A did:peer:4 agent is refused. Publication and retirement are stored in the agent's own log; the push to the utility server happens when the agent next runs connected, so confirm through the resolver (step 3 below) before the cutover.

## Provision and cut over

1. `provision --generation 1`. The output carries the key fingerprint.
2. `publish --generation 1` (run it first without `--execute` to see the entry validate).
3. Check: resolve the DID through the public resolver; confirm `source` is `log`, the chain is valid, and `#key-boundary` carries the fingerprinted key (`status` prints the fingerprint the process holds).
4. Wait for propagation to every verifier's resolver cache.
5. Set `TRUST_TASKS_BOUNDARY_KEY=dedicated` and `BOUNDARY_KEY_CUTOVER_AT=<a time after step 4>` and restart. Check the log line `signer.installed` (mode, generation, fingerprint, cutover).

Documents created after the cutover verify only under `#key-boundary`; `#key-1` is refused for them once the key set at `created` lists the dedicated key.

The utility server checks at start-up that its own rotation log publishes the key it holds (the boundary method is taken from the latest entry of that log; the rest of its runtime document is unchanged).

## Rotation

1. `provision --generation N+1`.
2. `rotate --generation N+1` replaces the key of `#key-boundary` in a new log entry. Documents created before that entry still verify under the old key (time-pinned resolution).
3. Wait for propagation, set `BOUNDARY_KEY_GENERATION=N+1`, restart. Until the restart the process holds generation N and a restart on generation N is refused (`notPublished`).
4. After documents signed with generation N are outside every retention need, `destroy --generation N`.

Who may rotate: whoever can run the CLI as the agent with its passphrase, or hold the utility server key store, its configuration and passphrase. Nothing is reachable over the network.

## Cutover rollback and retirement

1. `retire` appends an entry that removes `#key-boundary` and its `authentication` entry. The document is back to `#key-1` only; documents signed with the dedicated key before the entry still verify.
2. Wait for propagation, unset `TRUST_TASKS_BOUNDARY_KEY` (or set it to `key-1`) and restart.
3. Optionally `destroy --generation N`.

Rolling back before step 1 of provisioning needs only unsetting the variable and restarting.

## Backup and restore

- Back up the key store file together with its passphrase (separately), after each provisioning.
- Restore: put the file at its path, set the same passphrase, start in dedicated mode. A wrong passphrase or damaged file is `corrupt`; an absent generation is `missing`; both refuse.
- Loss of the key store with the dedicated mode on: the process refuses. Recover by provisioning the next unused generation, `rotate` (replaces the key of `#key-boundary`; use `publish` if `retire` was run), and moving `BOUNDARY_KEY_GENERATION`; or roll back as above.
- The DID document and rotation log need no special backup.

## Logs

Lines are `[trust-tasks] {"event":...}`. Fields never include keys, seeds, passphrases or tokens (such field names and binary values are redacted by the formatter); fingerprints and generations are logged.
