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

## Provision and cut over (did:scid:vh)

The provisioning, publishing, rotation and retirement calls exist on `ScidVhAgent` only. The utility server loads, verifies and signs with a provisioned key but has no provisioning or publishing tool yet; its dedicated mode cannot be turned on until that exists.

1. Agent: with the agent started and unlocked, call `provisionBoundaryKey(1)` on the `ScidVhAgent`. It returns the key fingerprint (hash prefix of the public key).
2. Publish: `publishBoundaryKey(1)`. This appends a metadata-only log entry that adds `#key-boundary` under `authentication` and changes nothing else, then pushes the log to the utility server.
3. Check: resolve the DID through the public resolver; confirm `source` is `log`, the chain is valid, and `#key-boundary` carries the fingerprinted key.
4. Wait for propagation to every verifier's resolver cache.
5. Set `TRUST_TASKS_BOUNDARY_KEY=dedicated` and `BOUNDARY_KEY_CUTOVER_AT=<a time after step 4>` and restart. Check the log line `signer.installed` (mode, generation, fingerprint, cutover).

Documents created after the cutover verify only under `#key-boundary`; `#key-1` is refused for them once the key set at `created` lists the dedicated key.

## Rotation

1. `provisionBoundaryKey(N+1)`.
2. `publishBoundaryKey(N+1)` replaces the key of `#key-boundary` in a new log entry. Documents created before that entry still verify under the old key (time-pinned resolution).
3. Wait for propagation, set `BOUNDARY_KEY_GENERATION=N+1`, restart. Until the restart the process holds generation N and a restart on generation N is refused (`notPublished`).
4. After documents signed with generation N are outside every retention need, `destroyBoundaryKeySecret(N)`.

Who may rotate: whoever can run code as the agent with its passphrase, or hold the utility server key store and passphrase. There is no network or UI route for any of these operations.

## Cutover rollback and retirement

1. `retireBoundaryKey()` appends an entry that removes `#key-boundary` and its `authentication` entry. The document is back to `#key-1` only; documents signed with the dedicated key before the entry still verify.
2. Wait for propagation, unset `TRUST_TASKS_BOUNDARY_KEY` (or set it to `key-1`) and restart.
3. Optionally `destroyBoundaryKeySecret(N)`.

Rolling back before step 1 of provisioning needs only unsetting the variable and restarting.

## Backup and restore

- Back up the key store file together with its passphrase (separately), after each provisioning.
- Restore: put the file at its path, set the same passphrase, start in dedicated mode. A wrong passphrase or damaged file is `corrupt`; an absent generation is `missing`; both refuse.
- Loss of the key store with the dedicated mode on: the process refuses. Recover by provisioning the next unused generation, `publishBoundaryKey` (replaces the key of `#key-boundary`), and moving `BOUNDARY_KEY_GENERATION`; or roll back as above.
- The DID document and rotation log need no special backup.

## Logs

Lines are `[trust-tasks] {"event":...}`. Fields never include keys, seeds, passphrases or tokens (such field names and binary values are redacted by the formatter); fingerprints and generations are logged.
