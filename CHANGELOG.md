# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Process wiring and key custody for the dedicated `#key-boundary` key. The agent runtime
  validates its listener settings strictly (a bad port, the UI port, a tier other than 1
  or 2, an unknown propose policy or an empty host now fail instead of falling back),
  closes the listener gracefully, and writes structured one-line `[trust-tasks]` log
  events that redact key material.
- Key custody: the key is random, stored in the existing encrypted key store under the
  agent passphrase (type `boundary-ed25519-g<N>` per identifier), and never derived or
  overwritten. `ScidVhAgent` gains `provisionBoundaryKey`, `publishBoundaryKey`,
  `retireBoundaryKey` and `destroyBoundaryKeySecret`; the rotation and retirement
  entries may change `#key-boundary` only.
- Operator CLI `packages/app-api/src/cli/boundary-key.ts` (`provision`, `publish`, `rotate`,
  `retire`, `destroy`, `status`). Mutating commands are a dry run unless `--execute`; the
  passphrase comes only from `P2PTS_AGENT_PASSPHRASE`; output never contains key material.
- Runbook: `docs/trust-task-boundary-key-runbook.md`.

### Changed
- A new `installProcessBoundarySigner` applies the gate for a process; the agent uses it. With
  the gate on and the key missing, damaged, unpublished
  or of a stale generation, the agent starts no listener and leaves no signer installed. It
  never falls back to `#key-1`.

### Upgrade notes
- No schema change, no migration.
- Default off. New opt-in variables: `TRUST_TASKS_BOUNDARY_KEY` (`dedicated`),
  `BOUNDARY_KEY_CUTOVER_AT`, `BOUNDARY_KEY_GENERATION` (default 1) and
  `BOUNDARY_KEY_MAX_PROOF_AGE_SECONDS` (default 600), alongside the listener variables from
  the earlier package. With them unset the agent signs `#key-1` and behaves as before.
- Dedicated mode is available to `did:scid:vh` agents only; a `did:peer:4` agent is refused.
- A mistyped gate value is fatal for the agent's listener, where it previously signed
  `#key-1` and reported a problem string.
- The CLI publishes to the agent's own log; the push to the utility server happens when the
  agent next runs connected. Confirm through the resolver before setting the cutover.

### Added
- A dedicated `#key-boundary` signing key for Trust Task documents, as a library behind a
  default-off gate. `updateDocument` and `addBoundaryKey` publish the key through a
  metadata-only log entry that must carry the previous document forward; a time-pinned
  key resolver answers `did:scid:vh` key sets as of `proof.created` from the validated
  log; a verifier key policy bounds `created` against the verifier's own clock and
  retires `#key-1` after the cutover for identifiers that list `#key-boundary`; the
  signer signs with `#key-1` before the cutover time and `#key-boundary` from it on, and
  only when the document publishes the key it holds under `authentication`.
- `resolveBoundaryKeyConfig` reads the gate. A mistyped value is not honoured and reports
  why.

### Upgrade notes
- No schema change, no migration. Requires the carry-forward fix and the spec-aligned
  pipeline from the earlier packages.
- Default off and byte-identical when off: the gate is `TRUST_TASKS_BOUNDARY_KEY=dedicated`
  together with `BOUNDARY_KEY_CUTOVER_AT` (RFC 3339 time with a zone); with either missing
  the signer and verifier behave exactly as before and sign `#key-1` (a test pins this).
  `BOUNDARY_KEY_MAX_PROOF_AGE_SECONDS` sets the verifier freshness bound (default 600).
- No process reads these variables in this package; a host opts in by calling
  `resolveBoundaryKeyConfig`. Process wiring and key custody follow in the next package.

## [0.2.0] - 2026-10-30

### Added
- Leveled, dependency-free logger (`@p2p-trust-stack/core/util/logger`) — every log
  line the stack emits now routes through one gate, controlled by the `P2PTS_LOG_LEVEL`
  environment variable (`silent` | `error` | `warn` | `info` | `debug`) or programmatically
  with `setLogLevel()` / `setLogSink()`. The default is `warn`, so the packages are quiet
  unless a host asks for more.
- Logging from a config file (`@p2p-trust-stack/core/config/logging-env`) — an app can
  keep its verbosity in a `.env` (`P2PTS_LOG_LEVEL`, `CEREMONY_TRACE`) instead of an
  environment variable, because `P2PTS_LOG_LEVEL=info node …` is POSIX-shell syntax that
  cannot live in a `package.json` script on Windows and does not exist where a native host
  launches Node (Capacitor). Resolution order is `setLogLevel()` > config file >
  `P2PTS_LOG_LEVEL` > `warn`, and a missing or malformed file is never fatal.
  Entry points: `applyLoggingEnv()` / `getEffectiveLogging()`.
- `setCeremonyTrace()` / `isCeremonyTraceEnabled()` (`core/relationship/ceremony-trace`) —
  the `[CEREMONY]` OOBI→RFI→RFA trace is now switchable programmatically and from a config
  file, not only via the `CEREMONY_TRACE` environment variable.
- `createLoggingConfigApi()` (`@p2p-trust-stack/app-api`) — the `logging-config` domain, so
  every front end reads and applies the same `.env` logging block identically.
- Bootstrap/relay configuration domain (`@p2p-trust-stack/app-api`
  `domains/bootstrap-config`) — typed access to the bootstrap/relay `.env` for front ends,
  including the selectable-VTN role-split `.env`.
- Ordered dial-candidate ladder (`@p2p-trust-stack/core/transport/dial-candidates`) and a
  hardened relay-health check (`core/transport/relay-health`), so connections survive
  relay-only and NAT'd paths.

### Changed
- `explainFailure()` now distinguishes a `connection` failure (a join or connect — nothing
  was kept locally, and a retry may be running) from a `mutation` (accepted locally and
  queued for the server), so it no longer tells a user their "change has been kept locally"
  after a failed connection.

### Fixed
- Agents on separate routers behind NAT that share a `192.168.1.x` subnet are no longer
  treated as if they were on the same LAN.
- Transport: `bootstrap-client` and `libp2p-transport` no longer stall or crash on slow or
  interrupted server responses.

## [0.1.0] - TBD

### Added
- `@p2p-trust-stack/core` — initial public release of the protocol stack
  (`crypto`, `did`, `keystore`, `tsp`, `transport`, `relationship`, `vtc`, `tx`,
  plus the shared `db`, `services`, `platform`, `exchange` and `tsp-handlers`
  modules).
- `@p2p-trust-stack/app-api` — initial public release of the agent application
  API (`createAgentStack`, the `TrustStack` domains, the closed event
  catalogue, the `Host` seam, the durable stores and the DTOs).
- Initial public monorepo scaffold: two published packages
  (`@p2p-trust-stack/core` and `@p2p-trust-stack/app-api`), dual-license
  (GPL-3.0 + commercial), `exports` maps, build config, and governance docs.

[Unreleased]: https://github.com/TrustStackers/p2p-trust-stack/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/TrustStackers/p2p-trust-stack/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/TrustStackers/p2p-trust-stack/releases/tag/v0.1.0
