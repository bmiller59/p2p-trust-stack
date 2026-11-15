# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Opt-in Trust Task boundary module for the agent (`@p2p-trust-stack/app-api`): a listener
  that serves `vrc/relationships/propose` (a held proposal is answered by next-step and
  lapses after seven days) and `vrc/relationships/issue`, the witness-share task,
  ceremony documents, task consent and credential exchange, on the spec-aligned pipeline.
- Each VRC exchange uses its own relationship `did:peer:4`, recorded in
  `vrc_exchange_relationship_dids`. Its secret is encrypted under the agent passphrase and
  deleted when the relationship ends.
- Storage for shared witness credentials and credential presentations.
- A JSON-RPC adapter (stdio and HTTP) for the DTGWG Trust Task conformance suite, with
  generated results under `packages/app-api/conformance/results`.
- Proof options for signer challenge and domain; the verifier reports `challengeMismatch`
  and `domainMismatch`.

### Changed
- The VRC receive participant applies a conformant credential at commit rather than at
  prepare.

### Upgrade notes
- Migrations `0022_vrc_exchange_relationship_dids.sql`, `0023_witness_shares.sql` and
  `0024_credential_presentations.sql`, `SCHEMA_VERSION` 25 to 28. All three are
  `CREATE TABLE IF NOT EXISTS` (plus one nullable `pending_ops` column on the transaction
  table); no existing data is rewritten. A database at 28 cannot be opened by an older
  release.
- Default off. The listener binds nothing unless `TRUST_TASKS_LISTENER=1` and
  `TRUST_TASKS_LISTENER_PORT` are both set (or the `trustTasksListener` option is passed),
  and it never shares the UI port. Further opt-in settings: `TRUST_TASKS_LISTENER_HOST`
  (default `127.0.0.1`), `TRUST_TASKS_TIER` (`1`, or `2` by default), `TRUST_TASKS_PROPOSE_POLICY`
  (`hold` by default, or `decline`) and `TRUST_TASKS_ROTATION_LOG_ENDPOINT` (a utility
  server base URL, consulted after the local store when resolving a peer's `did:scid:vh`).
- Licensing: the module is part of core and is available under GPL-3.0-only or the
  commercial licence; contributions fall under the repository's CLA.

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
