# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Spec-aligned Trust Task boundary pipeline in `@p2p-trust-stack/core`
  (`services/trust-tasks/boundary`), as a library with no listener of its own: typed
  error documents and the lifecycle states, a transport-agnostic consumer pipeline for
  the HTTPS binding, a DID-resolving proof verifier (`eddsa-jcs-2022` for `did:key`,
  `did:peer:4` and `did:scid:vh` issuers), signed replies and the attested tier (proof
  on every request, every reply signed), task digests and outcome evidence,
  `trust-task-next-step` and a `trust-task-discovery` 0.4 responder. The pinned
  `@openvtc/trust-tasks` runtime is 0.29.0.
- A durable accepted-id store (`AcceptedIdStore`) for duplicate suppression,
  `TransactionManager.getOutcome()` (committed, aborted, in flight or unknown) and a
  prune hook on `TxJanitor`.

### Changed
- Ceremony participants follow the specified failure rules: a late approval is refused
  with `deadlineLapsed` and the proposal is marked expired, `ceremony_reset` is allowed
  only from a failed or expired ceremony, a repeated approval is idempotent, and a
  failed step records its `error_code` and `retryable` flag.
- The legacy `policy/evaluate` handler takes its actor from the verified sender only and
  answers `permissionDenied` without one. Read-only evaluate documents are no longer
  recorded.

### Upgrade notes
- Migration `0021_trust_task_boundary.sql`, `SCHEMA_VERSION` 24 to 25: ten nullable
  columns on `trust_tasks`, the `error_code` / `retryable` columns on the proposal
  tables, and the `trust_task_accepted` table. Additive only; existing rows are
  untouched. A release that records schema version 25 cannot be opened by an older one.
- Default off: nothing in this release serves a Trust Task endpoint. The pipeline is used
  only by a host that installs it (the utility server's `POST /trust-tasks`, and the
  opt-in agent listener added in the next package). No new environment variables.

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
