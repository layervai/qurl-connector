# Repository guide

This file is the concise repository contract for coding agents. Human
contributors should also read [CONTRIBUTING.md](CONTRIBUTING.md).

## Architecture

- `pkg/share` is the single production NHP/FRP lifecycle implementation.
- `cmd/frpc` composes the standalone binary from reusable packages; it must not
  grow another native registration, refresh, knock, or FRP supervisor.
- NHP admission is resource-bound. Keep public resource ID, knock resource ID,
  connector/routing ID, session ID, and serving epoch distinct.
- The macOS managed daemon is credential-free. Account-authenticated
  desired-state changes belong to the foreground `qurl` command. Linux and
  Windows use the explicit foreground path until a reviewed per-user service
  manager exists for those platforms.
- Session renewal is make-before-break and becomes ready only when every
  configured FRP proxy reaches its running phase.
- Per-resource failures must not tear down healthy sibling shares.

## Required validation

Run focused tests while editing, then:

```bash
make test
make test-race
make lint
make vet
make verify-deps
go test ./.github/scripts
```

Tests in this public repository are hermetic. Do not add credentials, private
endpoints, cloud account identifiers, customer data, or live rollout evidence.

## State and security

- Persistent state, IPC directories, and macOS LaunchAgent state are owner-only
  and reject symlinked or permissive parents.
- Persisted lifecycle updates are monotonic: serving epochs cannot regress and
  immutable resource identities cannot change in place.
- Automatic assignment recovery uses bounded persisted backoff. Authenticated
  denials and malformed replies are not assignment-refresh signals.
- Never log enrollment credentials, device keys, account bearers, NHP tokens,
  or complete unredacted state.

The repository publishes a Go module source tag only. Users install the
`qurl` binary, which embeds this module. `cmd/frpc` is a developer and
diagnostic command and must not gain a release-binary, container, installer,
or Homebrew distribution path.

## Scopes

Use one of these Conventional Commit scopes when practical:

- `share` — native admission and FRP session lifecycle
- `agent` — enrollment, assignment, or durable agent state
- `config` — route/config parsing and generation
- `service` — systemd/launchd service management
- `frpc` — standalone command behavior
- `audit` — audit event pipeline
- `release` — module tags, provenance, and publishing
- `ci` — repository automation
- `docs` — public documentation
- `deps` — dependencies

Choose `other` for a genuinely cross-cutting change.
