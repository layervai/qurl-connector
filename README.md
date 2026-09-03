# qURL Connector

qURL Connector is the local tunnel runtime for qURL. It
admits each shared resource with the Network-invisible Handshake Protocol
(NHP), then carries approved traffic over a resource-bound FRP session.

```text
local service -> qURL Connector -> qURL -> recipient
```

Users install only the `qurl` CLI. It embeds this module. On Linux, macOS, and
Windows, the CLI uses the native per-user job manager when a local share is
first published or started. The daemon resumes desired-on shares after login
and recovers automatically across sleep, wake, network changes, assignment
refreshes, and session rotation. Linux uses a systemd user service; macOS uses
launchd; Windows uses Task Scheduler. Each manager restarts failure exits, and
the next login or foreground `qurl` command repairs a clean daemon exit. Linux
fails clearly when the host has no real systemd user manager instead of
pretending that it installed a persistent background process.
The user manager must support `Type=exec`, append log output, and
`RestrictSUIDSGID`. qURL reports these requirements if the installed systemd
cannot load the managed service definition.

On Windows, native state is under `%LOCALAPPDATA%\qurl-connector`. The first
run creates the directory and its security-sensitive files with protected ACLs
for the current user, SYSTEM, and Administrators. This is a greenfield contract:
the Connector does not adopt a state directory or file with inherited or
foreign ACLs. If ACL validation fails, stop the Connector, move that state
directory aside, and start again so it can create protected state and enroll a
new identity. Connector and pinned qurl-go writers use the same protected-file
contract for all production identity and session state. A custom Windows state
path must use a local filesystem under a user-owned namespace where Windows can
flush directory updates. Network paths and system-owned parents are not
supported state locations.

`cmd/frpc` is retained for development and diagnostics. It is not a supported
customer distribution, Homebrew formula, release binary, or container image.

The developer command names two public LayerV endpoints in source:
`https://api.layerv.ai/v1` for the public API and `hub.nhp.layerv.ai:443` for
the public NHP Hub. Hostnames are not credentials. No Hub public key is
embedded; the command fails closed unless an explicit trusted key is supplied.

## Security model

- NHP admission is resource-specific. A token or session issued for one
  resource cannot register a different resource.
- The managed daemon does not retain an account bearer. Account-authorized
  lifecycle changes remain in the foreground `qurl` command.
- Connector state is owner-only and fails closed on unsafe permissions,
  symlinks, contradictory identity, or malformed persisted data.
- Session renewal is make-before-break: a replacement must reach FRP's running
  state before the old route drains.
- Assignment recovery is automatic, bounded, and persisted; normal network
  failures do not require an approval flag or reprovisioning.

Please report vulnerabilities through the repository's private
[security-advisory form](https://github.com/layervai/qurl-connector/security/advisories/new),
not a public issue.

## Build from source

Requirements:

- Go 1.26.6 or newer
- Git

All Go dependencies, including the reviewed LayerV FRP fork, are public and
available through the public Go module proxy.

```bash
make verify-deps
make frpc
./bin/qurl-connector version
```

`make verify-deps` checks the pinned FRP release against its public-proxy
checksums, source commit, and live release tag. `make frpc` builds the
developer-only command locally.

## Development

```bash
make test       # hermetic package and command tests
make test-race  # race detector
make lint       # golangci-lint
make vet        # go vet
make frpc       # build the developer-only command
```

The reusable production runtime lives under `pkg/share`. It owns native
assignment recovery, resource-bound NHP admission, FRP session readiness,
make-before-break renewal, and per-resource failure isolation. Command code
must use that implementation rather than introducing another knock/session
supervisor. `ResourceRunner` serves one route per admission;
`SessionGroupRunner` serves many routes (up to `MaxGroupRoutes`) on one
admission and one FRP session, with live route add/remove/restart and
per-route failure reporting.

See [CONTRIBUTING.md](CONTRIBUTING.md) for change and validation expectations.

## Scaling proof

`TestHermeticSessionGroupServes1000Routes` in `pkg/share` proves that one
Connector process serves many routes on one NHP admission and one FRP control
session, and measures what that costs. It runs in-process against the real
FRP client and the real FRP server from the pinned fork; the knock is a
scripted admitter and the tunnel-auth plugin is a hermetic HTTP plugin that
answers `NewProxy` the way the platform does. Everything between them is
production code on loopback.

The normal suite runs it at 50 routes. The opt-in run is:

```bash
make proof-1000   # 1000 routes with the race detector off, then 200 with it on
```

`QURL_PROOF_ROUTES` sets the route count and `QURL_PROOF_REPORT` writes the
measurements as JSON (`make proof-1000` leaves them in `bin/`). One run
asserts, in order: every route registers on the single admission and answers
through the vhost; ten routes leave and ten join with no second knock and no
sibling re-registration; one route restarts under a fresh proxy name alone;
the admission rotates and the replacement carries every route before the old
session retires, with a background request loop running across the overlap;
and one route the server rejects as `resource_not_found` is withdrawn while
every sibling keeps answering.

Measured on darwin/arm64 (Apple M5 Max, 18 cores, Go 1.27.1):

| | 1000 routes, race off | 200 routes, race on |
|---|---|---|
| `Run()` to every route serving | 76 ms | 76 ms |
| vhost sweep, every route once, 32-way | 79 ms (cold p50 2.2 ms, p99 5.9 ms) | 38 ms (cold p50 5.2 ms, p99 9.9 ms) |
| steady-state latency, 2000 requests | p50 0.31 ms, p99 0.46 ms | p50 0.67 ms, p99 1.37 ms |
| rotation: Admit to every route re-registered | 78 ms (promoted at 82 ms) | 91 ms (promoted at 94 ms) |
| drain: promotion to old proxies withdrawn | 19 ms | 57 ms |
| overlap requests / failures | 95,018 / 1 (at its route's re-registration instant, the gap below) | 8,361 / 0 (drain only) |
| goroutines per route (the FRP client's status worker) | 1.02 | 1.10 |
| open FDs at registration (baseline 15) | 19 | 19 |
| open FDs after every route was hit once | 2,085 (2.07 per route, idle work connections) | 485 |
| goroutines after that sweep | 7,172 (FRP client 2,002; 5,155 net/http and stream goroutines, mostly the in-process server's) | 1,778 |
| Go `sys` at registration / after that sweep | 53 MiB / 203 MiB | 45 MiB / 69 MiB |
| peak RSS, whole test process | 393 MiB | 875 MiB (race detector) |
| FRP server online HTTP proxies | 1000 | 200 |
| `NewProxy` admitted / rejected | 2011 / 1 | 411 / 1 |
| goroutines / FDs after stop (baseline 42 / 15) | 45 / 17 | 45 / 17 |

Registration and rotation are linear and fast, about 80 µs per route on the
server's serial `NewProxy` path, so the production rotation lead of 50 ms per
route is roughly 650 times what this machine needs. The steady-state cost of
a route is one goroutine and no file descriptor. Memory and descriptors scale
with idle work connections, not routes: the FRP server keeps up to five idle
work connections per Host for 60 s, so once every route has been hit the
process holds about two descriptors per route (client and server ends,
in-process), roughly five goroutines per connection, and roughly 75 KiB of
stream buffers per connection. Goroutines and descriptors return to baseline
after stop; Go's `sys` is not handed back to the OS promptly, as usual.

Caveats: hermetic knock, hermetic tunnel-auth plugin, one machine, loopback,
in-process server (goroutine and descriptor counts include the server's
share; the breakdown is printed). Peak RSS covers the whole test process, and
the race-on figure is dominated by the detector's shadow memory; Go `sys` is
the runtime's high-water mark and includes the proof's own goroutine-dump
buffers. Peak RSS and descriptor counts are not measured on Windows. Under
the race detector the overlap loop starts only after the old proxies have
left the server (see the gap below), so the race-on overlap column covers the
drain, not the whole rotation. Server-side budgets are proven separately by
the platform.

One gap was found, and it is not in this repository. The pinned FRP client
admits a work connection only while its proxy is in the running phase, and
that phase lags the server on both edges of a proxy's life: the server adds a
new proxy to its load-balancer group inside `RegisterProxy` and only then
sends `NewProxyResp`, and `Wrapper.Stop` marks a proxy closed in the same
instant it sends `CloseProxy`. A request the server dispatches to the proxy
inside either window is refused by the client and answered 404 by the
server's reverse proxy. Under a deliberately hostile overlap load (16 workers,
no pause, about 36,000 requests per second across 20 routes) it shows as one
to three such 404s per rotation in roughly half the runs, every one at its
own route's re-registration instant; at the proof's background load it
appears about once per few hundred thousand requests (1 in 95,018 in the
published 1000-route run, 1 in about 500,000 across the 50-route runs). The
proof attributes every overlap failure to that exact instant, bounds how
many it will excuse, and fails on any failure outside it. The same
site is also a data race: `Wrapper.InWorkConn` reads the proxy phase after
releasing the wrapper's lock, so the race detector reports the dispatch
whenever it happens under `-race`, which is why the race lane starts its
overlap loop after withdrawal. The fix belongs in the FRP fork's client:
read the phase under the lock, accept work connections while a proxy awaits
its `NewProxyResp`, and keep accepting through the drain grace after
`CloseProxy` is sent.

## Developer command configuration

The standalone binary reads `qurl-proxy.yaml` from the current directory, the
binary's `etc` directory, or the user's qURL config directory. A minimal route
looks like:

```yaml
server:
  protocol: tcp

routes:
  - id: my-webapp
    type: http
    local_port: 8080
```

Resource, routing, and knock identities are issued by the qURL platform. Do
not derive or substitute one identity for another. Standard placement comes
from the authenticated NHP response; custom Hub and endpoint overrides are
intended only for deployments that own the corresponding trust configuration.

Native session operations require `QURL_CONNECTOR_NATIVE_OWNER_ID` from the
authenticated account context. The command never derives the owner from a CRID,
route, API resource, or NHP packet. AWS accounts, regions, and storage names are
private NHP server configuration and are not Connector settings or build data.

The developer command stays in the foreground:

```bash
qurl-connector run
```

## Supply chain

- Releases are immutable Go module source tags; this repository publishes no
  customer binary or container artifact.
- The module pins Go dependencies and the FRP fork's exact reviewed source
  revision and checksum.
- Dependabot, dependency review, govulncheck, CodeQL, and secret scanning gate
  changes.

## License

Licensed under the [Apache License 2.0](LICENSE).
