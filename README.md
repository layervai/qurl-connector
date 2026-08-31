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
contract for all production identity and session state.

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
supervisor.

See [CONTRIBUTING.md](CONTRIBUTING.md) for change and validation expectations.

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
