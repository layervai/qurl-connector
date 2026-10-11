# Public publishing isolation design

Status: proposed future work. Implementation and rollout need a separate plan.

Public CRIDs let unknown people and agents use a published app. The app must
run with limited access to the publisher's machine. Assume that a consumer
can exploit the app and execute arbitrary code inside it. The isolation
boundary must limit what that code can reach.

This design covers local HTTP apps. Public access stays anonymous. Email
capture, invitations, payment, and private access decisions are separate
controls and are outside this design.

## Current boundary

The Connector admits a resource through NHP and forwards traffic through FRP
to its configured HTTP target. [`pkg/share`](../pkg/share) owns that lifecycle;
[`pkg/config/target.go`](../pkg/config/target.go) parses the target address.
Neither function starts the target inside an app sandbox. Restricting tunnel
access does not restrict the target process's files, credentials, or network.

An app already running as the publisher can have access to the publisher's
home directory and services. Putting a proxy in front of that process does
not remove its permissions. It must be restarted inside a restricted
environment before LayerV can describe it as isolated.

Access expiry stops access through LayerV. It does not recover copied data,
undo changes in another service, or remove a compromise from a running app.

## Proposed execution boundary

Use one disposable Linux VM for each published workload. Keep the qURL CLI,
Connector, admission keys, and VM control process outside the guest. Start the
app in the guest under a non-root user, with a read-only base image and bounded
writable scratch space. A container inside the guest can package the app; the
VM remains the boundary that protects the publisher's host.

Do not create a VM for each consumer, request, or qURL link. One running app
serves many consumers. The existing Connector session grouping can still
carry many isolated workloads without giving the guests access to each other.

```text
consumer
   |
   v
qURL access enforcement -- NHP/FRP -- host Connector
                                         |
                                  fixed app endpoint
                                         |
                                  dedicated app VM
                                  app + chosen data

host CLI, Connector keys, VM control, and other apps stay outside the VM
```

Begin with one supported Linux/KVM runtime. Firecracker with its jailer is a
concrete candidate, subject to a compatibility and performance trial. Use its
maintained VM implementation and host-hardening guidance instead of writing
a hypervisor. Its KVM model is not a native macOS or Windows implementation.
Those platforms need a separately tested adapter to an existing VM runtime
that supplies the same boundary. An unsupported host must report that it
cannot start isolated publishing; it must not quietly run the app on the host.

An ordinary host container is useful protection, but it shares a kernel with
the host. Do not equate a default container, loopback listener, tunnel, or
TPM-sealed Connector state with this app isolation contract. A different
runtime, such as gVisor, needs its own compatibility and adversarial validation
before it can be described as an equivalent supported profile.

## Files and build steps

Copy an explicit set of app inputs into the guest. Do not mount the
publisher's home directory, an entire working directory, or writable host
paths. Resolve each input path before copying it; refuse a symlink or path
that escapes the selected input root. Exclude credential stores, `.env`
files, version-control metadata, and agent memory unless the publisher has
selected a specific required input. A filename exclusion or secret scanner
alone does not prove that the selected content is safe to publish.

Run package installation, build scripts, and the app inside the boundary.
Do not run a guest-supplied build or launch command on the host. Build access
to package sources is an explicit network policy that ends when the build
ends; the serving app does not inherit unrestricted build-time access.

Use a read-only source snapshot and a separate guest scratch disk. A guest
must not change host source that an assistant or developer will later execute.
Export guest outputs only through an explicit operation that treats them as
untrusted data. Updates create another selected snapshot and use the existing
resource lifecycle to replace the serving app safely.

## Credentials and network

The guest receives only the app credentials the publisher selected. Use
service credentials with the least permissions that the app needs. Never
inherit the host environment, account bearer, Connector state, SSH agent,
credential helper, container socket, VM control socket, or cloud credentials.
Keep control directories owner-only and outside every guest export.

The host Connector forwards to one configured app endpoint on an isolated
guest connection. The guest must not be able to initiate a connection to the
host Connector, VM management API, host loopback services, local network,
another guest, or cloud metadata. A host firewall or trusted boundary process
enforces this rule outside the guest. A compromised guest cannot change it.

Serving egress is denied by default. Permit only destinations the publisher
selected, with the required protocols. A policy must cover IPv4, IPv6, DNS,
redirects, and destination changes after DNS resolution. Resolve and validate
the actual destination at connection time. Do not implement an allowlist
solely as a string check of the app's URL. Required external services should
use scoped credentials and bounded spending where that service supports it.

The app endpoint has no direct public listener and cannot bypass qURL access
enforcement. The guest cannot choose another tunnel target or ask the
Connector to publish more routes. Authentication and operation permissions
inside the app remain necessary: isolation does not make its own data or
external service permissions harmless.

## Resource limits and lifecycle

Set per-workload limits for CPU, memory, processes, scratch disk, and network
use. Enforce them outside the guest. An app that exhausts its budget must not
stop sibling shares or fill the host disk. Guest logs are bounded, escaped
untrusted text; instructions in them cannot change publishing policy.

Before admitting a public route, check that the intended VM, image, endpoint,
and policy are running and that the app answers a health probe. If a required
protection cannot be installed or verified, leave that resource unavailable.
Do not fall back to the original unrestricted host process.

Record a small, owner-only workload descriptor with the existing desired
share state: workload ID, input/image digest, runtime profile and version,
endpoint, limits, network policy, and secret references. Store references to
secrets, not their values. Keep app execution state separate from CRID,
resource, NHP session, and serving-epoch identities.

A restart reconciles the saved descriptor before reconnecting the route.
Replacement must fence the old endpoint and use the existing safe session
and serving-epoch rules. Failure of one VM affects only its workloads.
Stopping a workload withdraws its routes and terminates its processes before
releasing its private network. Delete scratch data under an explicit retention
policy, with a later cleanup attempt if the first removal fails. Deletion does
not undo an external side effect or revoke a credential already copied.

## Publisher and assistant flow

The publisher can say, "Make this app and share it publicly." A tool-capable
assistant builds the app in the supported boundary and reports the public
address only after the app and isolation checks pass. It asks only for facts
that affect the app's permissions, such as a required data folder or service.
Natural language supplies intent; structured, server-checked policy supplies
permissions. App text and tool output cannot authorize additional access.

An existing unrestricted app needs a relaunch from known inputs. If LayerV
cannot reproduce or launch it safely, say that isolated publishing is not
available for that app. Do not describe the existing target as isolated.
Private access can reduce its audience, but does not establish host isolation.

The CLI, browser, skill, and API result must distinguish access mode from
execution protection. Report the effective protection and supported runtime,
not merely the publisher's requested setting. New flags and result fields
are a later API/CLI design; this document does not claim they exist today.

## Integration responsibilities

The qURL CLI owns workload preparation and the local publisher interaction.
The local workload runner owns VM start, stop, reconciliation, and externally
enforced policy. Reuse an existing runtime; keep the runner's privileged
interface small and reject arbitrary host paths, commands, and sockets.

The Connector continues to use the single production lifecycle in
`pkg/share`. It accepts the runner's fixed app endpoint, not untrusted guest
instructions. Isolation does not require another NHP/FRP implementation or
per-request identity-service call. Platform metadata, browser copy, and the
customer skill must agree on what the runtime actually enforces.

## Acceptance before a public protection claim

Use a fixture app that deliberately gives a consumer shell execution. Check
the boundary with that access, rather than only sending harmless HTTP calls.
Use synthetic credentials and isolated test machines.

| Attempt or event | Required result |
|---|---|
| Read synthetic host home, SSH/cloud keys, CLI state, or agent memory | No host file or credential is reachable |
| Modify host source or use a symlink to escape selected inputs | Refused; no host write |
| Reach a host service, another guest, local network, or metadata address | Refused, including IPv6 and DNS/redirect variants |
| Open the app without the qURL route | No direct public path |
| Change the target, mounts, credentials, egress, or resource limits from the guest | Refused by the host boundary |
| Access an explicitly permitted input or service | Works within the granted scope |
| Exhaust CPU, memory, process count, disk, or log budget | Workload is bounded; sibling share remains usable |
| Crash app, VM, runner, or Connector; restart the host | Reconciliation retains resource identity and never opens an unrestricted fallback |
| Replace, stop, or expire a share during active HTTP/WebSocket traffic | Existing access/session limits hold; old endpoint cannot serve through a new route |
| Supply hostile app text, guest output, or a log instruction | Cannot change assistant consent or host policy |

Measure app start time, idle and peak memory, steady-state and streaming
latency, concurrent consumers per workload, and replacement interruption on
the actual supported runtime. Establish budgets from those measurements.
Connector-only measurements do not establish the VM path's performance.

## Limits and source guidance

VM or runtime vulnerabilities remain possible. Keep the host, guest image,
and runtime patched. This design limits damage; it does not guarantee that
no future exploit can cross the boundary. Data and credentials deliberately
given to the app remain exposed if the app is compromised. Those permissions
must be small enough for the publisher to accept that loss.

- [NIST Application Container Security Guide](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-190.pdf)
  explains container, host, shared-kernel, and network risks.
- [Docker Engine security](https://docs.docker.com/engine/security/) explains
  the authority of the daemon, mounts, and container capabilities.
- [Firecracker jailer guidance](https://github.com/firecracker-microvm/firecracker/blob/main/docs/jailer.md)
  describes the additional host boundary for the proposed Linux/KVM trial.
- [gVisor architecture](https://gvisor.dev/docs/) describes an alternative
  application-kernel boundary and its differences from containers and VMs.
