# Private gateway enrollment

The `private-gateway-a` target in **Rotate sandbox tunnel enrollment** prepares
one registered identity for three private routes. Current service authorization
binds each resource to one serving identity; multiple agents ensuring the same
owner/slug replace that binding. Only gateway A may enroll or serve these routes.
Stop earlier gateway services and one-off tasks before native enrollment or
replacement. Preserve dormant B/C identity storage, and never copy identities.

## Protected configuration

After allocating three distinct private tunnel resources under the reviewed
service-owner account, copy their authenticated readback into the protected
sandbox environment secret `QURL_PRIVATE_GATEWAY_CONFIG_JSON`:

- `owner_id`: the account returned by `GET /v1/me` using the protected account key.
- `routes`: exactly `uploader`, `fileviewer`, and `detect`. Each value contains
  `slug`, `crid`, `connector_routing_id`, and `knock_resource_id` from that same
  account's resource record. These are the same pins used by the infrastructure
  configuration, not values derived from keys, DNS names, or test fixtures.

Do not reuse existing public fileviewer/detect slugs. Review the chosen owner's
native home-cell assignment before allocating resources; the serving identity
and resources must belong to the same cell. This workflow does not allocate
resources, move account placement, or enable sharing. All three resources must
already be active with sharing on and a positive serving epoch.

The workflow verifies the account identity and exact route pins before minting
anything. It requires the existing protected sandbox API endpoint and digest,
account API key with `qurl:agent`, and write-only recovery role. Private A and
the older fileviewer A target share the preserved bootstrap parameter, so runs
are serialized. Choose only `private-gateway-a` for the shared private gateway.

## Credential authority

The older fileviewer targets also use `target=agent`. Although their enrollment
request carries one optional connector claim, the current native producer
classifies `agent_bootstrap` as `bootstrap` and does not retain that claim on the
registered identity. Do not treat those targets as a narrower native authority
boundary. The new target adds the reviewed owner/three-route preflight and avoids
the legacy target's automatic sharing mutation; it does not create a new native
privilege class.

The API request is `kind=enrollment_token`, `target=agent`, `claims=[]`, and
`expires_in=1h`, with no caller-specified scopes. Current native assignment
classifies this as one-use `bootstrap`, owned by the selected account. It is
consumed by successful native enrollment. The service does not support a
three-claim enrollment token: an unbound bootstrap authorizes this enrolled
identity to ensure resources belonging to its owner, beyond the three local
route pins. Use the dedicated reviewed service owner and keep its account key
out of the runtime. This authority choice must be reviewed before deployment.

Only the short-lived token is written to the existing A bootstrap parameter.
The response must confirm `enrollment_token`, `agent`, and no claims (the API
omits an empty claims field). The existing idempotency, deadline, ambiguous
outcome reporting, and write-only SSM installation behavior remain in force.
Use the infrastructure's stopped-gateway preflight, one-off enrollment, then
credential-free restart proof. Clear the enrollment generation before activation.
No recovery workflow run is a private upload, viewer, issuer, or detect smoke.
