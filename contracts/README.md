# Wire-contract snapshots

This directory contains machine-readable consumer snapshots for wire surfaces
shared with qURL server components. Each producer keeps a matching snapshot
beside its emit site and binds it to production code with its own tests.

Decoders are strict: unknown fields, unsupported `schema_version` values, and
trailing JSON are rejected. Even an additive shape change therefore requires a
coordinated update.

`qrts_knock_token_login_wire_contract.json` pins the knock-token FRP Login
metadata key, exact reject tag, consumer needles, and producer wire texts. Set
`QRTS_KNOCK_TOKEN_LOGIN_CONTRACT` to compare a producer snapshot locally.
The client binding lives in `pkg/share/qrts_contract_test.go`, beside the one
production NHP/FRP lifecycle implementation.

`qrts_recoverable_newproxy_wire_contract.json` pins the exact qRTS NewProxy
terminal tags that rotate a resource through a fresh NHP admission. Set
`QRTS_RECOVERABLE_NEWPROXY_CONTRACT` to compare a producer snapshot locally.

Ordinary tests remain hermetic and use the committed consumer snapshots.

## Changing a contract

1. Update the consumer and producer snapshots with their bound code and tests.
2. Bump `schema_version` for shape changes, not value-only changes.
3. Land and deploy the coordinated changes in a compatibility-safe order.
4. Never weaken strict decoding to make mismatched snapshots appear compatible.
