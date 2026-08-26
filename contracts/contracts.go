// Package contracts embeds the machine-readable cross-repo wire-contract
// snapshots under contracts/ so in-repo tests bind production code to the
// exact bytes sibling repos vendor. See contracts/README.md for the layout,
// producer copies, and the change procedure.
//
// Production code must not import this package: the snapshots are test
// fixtures, and pkg/share's binding tests keep runtime classification and the
// JSON in agreement.
package contracts

import _ "embed"

// QRTSKnockTokenLogin is the consumer snapshot of the knock-token FRP Login
// contract with the qURL tunnel server. Bound by
// pkg/share/qrts_contract_test.go.
//
//go:embed qrts_knock_token_login_wire_contract.json
var QRTSKnockTokenLogin []byte

// QRTSRecoverableNewProxy is the consumer snapshot of the exact NewProxy
// terminal tags that require a fresh resource-bound NHP admission. Bound by
// pkg/share/qrts_contract_test.go.
//
//go:embed qrts_recoverable_newproxy_wire_contract.json
var QRTSRecoverableNewProxy []byte
