package strictproof

import (
	"testing"

	"github.com/layervai/qurl-connector/pkg/audit"
)

// strictproof deliberately re-declares the Connector audit event strings
// instead of importing pkg/audit: the verifiers pin the stable wire surface
// (pkg/audit/entry.go) independently of the emitter, so a rename in pkg/audit
// fails loudly here instead of silently propagating into the proofs (see
// doc.go — a verifier never inherits what it is supposed to check). These
// strings are a breaking change for audit-log consumers; a deliberate rename
// must update BOTH constant sets (plus the operator docs pkg/audit/entry.go
// lists) in the same change.
func TestEventStringsMatchAuditWireSurface(t *testing.T) {
	pairs := []struct {
		name    string
		pinned  string // strictproof's independent pin
		emitted string // what pkg/audit actually emits
	}{
		{"EventKnockSuccess", EventKnockSuccess, audit.EventKnockSuccess},
		{"EventLoginSuccess", EventLoginSuccess, audit.EventLoginSuccess},
		{"EventProxyAllow", EventProxyAllow, audit.EventProxyAllow},
		{"EventBootstrapOK", EventBootstrapOK, audit.EventBootstrapSuccess},
	}
	for _, pair := range pairs {
		if pair.pinned != pair.emitted {
			t.Errorf(
				"strictproof.%s = %q but pkg/audit emits %q; the verifier pin and the emitter constant must change together",
				pair.name, pair.pinned, pair.emitted,
			)
		}
	}
}
