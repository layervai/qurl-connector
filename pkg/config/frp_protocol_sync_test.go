package config

import (
	"slices"
	"sort"
	"strings"
	"testing"

	frpvalidation "github.com/fatedier/frp/pkg/config/v1/validation"
)

// TestServerProtocolAllowlistMatchesFRPSupportedTransportProtocols kills the
// hand-sync risk documented on validate.go's server.protocol switch ("kept in
// sync by hand" with FRP's v1 validator): the FRP fork is an importable
// dependency, so the authoritative set — the exported
// validation.SupportedTransportProtocols slice the FRP client itself enforces
// (pkg/config/v1/validation/client.go) — is compared here against what our
// Validate actually accepts, on every `make test` run and on every FRP
// version bump.
//
// The comparison is behavioral rather than a source-literal mirror: for every
// candidate value we probe Validate and require accepted == (member of FRP's
// set, or the empty string). Empty is the one deliberate difference —
// validate.go allows "" as "FRP default" and applyDefaults resolves it to
// "tcp" on the Load path, while FRP's own validator never sees an empty value
// (FRP's client resolves it to tcp before validation).
//
// Candidate universe: the live FRP slice catches FRP ADDING a protocol our
// switch does not know (the config would bounce here while FRP supports it).
// The static probes pin every protocol our switch accepts today plus
// never-supported spellings, so FRP REMOVING or renaming a protocol our
// switch still accepts also fails loudly (that config would pass Validate
// only to die inside FRP at runtime — the exact failure mode the allowlist
// exists to prevent). A conscious update to validate.go's switch, this
// candidate list together is the intended response to either failure.
func TestServerProtocolAllowlistMatchesFRPSupportedTransportProtocols(t *testing.T) {
	frpSet := make(map[string]struct{}, len(frpvalidation.SupportedTransportProtocols))
	for _, protocol := range frpvalidation.SupportedTransportProtocols {
		if protocol == "" {
			t.Fatalf("FRP SupportedTransportProtocols contains an empty entry; the empty-string carve-out below is no longer sound: %q", frpvalidation.SupportedTransportProtocols)
		}
		if _, dup := frpSet[protocol]; dup {
			t.Fatalf("FRP SupportedTransportProtocols contains duplicate %q: %q", protocol, frpvalidation.SupportedTransportProtocols)
		}
		frpSet[protocol] = struct{}{}
	}
	if len(frpSet) == 0 {
		t.Fatal("FRP SupportedTransportProtocols is empty; the import no longer reaches FRP's v1 validation set")
	}

	candidates := map[string]struct{}{
		// The deliberate Connector-side extra: empty means "FRP default";
		// applyDefaults resolves it to tcp on the Load path.
		"": {},
		// Every value validate.go's switch accepts today. Static on purpose —
		// these must keep being probed even if FRP drops them from its slice,
		// or a removal would go undetected.
		"tcp": {}, "kcp": {}, "quic": {}, "websocket": {}, "wss": {},
		// Never-supported spellings: FRP server-side-only or retired transports
		// and non-exact spellings of supported ones. All must stay rejected.
		"sudp": {}, "xtcp": {}, "wss-h2": {},
		"TCP": {}, " tcp": {}, "tcp ": {},
	}
	for _, protocol := range frpvalidation.SupportedTransportProtocols {
		candidates[protocol] = struct{}{}
	}
	ordered := make([]string, 0, len(candidates))
	for candidate := range candidates {
		ordered = append(ordered, candidate)
	}
	sort.Strings(ordered)

	for _, candidate := range ordered {
		cfg := &Config{
			Server: ServerConfig{Protocol: candidate},
			Routes: []Route{{ID: "web", Type: RouteTypeHTTP, LocalIP: "127.0.0.1", LocalPort: 8080}},
		}
		err := Validate(cfg)
		if err != nil && !strings.Contains(err.Error(), "not a supported FRP transport") {
			t.Fatalf("probe fixture drift: Validate(protocol %q) failed for a non-protocol reason: %v", candidate, err)
		}
		accepted := err == nil
		_, inFRPSet := frpSet[candidate]
		want := candidate == "" || inFRPSet
		switch {
		case accepted && !want:
			t.Errorf("Validate accepts server.protocol %q but FRP's SupportedTransportProtocols does not list it; the config would pass validation only to fail inside FRP at runtime — remove it from validate.go's switch", candidate)
		case !accepted && want:
			t.Errorf("Validate rejects server.protocol %q but FRP's SupportedTransportProtocols lists it; add it to validate.go's switch after auditing the TLS/egress implications", candidate)
		}
	}

	// Belt-and-braces pin of today's exact FRP set. Redundant with the probes
	// above for drift DETECTION, but on failure it prints both sets whole, so
	// the operator sees the full delta rather than one candidate at a time.
	wantToday := []string{"kcp", "quic", "tcp", "websocket", "wss"}
	gotFRP := make([]string, 0, len(frpSet))
	for protocol := range frpSet {
		gotFRP = append(gotFRP, protocol)
	}
	sort.Strings(gotFRP)
	if !slices.Equal(gotFRP, wantToday) {
		t.Errorf("FRP SupportedTransportProtocols changed: got %q, previously %q; re-audit validate.go's server.protocol switch and its kcp/quic egress_local_ip carve-out, then update this pin", gotFRP, wantToday)
	}
}
