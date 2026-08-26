package main

import (
	"fmt"
	"strings"
	"testing"

	"github.com/layervai/qurl-connector/pkg/hubpin"
)

// darkHubPinLiteral is the exact prefix the CI developer-build check greps.
const darkHubPinLiteral = "hub trust pin: none (dark build"

// TestVersionShortFlagIsRegistered prevents a refactor from leaving the Run
// body reading an unregistered flag. Assert registration rather than output:
// the Run body writes to process stdout rather than cmd.OutOrStdout().
func TestVersionShortFlagIsRegistered(t *testing.T) {
	flag := versionCmd.Flags().Lookup("short")
	if flag == nil {
		t.Fatal("version does not register --short")
	}
	if got := flag.Value.Type(); got != "bool" {
		t.Errorf("--short is %q, want bool", got)
	}
}

func TestHubTrustPinStatusDark(t *testing.T) {
	old := defaultHubServerPublicKeyB64
	defaultHubServerPublicKeyB64 = ""
	t.Cleanup(func() { defaultHubServerPublicKeyB64 = old })

	got := hubTrustPinStatus()
	want := "hub trust pin: none (dark build; the all-or-none QURL_CONNECTOR_HUB_* custom deployment triple is required)"
	if got != want {
		t.Fatalf("dark hubTrustPinStatus() = %q, want %q", got, want)
	}
	if !strings.HasPrefix(got, darkHubPinLiteral) {
		t.Fatalf("dark hubTrustPinStatus() = %q no longer starts with the CI grep literal %q", got, darkHubPinLiteral)
	}
}

func TestHubTrustPinStatusPinned(t *testing.T) {
	keyB64 := provisionedDefaultHubPinForTest(t)
	key, err := hubpin.DecodeServerPublicKeyB64(keyB64)
	if err != nil {
		t.Fatal(err)
	}
	got := hubTrustPinStatus()
	want := fmt.Sprintf("hub trust pin: hub.nhp.layerv.ai:443 %s (key sha256:%s)", keyB64, hubpin.FingerprintSHA256Hex(key))
	if got != want {
		t.Fatalf("pinned hubTrustPinStatus() = %q, want %q", got, want)
	}
}

func TestHubTrustPinStatusInvalid(t *testing.T) {
	old := defaultHubServerPublicKeyB64
	defaultHubServerPublicKeyB64 = "%%%not-base64%%%"
	t.Cleanup(func() { defaultHubServerPublicKeyB64 = old })

	got := hubTrustPinStatus()
	if !strings.HasPrefix(got, "hub trust pin: INVALID (") {
		t.Fatalf("invalid hubTrustPinStatus() = %q, want an INVALID report, never a masked dark/pinned state", got)
	}
}
