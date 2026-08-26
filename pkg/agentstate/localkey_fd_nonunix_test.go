//go:build !unix

package agentstate

import (
	"strings"
	"testing"
)

func TestLocalKeyProviderInheritedDescriptorUnsupported(t *testing.T) {
	t.Setenv(EnvKeyProvider, KeyProviderLocalKey)
	t.Setenv(EnvLocalKeyFD, "3")
	resetLocalKeyProviderCache(t)
	if _, err := newLocalKeyProviderFromEnv(); err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("newLocalKeyProviderFromEnv error = %v, want unsupported platform", err)
	}
}
