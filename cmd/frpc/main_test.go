package main

import (
	"os"
	"testing"

	"github.com/layervai/qurl-connector/pkg/agentstate"
)

// TestMain keeps every test in this package off the host's TPM: a fresh state
// namespace would otherwise probe it and, on a machine where the TPM is
// usable, seal test state to real hardware. A test that needs another provider
// sets it with t.Setenv, which restores this.
func TestMain(m *testing.M) {
	if os.Getenv(agentstate.EnvKeyProvider) == "" {
		_ = os.Setenv(agentstate.EnvKeyProvider, agentstate.KeyProviderFile)
	}
	os.Exit(m.Run())
}
