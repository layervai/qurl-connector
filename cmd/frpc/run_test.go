package main

import (
	"context"
	"strings"
	"testing"

	"github.com/fatedier/frp/assets"

	nhpconfig "github.com/layervai/qurl-connector/pkg/config"
)

func TestStartFRPFromConfigRejectsInvalidLogLevel(t *testing.T) {
	oldLevel := logLevel
	logLevel = "loud"
	t.Cleanup(func() { logLevel = oldLevel })
	disabled := false
	err := startFRPFromConfig(context.Background(), "", "machine", &nhpconfig.Config{
		Server: nhpconfig.ServerConfig{Protocol: "tcp"},
		Audit:  nhpconfig.AuditConfig{Enabled: &disabled},
	}, "agent", nil)
	if err == nil || !strings.Contains(err.Error(), "invalid log level") {
		t.Fatalf("startFRPFromConfig error = %v, want invalid log level", err)
	}
}

func TestAdminAuthPassword(t *testing.T) {
	t.Run("uses Desktop secret", func(t *testing.T) {
		got, err := adminAuthPassword(&nhpconfig.AdminConfig{Password: "desktop-secret"})
		if err != nil || got != "desktop-secret" {
			t.Fatalf("adminAuthPassword = %q, %v", got, err)
		}
	})
	t.Run("rejects unknown machine fallback", func(t *testing.T) {
		setCachedMachineIDForTest(t, unknownMachineID)
		if _, err := adminAuthPassword(&nhpconfig.AdminConfig{}); err == nil {
			t.Fatal("adminAuthPassword accepted an unknown machine ID")
		}
	})
}

func TestAdminDashboardAssetsAreNotEmbedded(t *testing.T) {
	if assets.FileSystem != nil {
		t.Fatal("dashboard assets were registered in the connector binary")
	}
}
