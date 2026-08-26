package main

import (
	"io"
	"os"
	"strings"
	"testing"

	"github.com/layervai/qurl-connector/pkg/audit"
	nhpconfig "github.com/layervai/qurl-connector/pkg/config"
)

func boolPtr(value bool) *bool { return &value }

func TestSwapAuditLoggerFromYAMLClosesOldAndUsesNewFile(t *testing.T) {
	previous := audit.SetDefault(nil)
	t.Cleanup(func() { audit.SetDefault(previous) })
	dir := t.TempDir()
	earlyPath := dir + "/early.log"
	runtimePath := dir + "/runtime.log"
	early, err := audit.NewJSONLLogger(audit.LoggerConfig{FilePath: earlyPath, MachineID: "early", Version: "test"})
	if err != nil {
		t.Fatal(err)
	}
	audit.SetDefault(early)
	audit.Default().Log(audit.Entry{Event: audit.EventBootstrapSuccess, Outcome: audit.OutcomeSuccess})
	if err := swapAuditLoggerFromYAML(&nhpconfig.Config{Audit: nhpconfig.AuditConfig{
		Enabled: boolPtr(true), FilePath: runtimePath, MirrorSlog: boolPtr(false),
	}}, "runtime", "agent"); err != nil {
		t.Fatal(err)
	}
	audit.Default().Log(audit.Entry{Event: audit.EventKnockSuccess, Outcome: audit.OutcomeSuccess})
	closeAuditLogger(audit.Default())
	audit.SetDefault(nil)
	earlyBytes, err := os.ReadFile(earlyPath)
	if err != nil {
		t.Fatal(err)
	}
	runtimeBytes, err := os.ReadFile(runtimePath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(earlyBytes), audit.EventBootstrapSuccess) || strings.Contains(string(earlyBytes), audit.EventKnockSuccess) {
		t.Fatalf("early audit file crossed logger swap: %s", earlyBytes)
	}
	if !strings.Contains(string(runtimeBytes), audit.EventKnockSuccess) || strings.Contains(string(runtimeBytes), audit.EventBootstrapSuccess) {
		t.Fatalf("runtime audit file crossed logger swap: %s", runtimeBytes)
	}
}

func TestSwapAuditLoggerFromYAMLHonorsEnvironmentKillSwitch(t *testing.T) {
	previous := audit.SetDefault(nil)
	t.Cleanup(func() { audit.SetDefault(previous) })
	t.Setenv("QURL_AUDIT_ENABLED", "false")
	path := t.TempDir() + "/runtime.log"
	if err := swapAuditLoggerFromYAML(&nhpconfig.Config{Audit: nhpconfig.AuditConfig{
		Enabled: boolPtr(true), FilePath: path, MirrorSlog: boolPtr(false),
	}}, "runtime", "agent"); err != nil {
		t.Fatal(err)
	}
	if _, ok := audit.Default().(audit.NopLogger); !ok {
		t.Fatalf("audit logger = %T, want disabled logger", audit.Default())
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatalf("disabled audit created %s: %v", path, err)
	}
}

func TestAuditEnabledFromEnvVocabulary(t *testing.T) {
	for _, test := range []struct {
		value string
		want  bool
	}{
		{"", true}, {"true", true}, {"1", true}, {"yes", true}, {"on", true},
		{"0", false}, {"false", false}, {" no ", false}, {"off", false},
	} {
		t.Run(test.value, func(t *testing.T) {
			t.Setenv("QURL_AUDIT_ENABLED", test.value)
			if got := auditEnabledFromEnv(); got != test.want {
				t.Fatalf("auditEnabledFromEnv(%q) = %t, want %t", test.value, got, test.want)
			}
		})
	}
}

func TestAuditEnabledFromEnvWarnsOnTypoAndStaysOn(t *testing.T) {
	original := os.Stderr
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = writer
	t.Cleanup(func() { os.Stderr = original })
	t.Setenv("QURL_AUDIT_ENABLED", "offf")
	if !auditEnabledFromEnv() {
		t.Fatal("unrecognized audit switch disabled audit silently")
	}
	_ = writer.Close()
	data, err := io.ReadAll(reader)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), `QURL_AUDIT_ENABLED="offf" not recognized`) {
		t.Fatalf("warning = %q", data)
	}
}
