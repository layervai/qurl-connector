//go:build windows

package config

import (
	"errors"
	"strings"
	"testing"
)

func TestWindowsConfigValidationErrorExplainsGreenfieldProtectedACL(t *testing.T) {
	wantErr := errors.New("insecure inherited ACL")
	err := wrapConfigFileValidationError("existing config file", wantErr)
	if !errors.Is(err, wantErr) {
		t.Fatalf("wrapped error = %v, want original cause", err)
	}
	for _, want := range []string{"protected current-user, SYSTEM, and Administrators ACL", "move the existing qurl-proxy.yaml aside", "qurl-connector add", "do not copy the old file back"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("wrapped error = %q, want guidance %q", err, want)
		}
	}
}

func TestWindowsNonConfigValidationErrorIsUnchanged(t *testing.T) {
	wantErr := errors.New("lock validation failed")
	if got := wrapConfigFileValidationError("config transaction lock", wantErr); !errors.Is(got, wantErr) || got.Error() != wantErr.Error() {
		t.Fatalf("lock validation error = %v, want unchanged %v", got, wantErr)
	}
}
