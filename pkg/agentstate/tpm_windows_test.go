//go:build windows

package agentstate

import (
	"errors"
	"fmt"
	"testing"

	"github.com/google/go-tpm/tpmutil/tbs"
)

// TestTBSStartupErrorsAreTransient pins that a TPM Base Services race at logon
// fails the operation instead of permanently choosing plaintext.
func TestTBSStartupErrorsAreTransient(t *testing.T) {
	for _, tc := range []struct {
		err  tbs.Error
		want error
	}{
		{tbs.ErrServiceStartPending, ErrTPMNotResponding},
		{tbs.ErrServiceNotRunning, ErrTPMNotResponding},
		{tbs.ErrTooManyTBSContexts, ErrTPMNotResponding},
		{tbs.ErrCommandCanceled, ErrTPMNotResponding},
		{tbs.ErrTPMNotFound, ErrTPMUnavailable},
	} {
		if got := tpmOpenError(fmt.Errorf("open: %w", tc.err)); !errors.Is(got, tc.want) {
			t.Errorf("tpmOpenError(%v) = %v, want %v", tc.err, got, tc.want)
		}
	}
}

// TestWindowsPrefersTheProvisionedSRK pins the order that keeps the owner
// hierarchy, whose authorization Windows discards, from being asked first.
func TestWindowsPrefersTheProvisionedSRK(t *testing.T) {
	if tpmParentOrder[0] != tpmParentPersistentSRK {
		t.Fatalf("Windows parent order = %v, want the persistent SRK first", tpmParentOrder)
	}
}
