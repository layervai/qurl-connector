//go:build !darwin && !linux

package config

import (
	"errors"
	"testing"

	"github.com/layervai/qurl-connector/internal/pinnedfs"
)

func TestConfigTransactionFailsClosedOnUnsupportedPlatform(t *testing.T) {
	if tx, err := AcquireFileTransaction("qurl-proxy.yaml"); tx != nil || !errors.Is(err, pinnedfs.ErrUnsupported) {
		t.Fatalf("AcquireFileTransaction = (%v, %v), want nil and ErrUnsupported", tx, err)
	}
}
