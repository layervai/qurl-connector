//go:build !darwin && !linux && !windows

package config

import (
	"context"
	"errors"
	"fmt"
	"os"
)

func acquireTransactionLock(_ context.Context, _ *os.File) error {
	return errors.New("config transactions are unsupported on this platform")
}

func releaseTransactionLock(file *os.File) error {
	if file == nil {
		return nil
	}
	return fmt.Errorf("release unsupported config transaction lock: %w", file.Close())
}
