//go:build !darwin && !linux

package pinnedfs

import (
	"context"
	"errors"
	"os"
)

func acquireAdvisoryLock(_ context.Context, _ *os.File, _ bool) error {
	return ErrUnsupported
}

func releaseAdvisoryLock(file *os.File) error {
	if file == nil {
		return nil
	}
	return errors.Join(ErrUnsupported, file.Close())
}
