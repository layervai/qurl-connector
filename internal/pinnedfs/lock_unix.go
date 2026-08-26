//go:build darwin || linux

package pinnedfs

import (
	"context"
	"errors"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

const lockPollInterval = 25 * time.Millisecond

func acquireAdvisoryLock(ctx context.Context, file *os.File, shared bool) error {
	operation := unix.LOCK_EX | unix.LOCK_NB
	if shared {
		operation = unix.LOCK_SH | unix.LOCK_NB
	}
	timer := time.NewTimer(lockPollInterval)
	if !timer.Stop() {
		<-timer.C
	}
	defer timer.Stop()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := unix.Flock(int(file.Fd()), operation)
		if err == nil {
			return nil
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
			return err
		}
		timer.Reset(lockPollInterval)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func releaseAdvisoryLock(file *os.File) error {
	if file == nil {
		return nil
	}
	return errors.Join(unix.Flock(int(file.Fd()), unix.LOCK_UN), file.Close())
}
