//go:build windows

package pinnedfs

import (
	"context"
	"errors"
	"os"
	"runtime"
	"time"

	"golang.org/x/sys/windows"
)

const windowsLockPollInterval = 25 * time.Millisecond

func acquireAdvisoryLock(ctx context.Context, file *os.File, shared bool) error {
	flags := uint32(windows.LOCKFILE_FAIL_IMMEDIATELY)
	if !shared {
		flags |= windows.LOCKFILE_EXCLUSIVE_LOCK
	}
	var overlapped windows.Overlapped
	timer := time.NewTimer(windowsLockPollInterval)
	if !timer.Stop() {
		<-timer.C
	}
	defer timer.Stop()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := windows.LockFileEx(windows.Handle(file.Fd()), flags, 0, 1, 0, &overlapped)
		runtime.KeepAlive(file)
		if err == nil {
			return nil
		}
		if !errors.Is(err, windows.ERROR_LOCK_VIOLATION) && !errors.Is(err, windows.ERROR_IO_PENDING) {
			return err
		}
		timer.Reset(windowsLockPollInterval)
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
	var overlapped windows.Overlapped
	return errors.Join(
		windows.UnlockFileEx(windows.Handle(file.Fd()), 0, 1, 0, &overlapped),
		file.Close(),
	)
}
