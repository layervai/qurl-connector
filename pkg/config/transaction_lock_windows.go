//go:build windows

package config

import (
	"context"
	"errors"
	"os"
	"runtime"
	"time"

	"golang.org/x/sys/windows"
)

const windowsTransactionLockPollInterval = 25 * time.Millisecond

func acquireTransactionLock(ctx context.Context, file *os.File) error {
	var overlapped windows.Overlapped
	timer := time.NewTimer(windowsTransactionLockPollInterval)
	if !timer.Stop() {
		<-timer.C
	}
	defer timer.Stop()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := windows.LockFileEx(
			windows.Handle(file.Fd()),
			windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY,
			0, 1, 0, &overlapped,
		)
		runtime.KeepAlive(file)
		if err == nil {
			return nil
		}
		if !errors.Is(err, windows.ERROR_LOCK_VIOLATION) && !errors.Is(err, windows.ERROR_IO_PENDING) {
			return err
		}
		timer.Reset(windowsTransactionLockPollInterval)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func releaseTransactionLock(file *os.File) error {
	if file == nil {
		return nil
	}
	var overlapped windows.Overlapped
	return errors.Join(
		windows.UnlockFileEx(windows.Handle(file.Fd()), 0, 1, 0, &overlapped),
		file.Close(),
	)
}
