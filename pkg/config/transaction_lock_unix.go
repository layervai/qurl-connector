//go:build darwin || linux

package config

import (
	"context"
	"errors"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

const transactionLockPollInterval = 25 * time.Millisecond

func acquireTransactionLock(ctx context.Context, file *os.File) error {
	timer := time.NewTimer(transactionLockPollInterval)
	if !timer.Stop() {
		<-timer.C
	}
	defer timer.Stop()
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		err := unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return nil
		}
		if !errors.Is(err, unix.EWOULDBLOCK) && !errors.Is(err, unix.EAGAIN) {
			return err
		}
		timer.Reset(transactionLockPollInterval)
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
	return errors.Join(unix.Flock(int(file.Fd()), unix.LOCK_UN), file.Close())
}
