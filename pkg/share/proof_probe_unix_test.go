//go:build unix

package share

import (
	"os"
	"runtime"
	"syscall"
)

// proofPeakRSSBytes reports the process's peak resident set size from
// getrusage. ru_maxrss is bytes on Darwin and kilobytes on Linux (the figure
// /proc/self/status reports as VmHWM) and on the BSDs.
func proofPeakRSSBytes() (uint64, bool) {
	var usage syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &usage); err != nil || usage.Maxrss < 0 {
		return 0, false
	}
	rss := uint64(usage.Maxrss)
	if runtime.GOOS != "darwin" {
		rss *= 1024
	}
	return rss, true
}

// proofOpenFDs counts the process's open file descriptors from its descriptor
// table (/proc/self/fd on Linux, /dev/fd elsewhere). The directory handle the
// count itself opens is excluded.
func proofOpenFDs() (int, bool) {
	for _, dir := range []string{"/proc/self/fd", "/dev/fd"} {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		return len(entries) - 1, true
	}
	return 0, false
}
