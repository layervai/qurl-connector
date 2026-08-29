//go:build !windows

package main

import (
	"fmt"
	"os"
	"syscall"
)

func describeFileOwnership(info os.FileInfo) string {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return fmt.Sprintf(",uid=%d,gid=%d", stat.Uid, stat.Gid)
	}
	return ""
}
