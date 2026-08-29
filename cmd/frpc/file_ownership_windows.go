//go:build windows

package main

import "os"

func describeFileOwnership(_ os.FileInfo) string {
	return ""
}
