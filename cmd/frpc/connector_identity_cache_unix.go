//go:build darwin || linux

package main

// Connector identity-cache pathname traversal, file validation, atomic writes,
// and locking are intentionally implemented through internal/pinnedfs.
// Keeping this supported-platform file makes the Linux/Darwin boundary explicit
// without maintaining a second openat pathname backend here.
