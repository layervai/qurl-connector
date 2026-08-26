//go:build !darwin && !linux

package main

// Mutating and read-only Connector identity-cache entrypoints both fail through
// pinnedfs.ErrUnsupported before creating a directory or lock on this platform.
