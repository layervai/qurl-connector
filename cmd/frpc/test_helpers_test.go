package main

import (
	"sync"
	"testing"
)

func resetToken(t *testing.T) {
	t.Helper()
	previous := token
	token = ""
	t.Cleanup(func() { token = previous })
}

func setCachedMachineIDForTest(t *testing.T, value string) {
	t.Helper()
	previousID := cachedMachineID
	cachedMachineID = value
	machineIDOnce = sync.Once{}
	machineIDOnce.Do(func() {})
	t.Cleanup(func() {
		cachedMachineID = previousID
		machineIDOnce = sync.Once{}
		if previousID != "" {
			machineIDOnce.Do(func() {})
		}
	})
}
