//go:build !windows

package config

func wrapConfigFileValidationError(_ string, err error) error { return err }
