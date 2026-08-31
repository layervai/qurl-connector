//go:build !windows

package config

func wrapConfigNamespaceValidationError(err error) error { return err }

func wrapConfigFileValidationError(_ string, err error) error { return err }
