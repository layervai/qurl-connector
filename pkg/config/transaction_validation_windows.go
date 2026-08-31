//go:build windows

package config

import "fmt"

func wrapConfigNamespaceValidationError(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("%w; on Windows, Connector can write configuration only in a directory owned by the current user with a trusted ACL: stop Connector, move the existing config directory aside, run `qurl-connector add` to create protected configuration, and then re-enter its routes; do not copy the old directory back", err)
}

func wrapConfigFileValidationError(label string, err error) error {
	if err == nil {
		return nil
	}
	switch label {
	case "config file", "config file after read", "existing config file":
		return fmt.Errorf("%w; on Windows, Connector accepts only a config file created with its protected current-user, SYSTEM, and Administrators ACL: move the existing qurl-proxy.yaml aside, use `qurl-connector add` to create a protected config, and then re-enter its routes; do not copy the old file back", err)
	default:
		return err
	}
}
