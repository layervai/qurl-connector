package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

const (
	yamlConfigName = "qurl-proxy.yaml"
	configSubdir   = "etc"
)

// UserConfigDir is the home-relative directory holding qURL's user config
// (qurl-proxy.yaml) and the optional developer token file
// (~/.config/qurl/token).
// Exported so cmd/frpc can resolve the token path against the same constant
// rather than re-hardcoding ".config/qurl". Join with os.UserHomeDir(),
// NOT os.UserConfigDir() (which is ~/Library/Application Support on macOS).
const UserConfigDir = ".config/qurl"

// Discover locates the configuration file to use. It checks, in order:
//  1. The explicit path from configFlag (error if not found).
//  2. ./qurl-proxy.yaml in the current working directory.
//  3. <binary_dir>/etc/qurl-proxy.yaml alongside the running binary.
//  4. ~/.config/qurl/qurl-proxy.yaml in the user's home directory.
//
// If no file is found, an error is returned. There is intentionally
// no fallback to a TOML config — qurl-connector is a
// brand-new product with no installed base predating the YAML
// schema; every install starts from `qurl-proxy.yaml`.
func Discover(configFlag string) (string, error) {
	// 1. Explicit flag takes priority.
	if configFlag != "" {
		if _, err := os.Stat(configFlag); err != nil {
			return "", fmt.Errorf("config file specified but not found: %w", err)
		}
		return configFlag, nil
	}

	// 2. Current working directory.
	if cwd, err := os.Getwd(); err == nil {
		p := filepath.Join(cwd, yamlConfigName)
		if fileExists(p) {
			return p, nil
		}
	}

	// 3. Binary directory / etc.
	if binDir, err := ExecutableDir(); err == nil {
		p := filepath.Join(binDir, configSubdir, yamlConfigName)
		if fileExists(p) {
			return p, nil
		}
	}

	// 4. User config directory.
	if home, err := userConfigHomeDir(); err == nil {
		p := filepath.Join(home, UserConfigDir, yamlConfigName)
		if fileExists(p) {
			return p, nil
		}
	}

	return "", errors.New("no configuration file found; create qurl-proxy.yaml or pass --config")
}

// userConfigHomeDir preserves the documented HOME-relative discovery contract
// on every platform. os.UserHomeDir ignores HOME on Windows and resolves
// USERPROFILE instead, which makes an explicit isolated HOME ineffective for
// managed processes and tests.
func userConfigHomeDir() (string, error) {
	if home := os.Getenv("HOME"); home != "" {
		return home, nil
	}
	return os.UserHomeDir()
}

// fileExists returns true if the path exists and is a regular file.
func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

// ExecutableDir returns the directory containing the running binary,
// resolving any symlinks.
func ExecutableDir() (string, error) {
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	exe, err = filepath.EvalSymlinks(exe)
	if err != nil {
		return "", err
	}
	return filepath.Dir(exe), nil
}
