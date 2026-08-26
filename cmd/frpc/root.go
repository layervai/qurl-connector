package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/fatedier/frp/pkg/config"
	"github.com/spf13/cobra"
)

// commandContext returns the cobra command's context, falling back to
// context.Background() when cmd is nil (the shape the command RunE helpers are
// invoked with directly from tests).
func commandContext(cmd *cobra.Command) context.Context {
	if cmd != nil {
		return cmd.Context()
	}
	return context.Background()
}

var (
	cfgFile string
	token   string
)

var rootCmd = &cobra.Command{
	Use:   "qurl-connector",
	Short: "qURL Connector client",
}

func init() {
	rootCmd.PersistentFlags().StringVarP(&cfgFile, "config", "c", "", "path to config file")
	rootCmd.PersistentFlags().StringVar(&token, "token", "",
		"LayerV-issued headless Connector enrollment credential for first native UDP registration; account/OAuth credentials are rejected, and assignment refresh uses the persisted device identity")

	rootCmd.AddCommand(runCmd)
	rootCmd.AddCommand(versionCmd)
	rootCmd.AddCommand(addCmd)
	rootCmd.AddCommand(listCmd)
	rootCmd.AddCommand(removeCmd)
	rootCmd.AddCommand(statusCmd)
	rootCmd.AddCommand(desktopConfigCmd)
}

// EnvAPIKey carries the headless Connector enrollment credential inline for
// the developer command.
// gosec G101: this is the env var NAME, not a credential value.
const EnvAPIKey = "QURL_API_KEY" //nolint:gosec // G101: env var name, not a credential

// EnvAPIKeyFile points at a file containing the headless Connector enrollment
// credential.
// Standard `_FILE` convention: preferred over EnvAPIKey because it keeps the
// secret out of the process environment.
// gosec G101: this is the env var NAME, not a credential value.
const EnvAPIKeyFile = "QURL_API_KEY_FILE" //nolint:gosec // G101: env var name, not a credential

// apiKeyFileMaxBytes caps the size of the QURL_API_KEY_FILE read.
// Headless Connector enrollment credentials are comfortably under 4 KiB; the cap
// exists so a misconfigured mount pointing at /dev/zero or a log file
// can't load arbitrary data into memory.
const apiKeyFileMaxBytes = 4 * 1024

// errSecretFileTooLarge is returned by readSecretFile when the file's
// size exceeds apiKeyFileMaxBytes. Strict-no-silent-truncate: callers
// surface this as a misconfiguration rather than handing a truncated
// blob to the NHP enrollment exchange (which would reject it with a generic
// invalid-token error several layers away from the actual cause).
var errSecretFileTooLarge = fmt.Errorf("file exceeds %d byte cap (Connector enrollment credentials fit well under this)", apiKeyFileMaxBytes)

// readSecretFile reads a path with a size cap and trims surrounding
// whitespace. Returns the trimmed value on success.
//
// Reads one byte past the cap and reports errSecretFileTooLarge when
// the file exceeds it, so a misconfigured mount pointing at /dev/zero
// or a log file fails loudly rather than silently truncating.
func readSecretFile(path string) (string, error) {
	// gosec G304: see getToken's contract comment — operator-supplied
	// path is the whole point of the _FILE indirection.
	f, err := os.Open(path) //nolint:gosec // G304: operator-supplied path is the contract
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, apiKeyFileMaxBytes+1))
	if err != nil {
		return "", err
	}
	if len(data) > apiKeyFileMaxBytes {
		return "", errSecretFileTooLarge
	}
	return strings.TrimSpace(string(data)), nil
}

// getToken returns the headless Connector enrollment credential. Resolution order:
//  1. --token flag (highest precedence; operator-supplied at invocation)
//  2. QURL_API_KEY_FILE — read trimmed contents of the file at that path
//  3. QURL_API_KEY env var
//
// All paths trim surrounding whitespace: a token never legitimately
// carries leading / trailing whitespace, and trimming uniformly avoids a
// "works via file but not via env" footgun when a customer pastes a
// value with a trailing newline from a secrets-manager UI.
//
// When QURL_API_KEY_FILE is set we do NOT fall back to QURL_API_KEY on a
// read error or empty file: the _FILE variant exists to keep the secret
// out of the process environment, and silently degrading to the env var
// would defeat the whole point and mask the misconfiguration. Both
// failure modes emit an stderr diagnostic naming the path so the
// operator can spot the issue in command logs.
//
// Account/OAuth credentials are not accepted by this headless runtime. The
// LayerV-issued credential must have an
// allowed connector_bootstrap, bootstrap, or agent registration key kind.
func getToken() string {
	if t := strings.TrimSpace(token); t != "" {
		return t
	}
	if path := strings.TrimSpace(os.Getenv(EnvAPIKeyFile)); path != "" {
		// gosec G304/G703: the path is operator-supplied via
		// QURL_API_KEY_FILE — that's the whole point of the _FILE
		// convention. Container runtimes that mount secrets into
		// well-known paths (Docker secrets, Kubernetes CSI, tmpfs
		// init scripts) deliver the value here intentionally.
		//
		// Size cap: Connector enrollment credentials are bounded
		// well under apiKeyFileMaxBytes; reading via io.LimitReader
		// avoids pulling an unbounded file into memory if the
		// operator accidentally points the env at /dev/zero, a log
		// file, or another large file.
		val, err := readSecretFile(path)
		if err != nil {
			// Include the path explicitly so non-PathError variants
			// (errSecretFileTooLarge, mid-read I/O errors) still name
			// the file the operator pointed at. The redundancy with
			// PathError's own "open /path/...: <reason>" formatting is
			// trivial vs. the operator having to look up the env value
			// separately when the failure isn't open-time.
			fmt.Fprintf(os.Stderr, "qurl: %s (%q) read failed: %v\n", EnvAPIKeyFile, path, err)
			return ""
		}
		if val == "" {
			fmt.Fprintf(os.Stderr, "qurl: %s set to %q but file is empty / whitespace-only\n", EnvAPIKeyFile, path)
			return ""
		}
		return val
	}
	if v := strings.TrimSpace(os.Getenv(EnvAPIKey)); v != "" {
		return v
	}
	return ""
}

// getAPIBaseURL returns the qURL management API base URL used by explicit
// commands such as `remove`. The `run`, `list`, and `status` paths do not use
// this endpoint: registered-agent resource resolution and continuity run over
// the assigned-cell NHP exchange, while list/status read local durable state.
//
// Precedence: QURL_API_URL, then the `qurl.api_url` config field, then the
// production default.
//
// The config field remains relevant to management commands, where silently
// falling back to production would target the wrong environment.
//
// Env still wins so existing deployments and CI keep their current behavior.
func getAPIBaseURL(configured string) string {
	if u := os.Getenv("QURL_API_URL"); u != "" {
		return u
	}
	if u := strings.TrimSpace(configured); u != "" {
		return u
	}
	return "https://api.layerv.ai/v1"
}

// Execute runs the root command.
func Execute() {
	rootCmd.SetGlobalNormalizationFunc(config.WordSepNormalizeFunc)
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
