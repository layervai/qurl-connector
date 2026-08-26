package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	testConnectorRoutingID  = "c-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testConnectorRoutingID2 = "c-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbq"
	testPublicResourceID    = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2vPoafaVb5Lue-bfcCuoL-_CnVBKf8YvV94G8ozebA6RHEQUPsnguSt1yx2mTzDSogBmb9WYEVBDgX7vc2NKTg"
	testPublicResourceID2   = "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEcOtuxu2qhc3gt1E7BiEU0CLqEDlXDwzZq0JnESgMAwERX6y_XXF5Cn5SKITWIZQmUhCZ0pHHlVn7SmFUTAnTGQ"
)

// The TestGetToken_* cases mutate the package-level `token` variable
// (Cobra binds the --token flag to it). They are NOT parallel-safe;
// do not call t.Parallel() in this group without first refactoring
// `token` behind a getter or a per-test override hook.

// withCapturedStderr runs fn with os.Stderr redirected to a captured
// buffer and returns whatever fn wrote. Each call closes/restores
// os.Stderr deterministically via t.Cleanup so a panicking fn doesn't
// leak a swapped stderr to subsequent tests.
//
// Like the package-level `token` mutation above, this swap is not
// parallel-safe — t.Parallel() in any sibling test will race against
// the os.Stderr global.
//
// Pipe buffer caveat: io.ReadAll(r) runs after w.Close(), so if fn
// writes more than the OS pipe buffer (~64 KiB on Linux) the write
// blocks before Close is reached and the test deadlocks. Today's
// getToken diagnostics are well under 1 KiB; if a future caller adds
// a large stderr write, swap to a background goroutine reader.
func withCapturedStderr(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stderr = w
	t.Cleanup(func() {
		os.Stderr = orig
		// Close both ends regardless of how fn exits. If fn panics
		// before the w.Close() below, the goroutine reading from r
		// would block forever — t.Cleanup runs LIFO so w closes
		// first here, unblocking any pending read on r.
		_ = w.Close()
		_ = r.Close()
	})
	fn()
	_ = w.Close()
	buf, _ := io.ReadAll(r)
	return string(buf)
}

// TestGetToken_FlagBeatsEverything pins --token as highest precedence.
// QURL_API_KEY_FILE and QURL_API_KEY are both set to bogus values
// alongside it, and the flag wins.
func TestGetToken_FlagBeatsEverything(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "key")
	if err := os.WriteFile(keyFile, []byte("from-file\n"), 0o600); err != nil {
		t.Fatalf("seed key file: %v", err)
	}
	t.Setenv(EnvAPIKey, "from-env")
	t.Setenv(EnvAPIKeyFile, keyFile)

	prev := token
	token = "from-flag"
	t.Cleanup(func() { token = prev })

	if got := getToken(); got != "from-flag" {
		t.Errorf("getToken() = %q, want from-flag", got)
	}
}

// TestGetToken_FileBeatsEnv is the customer-install happy path: a
// mounted secret file wins over an inline env var, and the trailing
// newline that secret-file mounters typically leave behind is trimmed.
func TestGetToken_FileBeatsEnv(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "key")
	if err := os.WriteFile(keyFile, []byte("from-file\n"), 0o600); err != nil {
		t.Fatalf("seed key file: %v", err)
	}
	t.Setenv(EnvAPIKey, "from-env")
	t.Setenv(EnvAPIKeyFile, keyFile)

	if got := getToken(); got != "from-file" {
		t.Errorf("getToken() = %q, want from-file (trimmed)", got)
	}
}

// TestGetToken_FileUnreadableDoesNotFallThrough pins the strict
// _FILE semantics: if the operator pointed QURL_API_KEY_FILE at a
// non-existent path, we MUST NOT silently fall through to
// QURL_API_KEY. The whole point of _FILE is to keep the secret out
// of the process env, so a silent fall-through would defeat it and
// mask the misconfiguration. We also expect a stderr warning so an
// operator scanning container logs sees what failed.
func TestGetToken_FileUnreadableDoesNotFallThrough(t *testing.T) {
	t.Setenv(EnvAPIKey, "from-env")
	t.Setenv(EnvAPIKeyFile, "/nonexistent/path/to/key")

	var got string
	stderr := withCapturedStderr(t, func() { got = getToken() })

	if got != "" {
		t.Errorf("getToken() = %q, want empty (caller should surface missing-token error)", got)
	}
	if !strings.Contains(stderr, EnvAPIKeyFile) {
		t.Errorf("stderr = %q, want a diagnostic mentioning %s", stderr, EnvAPIKeyFile)
	}
	if !strings.Contains(stderr, "/nonexistent/path/to/key") {
		t.Errorf("stderr = %q, want the failed path in the diagnostic", stderr)
	}
}

// TestGetToken_FileEmpty pins the "file exists but is empty /
// whitespace-only" failure mode. A realistic CSI-mount-misconfig
// case (volume mounted but key not yet synced, version pinned at
// `:0`, etc.). Strict _FILE semantics: do NOT fall back to env;
// emit a stderr diagnostic so the operator sees the issue.
func TestGetToken_FileEmpty(t *testing.T) {
	tests := []struct {
		name     string
		contents string
	}{
		{"truly empty", ""},
		{"whitespace only", "   \n\t  \n"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			keyFile := filepath.Join(dir, "key")
			if err := os.WriteFile(keyFile, []byte(tt.contents), 0o600); err != nil {
				t.Fatalf("seed key file: %v", err)
			}
			t.Setenv(EnvAPIKey, "from-env")
			t.Setenv(EnvAPIKeyFile, keyFile)

			var got string
			stderr := withCapturedStderr(t, func() { got = getToken() })

			if got != "" {
				t.Errorf("getToken() = %q, want empty (no fall-back to env)", got)
			}
			if !strings.Contains(stderr, EnvAPIKeyFile) {
				t.Errorf("stderr = %q, want a diagnostic mentioning %s", stderr, EnvAPIKeyFile)
			}
			if !strings.Contains(stderr, "empty") {
				t.Errorf("stderr = %q, want 'empty' diagnostic", stderr)
			}
		})
	}
}

// TestGetToken_AllInputsTrimmed verifies the trimming-consistency
// guarantee: a customer who accidentally has trailing whitespace in
// any of the three resolution paths gets the same usable token.
func TestGetToken_AllInputsTrimmed(t *testing.T) {
	t.Run("flag trimmed", func(t *testing.T) {
		t.Setenv(EnvAPIKey, "")
		t.Setenv(EnvAPIKeyFile, "")
		prev := token
		token = "  flag-value\n"
		t.Cleanup(func() { token = prev })

		if got := getToken(); got != "flag-value" {
			t.Errorf("getToken() = %q, want flag-value", got)
		}
	})
	t.Run("env trimmed", func(t *testing.T) {
		t.Setenv(EnvAPIKey, "  env-value\n")
		t.Setenv(EnvAPIKeyFile, "")

		if got := getToken(); got != "env-value" {
			t.Errorf("getToken() = %q, want env-value", got)
		}
	})
	t.Run("file trimmed", func(t *testing.T) {
		dir := t.TempDir()
		keyFile := filepath.Join(dir, "key")
		if err := os.WriteFile(keyFile, []byte("  file-value\n"), 0o600); err != nil {
			t.Fatalf("seed key file: %v", err)
		}
		t.Setenv(EnvAPIKey, "")
		t.Setenv(EnvAPIKeyFile, keyFile)

		if got := getToken(); got != "file-value" {
			t.Errorf("getToken() = %q, want file-value", got)
		}
	})
	t.Run("whitespace-only flag falls through to file", func(t *testing.T) {
		// A whitespace-only --token (e.g. an empty placeholder from a
		// config-management template) should NOT short-circuit the
		// resolution chain. After trimming it's empty, so getToken
		// must fall through to _FILE / env.
		dir := t.TempDir()
		keyFile := filepath.Join(dir, "key")
		if err := os.WriteFile(keyFile, []byte("file-value\n"), 0o600); err != nil {
			t.Fatalf("seed key file: %v", err)
		}
		t.Setenv(EnvAPIKey, "should-not-win")
		t.Setenv(EnvAPIKeyFile, keyFile)
		prev := token
		token = "   "
		t.Cleanup(func() { token = prev })

		if got := getToken(); got != "file-value" {
			t.Errorf("getToken() = %q, want file-value (whitespace flag must not short-circuit)", got)
		}
	})
}

// TestGetToken_FileSizeCap verifies the strict-no-silent-truncate
// behavior on QURL_API_KEY_FILE: a misconfigured mount pointing at a
// large file (`/dev/zero`, a log file, a config dump) should NOT
// quietly hand a 4 KiB truncated blob to the caller — that blob then
// gets shipped to the API and rejected as a generic invalid token,
// several layers away from the actual cause.
//
// Instead, readSecretFile reports errSecretFileTooLarge, getToken
// emits the stderr diagnostic naming the env var, and returns empty
// so the first-registration credential error fires with the full set of
// resolution sources.
func TestGetToken_FileSizeCap(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "key")

	// Write 2x the cap so the +1 read in readSecretFile observes data
	// past the cap. Happy-path API keys are well under 4 KiB; this
	// oversized blob simulates a misconfigured mount.
	oversized := strings.Repeat("A", apiKeyFileMaxBytes*2)
	if err := os.WriteFile(keyFile, []byte(oversized), 0o600); err != nil {
		t.Fatalf("seed key file: %v", err)
	}
	t.Setenv(EnvAPIKey, "fallback-env-should-not-be-used")
	t.Setenv(EnvAPIKeyFile, keyFile)

	var got string
	stderr := withCapturedStderr(t, func() { got = getToken() })

	if got != "" {
		t.Errorf("getToken() = %q (%d bytes); want empty (oversized file is strict-no-silent-truncate)", got, len(got))
	}
	if !strings.Contains(stderr, EnvAPIKeyFile) {
		t.Errorf("stderr = %q, want diagnostic mentioning %s", stderr, EnvAPIKeyFile)
	}
	if !strings.Contains(stderr, "exceeds") {
		t.Errorf("stderr = %q, want 'exceeds' diagnostic from errSecretFileTooLarge", stderr)
	}
}

// TestGetToken_EnvFallback verifies the developer environment path works when
// no flag or _FILE is set. The env value is trimmed uniformly with
// the other paths (see TestGetToken_AllInputsTrimmed); this case uses
// a no-whitespace value so the assertion is independent of the
// trimming behavior.
func TestGetToken_EnvFallback(t *testing.T) {
	t.Setenv(EnvAPIKey, "from-env")
	t.Setenv(EnvAPIKeyFile, "")

	if got := getToken(); got != "from-env" {
		t.Errorf("getToken() = %q, want from-env", got)
	}
}

// TestGetToken_EmptyWhenNothingSet is the first-registration credential
// failure path: with no flag, no _FILE, and no env, getToken returns empty and
// native UDP registration surfaces the enrollment error to the operator.
func TestGetToken_EmptyWhenNothingSet(t *testing.T) {
	t.Setenv(EnvAPIKey, "")
	t.Setenv(EnvAPIKeyFile, "")
	if got := getToken(); got != "" {
		t.Errorf("getToken() = %q, want empty", got)
	}
}

// getAPIBaseURL used to ignore the config field entirely: QURLConfig.APIURL was
// parsed and read by nothing, so pointing qurl-proxy.yaml at a non-production
// API silently kept talking to production. Against sandbox that surfaced as
// "API error 401: Invalid API key" on the first resource call after a
// SUCCESSFUL native registration -- a wrong-environment problem wearing a
// credential problem's error message.
func TestGetAPIBaseURL_Precedence(t *testing.T) {
	const sandbox = "https://sandbox-api.example.com/v1"
	const envURL = "https://api.env.example/v1"

	t.Run("config field is honored", func(t *testing.T) {
		t.Setenv("QURL_API_URL", "")
		if got := getAPIBaseURL(sandbox); got != sandbox {
			t.Fatalf("getAPIBaseURL(%q) = %q, want the configured URL", sandbox, got)
		}
	})

	t.Run("env still wins over config", func(t *testing.T) {
		t.Setenv("QURL_API_URL", envURL)
		if got := getAPIBaseURL(sandbox); got != envURL {
			t.Fatalf("getAPIBaseURL = %q, want the env override %q", got, envURL)
		}
	})

	t.Run("blank config falls back to production", func(t *testing.T) {
		t.Setenv("QURL_API_URL", "")
		for _, configured := range []string{"", "   ", "\t"} {
			if got := getAPIBaseURL(configured); got != "https://api.layerv.ai/v1" {
				t.Fatalf("getAPIBaseURL(%q) = %q, want the production default", configured, got)
			}
		}
	})
}
